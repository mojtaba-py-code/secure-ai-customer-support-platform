"""Embedding providers.

``HashingEmbedder`` (default) is a deterministic, local feature-hashing model: word unigrams and
bigrams plus character trigrams, light stemming and a small support-domain synonym map, signed
hashing into a fixed-size vector, sub-linear TF weighting and L2 normalisation. It needs no
network, no model download and no GPU, which makes development, CI and demos reproducible. It is
lexical rather than semantic.

``VoyageEmbedder`` calls the Voyage AI embeddings API (the embedding provider Anthropic
recommends) for semantic retrieval in production. Calls go through the egress policy
(allowlisted host, HTTPS, no redirects, response size cap) and responses are validated
(count, dimensionality, finite numbers) before use.
"""

from __future__ import annotations

import functools
import hashlib
import itertools
import math
import re
from collections import Counter
from collections.abc import Sequence
from typing import Any, Protocol

import httpx2

from aegis.core.egress import EgressPolicy, post_json
from aegis.core.errors import DependencyUnavailable
from aegis.core.resilience import retry_async


class Embedder(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def dimensions(self) -> int: ...

    @property
    def is_remote(self) -> bool: ...

    async def embed_documents(self, texts: Sequence[str]) -> list[list[float]]: ...

    async def embed_query(self, text: str) -> list[float]: ...

    async def close(self) -> None: ...


_TOKEN = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    [
        "a",
        "an",
        "the",
        "and",
        "or",
        "but",
        "if",
        "of",
        "to",
        "in",
        "on",
        "at",
        "for",
        "from",
        "by",
        "with",
        "about",
        "as",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "i",
        "me",
        "my",
        "we",
        "our",
        "you",
        "your",
        "he",
        "she",
        "it",
        "its",
        "they",
        "them",
        "their",
        "this",
        "that",
        "these",
        "those",
        "do",
        "does",
        "did",
        "can",
        "could",
        "will",
        "would",
        "should",
        "may",
        "might",
        "must",
        "have",
        "has",
        "had",
        "not",
        "no",
        "yes",
        "so",
        "than",
        "then",
        "there",
        "here",
        "what",
        "which",
        "who",
        "how",
        "when",
        "where",
        "why",
        "please",
        "thanks",
        "thank",
        "hi",
        "hello",
    ]
)
_CANONICAL = {
    "refunds": "refund",
    "refunded": "refund",
    "reimburse": "refund",
    "reimbursement": "refund",
    "moneyback": "refund",
    "returns": "return",
    "returning": "return",
    "returned": "return",
    "shipping": "ship",
    "shipped": "ship",
    "shipment": "ship",
    "delivery": "deliver",
    "delivered": "deliver",
    "arrive": "deliver",
    "arrival": "deliver",
    "cancellation": "cancel",
    "cancelled": "cancel",
    "canceled": "cancel",
    "guarantee": "warranty",
    "broken": "defect",
    "defective": "defect",
    "faulty": "defect",
    "damaged": "damage",
    "login": "signin",
    "logon": "signin",
    "hacked": "compromise",
    "stolen": "compromise",
    "charged": "charge",
    "charges": "charge",
    "billing": "charge",
    "invoice": "receipt",
    "tracking": "track",
    "tracked": "track",
}


def _stem(word: str) -> str:
    word = _CANONICAL.get(word, word)
    for suffix in ("ing", "edly", "ed", "ies", "es", "s", "ly"):
        if len(word) > len(suffix) + 3 and word.endswith(suffix):
            word = word[: -len(suffix)] + ("y" if suffix == "ies" else "")
            break
    return _CANONICAL.get(word, word)


def _features(text: str) -> Counter[str]:
    words = [_stem(w) for w in _TOKEN.findall(text.lower()) if w not in _STOPWORDS and len(w) > 1]
    features: Counter[str] = Counter()
    for word in words:
        features[f"w:{word}"] += 2
        padded = f"^{word}$"
        for i in range(len(padded) - 2):
            features[f"c:{padded[i : i + 3]}"] += 1
    for first, second in itertools.pairwise(words):
        features[f"b:{first}_{second}"] += 2
    return features


@functools.lru_cache(maxsize=2_048)
def _hashed_vector(text: str, dimensions: int) -> tuple[float, ...]:
    """Pure function of its inputs, so re-indexing unchanged text is served from the cache."""
    vector = [0.0] * dimensions
    for feature, count in _features(text).items():
        digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
        value = int.from_bytes(digest, "big")
        index = value % dimensions
        sign = 1.0 if (value >> 63) & 1 else -1.0
        vector[index] += sign * (1.0 + math.log(count))
    norm = math.sqrt(sum(v * v for v in vector))
    if norm == 0:
        return tuple(vector)
    return tuple(v / norm for v in vector)


class HashingEmbedder:
    def __init__(self, dimensions: int = 512) -> None:
        if dimensions < 16:
            msg = "dimensions must be >= 16"
            raise ValueError(msg)
        self._dimensions = dimensions

    @property
    def name(self) -> str:
        return f"hashing-{self._dimensions}"

    @property
    def dimensions(self) -> int:
        return self._dimensions

    @property
    def is_remote(self) -> bool:
        return False

    def embed(self, text: str) -> list[float]:
        return list(_hashed_vector(text, self._dimensions))

    async def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        return [self.embed(t) for t in texts]

    async def embed_query(self, text: str) -> list[float]:
        return self.embed(text)

    async def close(self) -> None:
        return None


class VoyageEmbedder:
    MAX_BATCH = 64
    MAX_RESPONSE_BYTES = 16 * 1024 * 1024

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str,
        dimensions: int,
        client: httpx2.AsyncClient,
        policy: EgressPolicy,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._url = f"{base_url.rstrip('/')}/v1/embeddings"
        self._dimensions = dimensions
        self._client = client
        self._policy = policy
        policy.validate(self._url)

    @property
    def name(self) -> str:
        return f"voyage-{self._model}"

    @property
    def dimensions(self) -> int:
        return self._dimensions

    @property
    def is_remote(self) -> bool:
        return True

    async def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for start in range(0, len(texts), self.MAX_BATCH):
            vectors.extend(await self._embed(texts[start : start + self.MAX_BATCH], "document"))
        return vectors

    async def embed_query(self, text: str) -> list[float]:
        return (await self._embed([text], "query"))[0]

    async def _embed(self, texts: Sequence[str], input_type: str) -> list[list[float]]:
        payload = {
            "input": list(texts),
            "model": self._model,
            "input_type": input_type,
            "output_dimension": self._dimensions,
        }
        headers = {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}

        async def call() -> Any:
            return await post_json(
                self._client,
                self._policy,
                self._url,
                payload=payload,
                headers=headers,
                max_response_bytes=self.MAX_RESPONSE_BYTES,
            )

        body = await retry_async(call, attempts=3, retry_on=(DependencyUnavailable,))
        return self._validate(body, expected=len(texts))

    def _validate(self, body: Any, *, expected: int) -> list[list[float]]:
        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, list) or len(data) != expected:
            raise DependencyUnavailable(
                log_message="embedding response has the wrong number of vectors"
            )
        ordered: list[list[float]] = [[] for _ in range(expected)]
        for item in data:
            if not isinstance(item, dict):
                raise DependencyUnavailable(log_message="embedding response item malformed")
            index, vector = item.get("index"), item.get("embedding")
            if (
                not isinstance(index, int)
                or not 0 <= index < expected
                or not isinstance(vector, list)
            ):
                raise DependencyUnavailable(log_message="embedding response item malformed")
            if len(vector) != self._dimensions or not all(
                isinstance(v, int | float) and math.isfinite(v) for v in vector
            ):
                raise DependencyUnavailable(log_message="embedding vector has unexpected shape")
            ordered[index] = [float(v) for v in vector]
        if any(not v for v in ordered):
            raise DependencyUnavailable(log_message="embedding response missing vectors")
        return ordered

    async def close(self) -> None:
        await self._client.aclose()
