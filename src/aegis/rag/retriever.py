"""Retrieval pipeline: query -> embedding -> filtered vector search -> validated context.

Validation after the vector search (defence in depth - the search itself is already filtered):

1. **Authorisation re-check** - any hit whose payload visibility is not allowed for the caller is
   dropped and reported as a security event (it would indicate a filter bug).
2. **Conflict resolution** - when several versions of the same policy match, only the newest
   version is kept; across documents, chunks are ordered by authority (the intent's primary
   category first, e.g. the refund policy before the FAQ) and the model is told that the
   lower-numbered document wins when sources disagree.
3. **Injection screening** - chunks that read like instructions to an AI (indirect prompt
   injection) are withheld from the model and reported.
4. **Diversity and budget** - at most N chunks per document, top-k overall, and a hard cap on
   total characters handed to the model.

Low-similarity results are removed by the score threshold; when nothing relevant remains the
agent receives no documents and is instructed to say it does not know rather than guess.
"""

from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass

from aegis.core.errors import DependencyUnavailable
from aegis.domain.enums import KnowledgeCategory, KnowledgeVisibility
from aegis.kv.base import KeyBuilder, KeyValueStore, KeyValueUnavailable
from aegis.observability import metrics
from aegis.rag.embeddings import Embedder
from aegis.rag.vector_store import QdrantVectorStore, VectorHit
from aegis.security.crypto import fingerprint
from aegis.security.injection import PromptInjectionDetector
from aegis.security.text import normalize_text, truncate

logger = logging.getLogger(__name__)

MAX_QUERY_CHARS = 1_000


@dataclass(frozen=True, slots=True)
class RetrievedChunk:
    source_id: str
    document_id: str
    title: str
    section: str
    text: str
    score: float
    category: str
    slug: str
    version: int


@dataclass(frozen=True, slots=True)
class RetrievalSettings:
    top_k: int
    candidate_k: int
    score_threshold: float
    max_context_chars: int
    max_chunks_per_document: int


class KnowledgeRetriever:
    def __init__(
        self,
        *,
        store: QdrantVectorStore,
        embedder: Embedder,
        detector: PromptInjectionDetector,
        settings: RetrievalSettings,
        cache: KeyValueStore | None = None,
        cache_keys: KeyBuilder | None = None,
    ) -> None:
        self._store = store
        self._embedder = embedder
        self._detector = detector
        self._settings = settings
        self._cache = cache
        self._cache_keys = cache_keys

    async def retrieve(
        self,
        query: str,
        *,
        visibilities: frozenset[KnowledgeVisibility],
        categories: Sequence[KnowledgeCategory] | None = None,
    ) -> list[RetrievedChunk]:
        cleaned = truncate(normalize_text(query), MAX_QUERY_CHARS, marker="")
        if not cleaned or not visibilities:
            return []
        try:
            vector = await self._query_vector(cleaned)
            hits = await self._store.search(
                vector,
                visibilities=visibilities,
                categories=categories,
                limit=self._settings.candidate_k,
                score_threshold=self._settings.score_threshold,
            )
            if not hits and categories:
                # Category filters are a relevance hint, not a security boundary: fall back to
                # all categories the caller may see before concluding nothing is relevant.
                hits = await self._store.search(
                    vector,
                    visibilities=visibilities,
                    categories=None,
                    limit=self._settings.candidate_k,
                    score_threshold=self._settings.score_threshold,
                )
        except DependencyUnavailable:
            metrics.RAG_RETRIEVALS.labels(outcome="error").inc()
            raise
        chunks = self._validate(hits, visibilities)
        if categories:
            # Authority order: chunks from the intent's primary category (e.g. the refund policy)
            # come before secondary sources (e.g. the FAQ); relevance breaks ties.
            rank = {category.value: position for position, category in enumerate(categories)}
            chunks.sort(key=lambda c: (rank.get(c.category, len(rank)), -c.score))
        metrics.RAG_RETRIEVALS.labels(outcome="hit" if chunks else "empty").inc()
        metrics.RAG_CHUNKS.observe(len(chunks))
        return chunks

    async def _query_vector(self, query: str) -> list[float]:
        if not (self._embedder.is_remote and self._cache and self._cache_keys):
            return await self._embedder.embed_query(query)
        key = self._cache_keys.key("qemb", self._embedder.name, fingerprint(query))
        try:
            cached = await self._cache.get(key)
            if cached:
                data = json.loads(cached)
                if isinstance(data, list) and len(data) == self._embedder.dimensions:
                    return [float(v) for v in data]
        except (KeyValueUnavailable, ValueError):
            pass
        vector = await self._embedder.embed_query(query)
        with contextlib.suppress(KeyValueUnavailable):
            await self._cache.set(key, json.dumps(vector), ttl_seconds=3_600)
        return vector

    def _validate(
        self, hits: list[VectorHit], visibilities: frozenset[KnowledgeVisibility]
    ) -> list[RetrievedChunk]:
        allowed = {v.value for v in visibilities}
        latest: dict[str, int] = {}
        for hit in hits:
            latest[hit.payload.slug] = max(latest.get(hit.payload.slug, 0), hit.payload.version)

        per_document: dict[str, int] = {}
        selected: list[RetrievedChunk] = []
        budget = self._settings.max_context_chars
        for hit in sorted(hits, key=lambda h: h.score, reverse=True):
            payload = hit.payload
            if payload.visibility not in allowed:
                metrics.security_event("rag_visibility_violation")
                logger.error(
                    "vector search returned a document outside the caller's visibility",
                    extra={"event": "rag.visibility_violation", "document_id": payload.document_id},
                )
                continue
            if payload.version < latest[payload.slug]:
                continue
            if per_document.get(payload.document_id, 0) >= self._settings.max_chunks_per_document:
                continue
            assessment = self._detector.assess(payload.text)
            if assessment.is_suspicious:
                metrics.security_event("rag_chunk_injection_blocked")
                logger.warning(
                    "retrieved chunk withheld: injection indicators",
                    extra={
                        "event": "rag.chunk_blocked",
                        "document_id": payload.document_id,
                        "categories": list(assessment.categories),
                    },
                )
                continue
            if budget <= 0:
                break
            text = payload.text if len(payload.text) <= budget else truncate(payload.text, budget)
            budget -= len(text)
            per_document[payload.document_id] = per_document.get(payload.document_id, 0) + 1
            selected.append(
                RetrievedChunk(
                    source_id=f"{payload.slug}@v{payload.version}#{payload.chunk_index}",
                    document_id=payload.document_id,
                    title=payload.title,
                    section=payload.section,
                    text=text,
                    score=round(hit.score, 4),
                    category=payload.category,
                    slug=payload.slug,
                    version=payload.version,
                )
            )
            if len(selected) >= self._settings.top_k:
                break
        return selected
