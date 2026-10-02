"""Qdrant vector index.

Every point carries its document's ``visibility`` and ``category`` in the payload, and every
search is filtered on visibility **inside Qdrant** - a customer's query cannot even score an
internal document. (The retriever re-checks the payload afterwards as defence in depth.)
Point ids are derived deterministically from (document id, chunk index), so re-indexing a
document overwrites its points instead of duplicating them.

Deployment modes: a Qdrant server (``AEGIS_QDRANT_URL`` + API key; required in production) or
qdrant-client's embedded local mode (in-memory or a directory) for tests and development.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any

from qdrant_client import AsyncQdrantClient, models

from aegis.core.errors import DependencyUnavailable
from aegis.domain.enums import KnowledgeCategory, KnowledgeVisibility

_POINT_NAMESPACE = uuid.UUID("4f3a1c2e-7b0d-4e8a-9c61-2d5b8e0f9a17")


@dataclass(frozen=True, slots=True)
class ChunkPayload:
    document_id: str
    chunk_index: int
    title: str
    section: str
    text: str
    category: str
    visibility: str
    slug: str
    version: int


@dataclass(frozen=True, slots=True)
class VectorHit:
    score: float
    payload: ChunkPayload


class VectorStoreConfigError(RuntimeError):
    """The existing collection is incompatible with the configured embedder."""


class QdrantVectorStore:
    def __init__(
        self, client: AsyncQdrantClient, *, collection: str, dimensions: int, local: bool
    ) -> None:
        self._client = client
        self._collection = collection
        self._dimensions = dimensions
        self._local = local

    @classmethod
    def create(
        cls,
        *,
        url: str | None,
        api_key: str | None,
        location: str,
        collection: str,
        dimensions: int,
        timeout_seconds: int = 10,
    ) -> QdrantVectorStore:
        if url:
            client = AsyncQdrantClient(url=url, api_key=api_key, timeout=timeout_seconds)
            return cls(client, collection=collection, dimensions=dimensions, local=False)
        if location == ":memory:":
            client = AsyncQdrantClient(location=":memory:")
        else:
            client = AsyncQdrantClient(path=location)
        return cls(client, collection=collection, dimensions=dimensions, local=True)

    async def ensure_collection(self) -> None:
        try:
            exists = await self._client.collection_exists(self._collection)
            if exists:
                info = await self._client.get_collection(self._collection)
                vectors = info.config.params.vectors
                size = vectors.size if isinstance(vectors, models.VectorParams) else None
                if size is not None and size != self._dimensions:
                    msg = (
                        f"collection {self._collection!r} stores {size}-d vectors but the embedder "
                        f"produces {self._dimensions}-d vectors; re-index into a new collection"
                    )
                    raise VectorStoreConfigError(msg)
                return
            await self._client.create_collection(
                self._collection,
                vectors_config=models.VectorParams(
                    size=self._dimensions, distance=models.Distance.COSINE
                ),
            )
            if not self._local:
                for field in ("visibility", "category", "document_id", "slug"):
                    await self._client.create_payload_index(
                        self._collection,
                        field_name=field,
                        field_schema=models.PayloadSchemaType.KEYWORD,
                    )
        except VectorStoreConfigError:
            raise
        except Exception as exc:
            raise DependencyUnavailable(
                log_message=f"vector store unavailable: {type(exc).__name__}"
            ) from exc

    @staticmethod
    def point_id(document_id: str, chunk_index: int) -> str:
        return str(uuid.uuid5(_POINT_NAMESPACE, f"{document_id}:{chunk_index}"))

    async def upsert(self, items: Sequence[tuple[ChunkPayload, list[float]]]) -> None:
        if not items:
            return
        points = [
            models.PointStruct(
                id=self.point_id(payload.document_id, payload.chunk_index),
                vector=vector,
                payload=asdict(payload),
            )
            for payload, vector in items
        ]
        try:
            await self._client.upsert(self._collection, points=points, wait=True)
        except Exception as exc:
            raise DependencyUnavailable(
                log_message=f"vector upsert failed: {type(exc).__name__}"
            ) from exc

    async def delete_document(self, document_id: str) -> None:
        selector = models.FilterSelector(
            filter=models.Filter(
                must=[
                    models.FieldCondition(
                        key="document_id", match=models.MatchValue(value=document_id)
                    )
                ]
            )
        )
        try:
            await self._client.delete(self._collection, points_selector=selector, wait=True)
        except Exception as exc:
            raise DependencyUnavailable(
                log_message=f"vector delete failed: {type(exc).__name__}"
            ) from exc

    async def search(
        self,
        vector: list[float],
        *,
        visibilities: frozenset[KnowledgeVisibility],
        categories: Sequence[KnowledgeCategory] | None,
        limit: int,
        score_threshold: float,
    ) -> list[VectorHit]:
        if not visibilities:
            return []
        must: list[Any] = [
            models.FieldCondition(
                key="visibility", match=models.MatchAny(any=sorted(v.value for v in visibilities))
            )
        ]
        if categories:
            must.append(
                models.FieldCondition(
                    key="category", match=models.MatchAny(any=sorted(c.value for c in categories))
                )
            )
        try:
            response = await self._client.query_points(
                self._collection,
                query=vector,
                query_filter=models.Filter(must=must),
                limit=limit,
                with_payload=True,
                score_threshold=score_threshold,
            )
        except Exception as exc:
            raise DependencyUnavailable(
                log_message=f"vector search failed: {type(exc).__name__}"
            ) from exc
        hits: list[VectorHit] = []
        for point in response.points:
            payload = _payload(point.payload)
            if payload is not None:
                hits.append(VectorHit(score=float(point.score), payload=payload))
        return hits

    async def count(self) -> int:
        try:
            if not await self._client.collection_exists(self._collection):
                return 0
            return int((await self._client.count(self._collection, exact=True)).count)
        except Exception as exc:
            raise DependencyUnavailable(
                log_message=f"vector count failed: {type(exc).__name__}"
            ) from exc

    async def healthy(self) -> bool:
        try:
            await self._client.collection_exists(self._collection)
        except Exception:  # noqa: BLE001 - a health probe reports failure, it never raises
            return False
        return True

    async def close(self) -> None:
        await self._client.close()


def _payload(raw: dict[str, Any] | None) -> ChunkPayload | None:
    if not raw:
        return None
    try:
        return ChunkPayload(
            document_id=str(raw["document_id"]),
            chunk_index=int(raw["chunk_index"]),
            title=str(raw["title"]),
            section=str(raw.get("section", "")),
            text=str(raw["text"]),
            category=str(raw["category"]),
            visibility=str(raw["visibility"]),
            slug=str(raw["slug"]),
            version=int(raw["version"]),
        )
    except (KeyError, TypeError, ValueError):
        return None
