"""Shared schema building blocks."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ResponseModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page[T](ResponseModel):
    items: list[T]
    limit: int
    offset: int


class Problem(BaseModel):
    """RFC 9457 problem details."""

    type: str = "about:blank"
    title: str
    status: int
    detail: str
    code: str
    request_id: str | None = None
    errors: list[dict[str, object]] | None = None
    details: dict[str, object] | None = None


class Message(BaseModel):
    detail: str = Field(max_length=300)
