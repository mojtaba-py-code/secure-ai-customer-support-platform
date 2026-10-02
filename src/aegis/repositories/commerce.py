"""Customers, products, orders, payments and refunds."""

from __future__ import annotations

import uuid

from sqlalchemy import Select, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from aegis.domain.enums import RefundStatus
from aegis.models import Customer, Order, Product, Refund
from aegis.repositories.common import clamp_page, escape_like


class CustomerRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, customer_id: uuid.UUID) -> Customer | None:
        return await self._session.get(Customer, customer_id)

    async def count_orders(self, customer_id: uuid.UUID) -> int:
        stmt = select(func.count()).select_from(Order).where(Order.customer_id == customer_id)
        return int((await self._session.execute(stmt)).scalar_one())


class ProductRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_sku(self, sku: str) -> Product | None:
        result = await self._session.execute(
            select(Product).where(Product.sku == sku.strip().upper(), Product.is_active.is_(True))
        )
        return result.scalar_one_or_none()

    async def search(self, term: str, *, limit: int = 5) -> list[Product]:
        pattern = f"%{escape_like(term.strip().lower())}%"
        stmt = (
            select(Product)
            .where(
                Product.is_active.is_(True),
                or_(
                    func.lower(Product.name).like(pattern, escape="\\"),
                    func.lower(Product.category).like(pattern, escape="\\"),
                ),
            )
            .order_by(Product.name)
            .limit(max(1, min(limit, 10)))
        )
        return list((await self._session.execute(stmt)).scalars())


class OrderRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _with_details(self) -> Select[Order]:
        return select(Order).options(selectinload(Order.items), selectinload(Order.payments))

    async def get_for_customer(self, customer_id: uuid.UUID, order_number: str) -> Order | None:
        """Ownership is part of the query: another customer's order is simply not found."""
        stmt = self._with_details().where(
            Order.order_number == order_number.strip().upper(), Order.customer_id == customer_id
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_by_number(self, order_number: str) -> Order | None:
        stmt = self._with_details().where(Order.order_number == order_number.strip().upper())
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_for_update(self, order_id: uuid.UUID) -> Order | None:
        stmt = (
            self._with_details()
            .where(Order.id == order_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def list_for_customer(
        self, customer_id: uuid.UUID, *, limit: int, offset: int
    ) -> list[Order]:
        limit, offset = clamp_page(limit, offset)
        stmt = (
            self._with_details()
            .where(Order.customer_id == customer_id)
            .order_by(Order.placed_at.desc(), Order.id)
            .limit(limit)
            .offset(offset)
        )
        return list((await self._session.execute(stmt)).scalars())

    async def list_all(
        self, *, customer_id: uuid.UUID | None, limit: int, offset: int
    ) -> list[Order]:
        limit, offset = clamp_page(limit, offset)
        stmt = (
            self._with_details()
            .order_by(Order.placed_at.desc(), Order.id)
            .limit(limit)
            .offset(offset)
        )
        if customer_id is not None:
            stmt = stmt.where(Order.customer_id == customer_id)
        return list((await self._session.execute(stmt)).scalars())


class RefundRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def add(self, refund: Refund) -> Refund:
        self._session.add(refund)
        return refund

    async def get(self, refund_id: uuid.UUID) -> Refund | None:
        return await self._session.get(Refund, refund_id)

    async def get_for_update(self, refund_id: uuid.UUID) -> Refund | None:
        stmt = (
            select(Refund)
            .where(Refund.id == refund_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_by_provider_reference_for_update(
        self, *, provider_refund_id: str | None, refund_number: str | None
    ) -> Refund | None:
        """The refund a provider event is about: by the provider's id, else our number."""
        for column, value in (
            (Refund.provider_refund_id, provider_refund_id),
            (Refund.refund_number, refund_number),
        ):
            if not value:
                continue
            stmt = (
                select(Refund)
                .where(column == value)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            refund = (await self._session.execute(stmt)).scalar_one_or_none()
            if refund is not None:
                return refund
        return None

    async def get_for_customer(self, customer_id: uuid.UUID, refund_id: uuid.UUID) -> Refund | None:
        stmt = (
            select(Refund)
            .join(Order, Order.id == Refund.order_id)
            .where(Refund.id == refund_id, Order.customer_id == customer_id)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_by_number_for_customer(
        self, customer_id: uuid.UUID, refund_number: str
    ) -> Refund | None:
        stmt = (
            select(Refund)
            .join(Order, Order.id == Refund.order_id)
            .where(
                Refund.refund_number == refund_number.strip().upper(),
                Order.customer_id == customer_id,
            )
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def list_for_order(self, order_id: uuid.UUID) -> list[Refund]:
        stmt = (
            select(Refund).where(Refund.order_id == order_id).order_by(Refund.created_at, Refund.id)
        )
        return list((await self._session.execute(stmt)).scalars())

    async def list_for_customer(
        self, customer_id: uuid.UUID, *, limit: int, offset: int
    ) -> list[Refund]:
        limit, offset = clamp_page(limit, offset)
        stmt = (
            select(Refund)
            .join(Order, Order.id == Refund.order_id)
            .where(Order.customer_id == customer_id)
            .order_by(Refund.created_at.desc(), Refund.id)
            .limit(limit)
            .offset(offset)
        )
        return list((await self._session.execute(stmt)).scalars())

    async def list_by_status(
        self, status: RefundStatus | None, *, limit: int, offset: int
    ) -> list[Refund]:
        limit, offset = clamp_page(limit, offset)
        stmt = (
            select(Refund).order_by(Refund.created_at.desc(), Refund.id).limit(limit).offset(offset)
        )
        if status is not None:
            stmt = stmt.where(Refund.status == status)
        return list((await self._session.execute(stmt)).scalars())

    async def order_number_for(self, refund: Refund) -> str:
        stmt = select(Order.order_number).where(Order.id == refund.order_id)
        return str((await self._session.execute(stmt)).scalar_one())
