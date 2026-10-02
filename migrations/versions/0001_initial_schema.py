"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-09-30 00:20:51.391021
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0001'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('audit_events',
    sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('actor_user_id', sa.Uuid(), nullable=True),
    sa.Column('actor_role', sa.String(length=32), nullable=True),
    sa.Column('action', sa.String(length=80), nullable=False),
    sa.Column('resource_type', sa.String(length=40), nullable=True),
    sa.Column('resource_id', sa.String(length=64), nullable=True),
    sa.Column('outcome', sa.String(length=32), nullable=False),
    sa.Column('request_id', sa.String(length=64), nullable=True),
    sa.Column('ip_address', sa.String(length=45), nullable=True),
    sa.Column('details', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("outcome IN ('success', 'failure', 'denied', 'error')", name=op.f('ck_audit_events_audit_outcome')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_events'))
    )
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.create_index('ix_audit_events_action', ['action', 'occurred_at'], unique=False)
        batch_op.create_index('ix_audit_events_actor', ['actor_user_id', 'occurred_at'], unique=False)
        batch_op.create_index('ix_audit_events_occurred_at', ['occurred_at'], unique=False)

    op.create_table('customers',
    sa.Column('customer_number', sa.String(length=16), nullable=False),
    sa.Column('full_name', sa.String(length=120), nullable=False),
    sa.Column('email', sa.String(length=254), nullable=False),
    sa.Column('phone', sa.Text(), nullable=True),
    sa.Column('address', sa.Text(), nullable=True),
    sa.Column('tier', sa.String(length=32), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("tier IN ('standard', 'plus', 'vip')", name=op.f('ck_customers_tier')),
    sa.CheckConstraint('email = lower(email)', name=op.f('ck_customers_email_lowercase')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_customers')),
    sa.UniqueConstraint('customer_number', name=op.f('uq_customers_customer_number')),
    sa.UniqueConstraint('email', name=op.f('uq_customers_email'))
    )
    op.create_table('llm_usage',
    sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=True),
    sa.Column('conversation_id', sa.Uuid(), nullable=True),
    sa.Column('task', sa.String(length=20), nullable=False),
    sa.Column('provider', sa.String(length=20), nullable=False),
    sa.Column('model', sa.String(length=60), nullable=False),
    sa.Column('input_tokens', sa.Integer(), nullable=False),
    sa.Column('output_tokens', sa.Integer(), nullable=False),
    sa.Column('cache_read_tokens', sa.Integer(), nullable=False),
    sa.Column('cache_write_tokens', sa.Integer(), nullable=False),
    sa.Column('cost_usd', sa.Numeric(precision=12, scale=6), nullable=False),
    sa.Column('latency_ms', sa.Integer(), nullable=False),
    sa.Column('outcome', sa.String(length=20), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_llm_usage'))
    )
    with op.batch_alter_table('llm_usage', schema=None) as batch_op:
        batch_op.create_index('ix_llm_usage_occurred_at', ['occurred_at'], unique=False)
        batch_op.create_index('ix_llm_usage_user', ['user_id', 'occurred_at'], unique=False)

    op.create_table('products',
    sa.Column('sku', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=160), nullable=False),
    sa.Column('category', sa.String(length=60), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('price_cents', sa.Integer(), nullable=False),
    sa.Column('currency', sa.String(length=3), nullable=False),
    sa.Column('warranty_months', sa.Integer(), nullable=False),
    sa.Column('stock_status', sa.String(length=32), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("stock_status IN ('in_stock', 'low_stock', 'out_of_stock', 'discontinued')", name=op.f('ck_products_stock_status')),
    sa.CheckConstraint('price_cents >= 0', name=op.f('ck_products_price_non_negative')),
    sa.CheckConstraint('warranty_months >= 0', name=op.f('ck_products_warranty_non_negative')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_products')),
    sa.UniqueConstraint('sku', name=op.f('uq_products_sku'))
    )
    with op.batch_alter_table('products', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_products_category'), ['category'], unique=False)

    op.create_table('orders',
    sa.Column('order_number', sa.String(length=16), nullable=False),
    sa.Column('customer_id', sa.Uuid(), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('currency', sa.String(length=3), nullable=False),
    sa.Column('subtotal_cents', sa.Integer(), nullable=False),
    sa.Column('shipping_cents', sa.Integer(), nullable=False),
    sa.Column('total_cents', sa.Integer(), nullable=False),
    sa.Column('placed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('shipped_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('delivered_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('cancelled_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('carrier', sa.String(length=40), nullable=True),
    sa.Column('tracking_number', sa.String(length=64), nullable=True),
    sa.Column('estimated_delivery', sa.Date(), nullable=True),
    sa.Column('shipping_address', sa.Text(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("status IN ('pending', 'paid', 'processing', 'shipped', 'delivered', 'cancelled', 'returned')", name=op.f('ck_orders_order_status')),
    sa.CheckConstraint('subtotal_cents >= 0 AND shipping_cents >= 0', name=op.f('ck_orders_amounts_non_negative')),
    sa.CheckConstraint('total_cents = subtotal_cents + shipping_cents', name=op.f('ck_orders_total_consistent')),
    sa.ForeignKeyConstraint(['customer_id'], ['customers.id'], name=op.f('fk_orders_customer_id_customers'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_orders')),
    sa.UniqueConstraint('order_number', name=op.f('uq_orders_order_number'))
    )
    with op.batch_alter_table('orders', schema=None) as batch_op:
        batch_op.create_index('ix_orders_customer_placed', ['customer_id', 'placed_at'], unique=False)

    op.create_table('users',
    sa.Column('email', sa.String(length=254), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('role', sa.String(length=32), nullable=False),
    sa.Column('display_name', sa.String(length=120), nullable=False),
    sa.Column('customer_id', sa.Uuid(), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('failed_login_count', sa.Integer(), nullable=False),
    sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('password_changed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("(role = 'customer') = (customer_id IS NOT NULL)", name=op.f('ck_users_customer_link')),
    sa.CheckConstraint("role IN ('customer', 'support_agent', 'support_manager', 'admin')", name=op.f('ck_users_role')),
    sa.CheckConstraint('email = lower(email)', name=op.f('ck_users_email_lowercase')),
    sa.CheckConstraint('failed_login_count >= 0', name=op.f('ck_users_failed_logins_non_negative')),
    sa.ForeignKeyConstraint(['customer_id'], ['customers.id'], name=op.f('fk_users_customer_id_customers'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_users')),
    sa.UniqueConstraint('customer_id', name=op.f('uq_users_customer_id')),
    sa.UniqueConstraint('email', name=op.f('uq_users_email'))
    )
    op.create_table('auth_sessions',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_reason', sa.String(length=40), nullable=True),
    sa.Column('ip_address', sa.String(length=45), nullable=True),
    sa.Column('user_agent', sa.String(length=200), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_auth_sessions_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_auth_sessions'))
    )
    with op.batch_alter_table('auth_sessions', schema=None) as batch_op:
        batch_op.create_index('ix_auth_sessions_expires_at', ['expires_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_auth_sessions_user_id'), ['user_id'], unique=False)

    op.create_table('conversations',
    sa.Column('customer_id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('subject', sa.String(length=200), nullable=True),
    sa.Column('channel', sa.String(length=20), nullable=False),
    sa.Column('last_message_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('message_count', sa.Integer(), nullable=False),
    sa.Column('assigned_agent_id', sa.Uuid(), nullable=True),
    sa.Column('escalated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('escalation_reason', sa.String(length=32), nullable=True),
    sa.Column('escalation_priority', sa.String(length=32), nullable=True),
    sa.Column('summary', sa.Text(), nullable=True),
    sa.Column('summarized_through', sa.Integer(), nullable=False),
    sa.Column('ai_failure_count', sa.Integer(), nullable=False),
    sa.Column('suspicious_count', sa.Integer(), nullable=False),
    sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("escalation_priority IN ('low', 'medium', 'high', 'urgent')", name=op.f('ck_conversations_escalation_priority')),
    sa.CheckConstraint("escalation_reason IN ('customer_request', 'account_security', 'payment_risk', 'legal', 'low_confidence', 'repeated_failure', 'unsupported_request', 'sensitive_data', 'negative_sentiment', 'policy_exception', 'ai_unavailable', 'suspicious_activity')", name=op.f('ck_conversations_handoff_reason')),
    sa.CheckConstraint("status IN ('active', 'awaiting_agent', 'agent_assigned', 'resolved', 'closed')", name=op.f('ck_conversations_conversation_status')),
    sa.ForeignKeyConstraint(['assigned_agent_id'], ['users.id'], name=op.f('fk_conversations_assigned_agent_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['customer_id'], ['customers.id'], name=op.f('fk_conversations_customer_id_customers'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_conversations_user_id_users'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_conversations'))
    )
    with op.batch_alter_table('conversations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_conversations_customer_id'), ['customer_id'], unique=False)
        batch_op.create_index('ix_conversations_queue', ['status', 'escalation_priority', 'escalated_at'], unique=False)
        batch_op.create_index('ix_conversations_user_last_message', ['user_id', 'last_message_at'], unique=False)

    op.create_table('idempotency_records',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('scope', sa.String(length=60), nullable=False),
    sa.Column('key', sa.String(length=120), nullable=False),
    sa.Column('request_hash', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('resource_id', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_idempotency_records_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_idempotency_records')),
    sa.UniqueConstraint('user_id', 'scope', 'key', name='uq_idempotency_records_user_scope_key')
    )
    with op.batch_alter_table('idempotency_records', schema=None) as batch_op:
        batch_op.create_index('ix_idempotency_records_expires_at', ['expires_at'], unique=False)

    op.create_table('knowledge_documents',
    sa.Column('title', sa.String(length=200), nullable=False),
    sa.Column('slug', sa.String(length=120), nullable=False),
    sa.Column('category', sa.String(length=32), nullable=False),
    sa.Column('visibility', sa.String(length=32), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('source_filename', sa.String(length=120), nullable=False),
    sa.Column('mime_type', sa.String(length=40), nullable=False),
    sa.Column('size_bytes', sa.Integer(), nullable=False),
    sa.Column('content_sha256', sa.String(length=64), nullable=False),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('injection_score', sa.Float(), nullable=False),
    sa.Column('injection_categories', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('chunk_count', sa.Integer(), nullable=False),
    sa.Column('error_code', sa.String(length=40), nullable=True),
    sa.Column('uploaded_by_user_id', sa.Uuid(), nullable=True),
    sa.Column('reviewed_by_user_id', sa.Uuid(), nullable=True),
    sa.Column('effective_date', sa.Date(), nullable=True),
    sa.Column('indexed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('meta', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("category IN ('faq', 'refund_policy', 'shipping_policy', 'cancellation_policy', 'warranty', 'payment_policy', 'account_policy', 'privacy_policy', 'product_docs', 'internal_playbook')", name=op.f('ck_knowledge_documents_kb_category')),
    sa.CheckConstraint("status IN ('pending', 'quarantined', 'indexing', 'indexed', 'failed', 'archived')", name=op.f('ck_knowledge_documents_kb_status')),
    sa.CheckConstraint("visibility IN ('public', 'internal')", name=op.f('ck_knowledge_documents_kb_visibility')),
    sa.ForeignKeyConstraint(['reviewed_by_user_id'], ['users.id'], name=op.f('fk_knowledge_documents_reviewed_by_user_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['uploaded_by_user_id'], ['users.id'], name=op.f('fk_knowledge_documents_uploaded_by_user_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_knowledge_documents')),
    sa.UniqueConstraint('slug', 'version', name='uq_knowledge_documents_slug_version')
    )
    with op.batch_alter_table('knowledge_documents', schema=None) as batch_op:
        batch_op.create_index('ix_knowledge_documents_status', ['status'], unique=False)
        batch_op.create_index('uq_knowledge_documents_live_content', ['content_sha256'], unique=True, postgresql_where=sa.text("status <> 'archived'"), sqlite_where=sa.text("status <> 'archived'"))

    op.create_table('order_items',
    sa.Column('order_id', sa.Uuid(), nullable=False),
    sa.Column('product_id', sa.Uuid(), nullable=True),
    sa.Column('position', sa.Integer(), nullable=False),
    sa.Column('sku', sa.String(length=32), nullable=False),
    sa.Column('product_name', sa.String(length=160), nullable=False),
    sa.Column('quantity', sa.Integer(), nullable=False),
    sa.Column('unit_price_cents', sa.Integer(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint('quantity > 0', name=op.f('ck_order_items_quantity_positive')),
    sa.CheckConstraint('unit_price_cents >= 0', name=op.f('ck_order_items_unit_price_non_negative')),
    sa.ForeignKeyConstraint(['order_id'], ['orders.id'], name=op.f('fk_order_items_order_id_orders'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['product_id'], ['products.id'], name=op.f('fk_order_items_product_id_products'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_order_items'))
    )
    with op.batch_alter_table('order_items', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_order_items_order_id'), ['order_id'], unique=False)

    op.create_table('password_reset_tokens',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('requested_ip', sa.String(length=45), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_password_reset_tokens_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_password_reset_tokens')),
    sa.UniqueConstraint('token_hash', name=op.f('uq_password_reset_tokens_token_hash'))
    )
    with op.batch_alter_table('password_reset_tokens', schema=None) as batch_op:
        batch_op.create_index('ix_password_reset_tokens_expires_at', ['expires_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_password_reset_tokens_user_id'), ['user_id'], unique=False)

    op.create_table('payments',
    sa.Column('order_id', sa.Uuid(), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('method', sa.String(length=32), nullable=False),
    sa.Column('amount_cents', sa.Integer(), nullable=False),
    sa.Column('currency', sa.String(length=3), nullable=False),
    sa.Column('card_brand', sa.String(length=20), nullable=True),
    sa.Column('card_last4', sa.String(length=4), nullable=True),
    sa.Column('provider_reference', sa.String(length=64), nullable=False),
    sa.Column('failure_code', sa.String(length=40), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('captured_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("method IN ('card', 'paypal', 'bank_transfer', 'gift_card')", name=op.f('ck_payments_payment_method')),
    sa.CheckConstraint("status IN ('pending', 'authorized', 'captured', 'failed', 'voided', 'partially_refunded', 'refunded')", name=op.f('ck_payments_payment_status')),
    sa.CheckConstraint('amount_cents > 0', name=op.f('ck_payments_amount_positive')),
    sa.CheckConstraint('card_last4 IS NULL OR length(card_last4) = 4', name=op.f('ck_payments_card_last4_only')),
    sa.ForeignKeyConstraint(['order_id'], ['orders.id'], name=op.f('fk_payments_order_id_orders'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_payments')),
    sa.UniqueConstraint('provider_reference', name=op.f('uq_payments_provider_reference'))
    )
    with op.batch_alter_table('payments', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_payments_order_id'), ['order_id'], unique=False)

    op.create_table('conversation_messages',
    sa.Column('conversation_id', sa.Uuid(), nullable=False),
    sa.Column('sequence', sa.Integer(), nullable=False),
    sa.Column('sender_type', sa.String(length=32), nullable=False),
    sa.Column('sender_user_id', sa.Uuid(), nullable=True),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('meta', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("sender_type IN ('customer', 'assistant', 'agent', 'system')", name=op.f('ck_conversation_messages_sender_type')),
    sa.ForeignKeyConstraint(['conversation_id'], ['conversations.id'], name=op.f('fk_conversation_messages_conversation_id_conversations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['sender_user_id'], ['users.id'], name=op.f('fk_conversation_messages_sender_user_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_conversation_messages')),
    sa.UniqueConstraint('conversation_id', 'sequence', name='uq_conversation_messages_sequence')
    )
    op.create_table('pending_actions',
    sa.Column('conversation_id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('customer_id', sa.Uuid(), nullable=False),
    sa.Column('action_type', sa.String(length=32), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('params', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('summary', sa.String(length=300), nullable=False),
    sa.Column('dedupe_key', sa.String(length=120), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('result', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("action_type IN ('refund_request', 'order_cancellation')", name=op.f('ck_pending_actions_action_type')),
    sa.CheckConstraint("status IN ('pending', 'executing', 'executed', 'declined', 'expired', 'failed')", name=op.f('ck_pending_actions_action_status')),
    sa.ForeignKeyConstraint(['conversation_id'], ['conversations.id'], name=op.f('fk_pending_actions_conversation_id_conversations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['customer_id'], ['customers.id'], name=op.f('fk_pending_actions_customer_id_customers'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_pending_actions_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_pending_actions'))
    )
    with op.batch_alter_table('pending_actions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pending_actions_conversation_id'), ['conversation_id'], unique=False)
        batch_op.create_index('uq_pending_actions_open_dedupe', ['dedupe_key'], unique=True, postgresql_where=sa.text("status IN ('pending', 'executing')"), sqlite_where=sa.text("status IN ('pending', 'executing')"))

    op.create_table('refresh_tokens',
    sa.Column('session_id', sa.Uuid(), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['session_id'], ['auth_sessions.id'], name=op.f('fk_refresh_tokens_session_id_auth_sessions'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_refresh_tokens')),
    sa.UniqueConstraint('token_hash', name=op.f('uq_refresh_tokens_token_hash'))
    )
    with op.batch_alter_table('refresh_tokens', schema=None) as batch_op:
        batch_op.create_index('ix_refresh_tokens_expires_at', ['expires_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_refresh_tokens_session_id'), ['session_id'], unique=False)

    op.create_table('refunds',
    sa.Column('refund_number', sa.String(length=16), nullable=False),
    sa.Column('order_id', sa.Uuid(), nullable=False),
    sa.Column('payment_id', sa.Uuid(), nullable=False),
    sa.Column('amount_cents', sa.Integer(), nullable=False),
    sa.Column('currency', sa.String(length=3), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('reason', sa.String(length=32), nullable=False),
    sa.Column('customer_note', sa.Text(), nullable=True),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('requested_by_user_id', sa.Uuid(), nullable=True),
    sa.Column('reviewed_by_user_id', sa.Uuid(), nullable=True),
    sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('decision_note', sa.String(length=500), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('idempotency_key', sa.String(length=120), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("reason IN ('damaged', 'defective', 'wrong_item', 'not_as_described', 'no_longer_needed', 'late_delivery', 'order_cancelled', 'other')", name=op.f('ck_refunds_refund_reason')),
    sa.CheckConstraint("source IN ('ai_agent', 'customer', 'staff', 'escalation')", name=op.f('ck_refunds_refund_source')),
    sa.CheckConstraint("status IN ('pending_review', 'approved', 'processing', 'completed', 'rejected', 'failed')", name=op.f('ck_refunds_refund_status')),
    sa.CheckConstraint('amount_cents > 0', name=op.f('ck_refunds_amount_positive')),
    sa.ForeignKeyConstraint(['order_id'], ['orders.id'], name=op.f('fk_refunds_order_id_orders'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['payment_id'], ['payments.id'], name=op.f('fk_refunds_payment_id_payments'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['requested_by_user_id'], ['users.id'], name=op.f('fk_refunds_requested_by_user_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['reviewed_by_user_id'], ['users.id'], name=op.f('fk_refunds_reviewed_by_user_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_refunds')),
    sa.UniqueConstraint('idempotency_key', name=op.f('uq_refunds_idempotency_key')),
    sa.UniqueConstraint('refund_number', name=op.f('uq_refunds_refund_number'))
    )
    with op.batch_alter_table('refunds', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_refunds_order_id'), ['order_id'], unique=False)
        batch_op.create_index('uq_refunds_one_open_per_order', ['order_id'], unique=True, postgresql_where=sa.text("status IN ('pending_review', 'approved', 'processing')"), sqlite_where=sa.text("status IN ('pending_review', 'approved', 'processing')"))

    op.create_table('support_tickets',
    sa.Column('ticket_number', sa.String(length=16), nullable=False),
    sa.Column('customer_id', sa.Uuid(), nullable=False),
    sa.Column('conversation_id', sa.Uuid(), nullable=True),
    sa.Column('created_by_user_id', sa.Uuid(), nullable=True),
    sa.Column('assigned_to_user_id', sa.Uuid(), nullable=True),
    sa.Column('subject', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('category', sa.String(length=40), nullable=False),
    sa.Column('priority', sa.String(length=32), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('idempotency_key', sa.String(length=120), nullable=True),
    sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("priority IN ('low', 'medium', 'high', 'urgent')", name=op.f('ck_support_tickets_ticket_priority')),
    sa.CheckConstraint("source IN ('ai_agent', 'customer', 'staff', 'escalation')", name=op.f('ck_support_tickets_ticket_source')),
    sa.CheckConstraint("status IN ('open', 'in_progress', 'pending_customer', 'resolved', 'closed')", name=op.f('ck_support_tickets_ticket_status')),
    sa.ForeignKeyConstraint(['assigned_to_user_id'], ['users.id'], name=op.f('fk_support_tickets_assigned_to_user_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['conversation_id'], ['conversations.id'], name=op.f('fk_support_tickets_conversation_id_conversations'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id'], name=op.f('fk_support_tickets_created_by_user_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['customer_id'], ['customers.id'], name=op.f('fk_support_tickets_customer_id_customers'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_support_tickets')),
    sa.UniqueConstraint('idempotency_key', name=op.f('uq_support_tickets_idempotency_key')),
    sa.UniqueConstraint('ticket_number', name=op.f('uq_support_tickets_ticket_number'))
    )
    with op.batch_alter_table('support_tickets', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_support_tickets_conversation_id'), ['conversation_id'], unique=False)
        batch_op.create_index('ix_support_tickets_customer_created', ['customer_id', 'created_at'], unique=False)
        batch_op.create_index('ix_support_tickets_status_priority', ['status', 'priority'], unique=False)



def downgrade() -> None:
    with op.batch_alter_table('support_tickets', schema=None) as batch_op:
        batch_op.drop_index('ix_support_tickets_status_priority')
        batch_op.drop_index('ix_support_tickets_customer_created')
        batch_op.drop_index(batch_op.f('ix_support_tickets_conversation_id'))

    op.drop_table('support_tickets')
    with op.batch_alter_table('refunds', schema=None) as batch_op:
        batch_op.drop_index('uq_refunds_one_open_per_order', postgresql_where=sa.text("status IN ('pending_review', 'approved', 'processing')"), sqlite_where=sa.text("status IN ('pending_review', 'approved', 'processing')"))
        batch_op.drop_index(batch_op.f('ix_refunds_order_id'))

    op.drop_table('refunds')
    with op.batch_alter_table('refresh_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_refresh_tokens_session_id'))
        batch_op.drop_index('ix_refresh_tokens_expires_at')

    op.drop_table('refresh_tokens')
    with op.batch_alter_table('pending_actions', schema=None) as batch_op:
        batch_op.drop_index('uq_pending_actions_open_dedupe', postgresql_where=sa.text("status IN ('pending', 'executing')"), sqlite_where=sa.text("status IN ('pending', 'executing')"))
        batch_op.drop_index(batch_op.f('ix_pending_actions_conversation_id'))

    op.drop_table('pending_actions')
    op.drop_table('conversation_messages')
    with op.batch_alter_table('payments', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_payments_order_id'))

    op.drop_table('payments')
    with op.batch_alter_table('password_reset_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_password_reset_tokens_user_id'))
        batch_op.drop_index('ix_password_reset_tokens_expires_at')

    op.drop_table('password_reset_tokens')
    with op.batch_alter_table('order_items', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_order_items_order_id'))

    op.drop_table('order_items')
    with op.batch_alter_table('knowledge_documents', schema=None) as batch_op:
        batch_op.drop_index('uq_knowledge_documents_live_content', postgresql_where=sa.text("status <> 'archived'"), sqlite_where=sa.text("status <> 'archived'"))
        batch_op.drop_index('ix_knowledge_documents_status')

    op.drop_table('knowledge_documents')
    with op.batch_alter_table('idempotency_records', schema=None) as batch_op:
        batch_op.drop_index('ix_idempotency_records_expires_at')

    op.drop_table('idempotency_records')
    with op.batch_alter_table('conversations', schema=None) as batch_op:
        batch_op.drop_index('ix_conversations_user_last_message')
        batch_op.drop_index('ix_conversations_queue')
        batch_op.drop_index(batch_op.f('ix_conversations_customer_id'))

    op.drop_table('conversations')
    with op.batch_alter_table('auth_sessions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_auth_sessions_user_id'))
        batch_op.drop_index('ix_auth_sessions_expires_at')

    op.drop_table('auth_sessions')
    op.drop_table('users')
    with op.batch_alter_table('orders', schema=None) as batch_op:
        batch_op.drop_index('ix_orders_customer_placed')

    op.drop_table('orders')
    with op.batch_alter_table('products', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_products_category'))

    op.drop_table('products')
    with op.batch_alter_table('llm_usage', schema=None) as batch_op:
        batch_op.drop_index('ix_llm_usage_user')
        batch_op.drop_index('ix_llm_usage_occurred_at')

    op.drop_table('llm_usage')
    op.drop_table('customers')
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.drop_index('ix_audit_events_occurred_at')
        batch_op.drop_index('ix_audit_events_actor')
        batch_op.drop_index('ix_audit_events_action')

    op.drop_table('audit_events')
