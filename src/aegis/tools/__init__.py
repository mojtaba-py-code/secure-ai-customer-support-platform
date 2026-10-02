"""The only way the model can affect the business: a small set of typed, permission-checked tools.

    LLM -> tool request -> schema validation -> allow-list for this turn -> RBAC check
        -> service (ownership in SQL) -> database -> minimised, validated output -> LLM

The model never supplies *who* it acts for: every tool receives the authenticated principal
from the server-side context, so an injected "customer_id=..." has nothing to bind to.
"""
