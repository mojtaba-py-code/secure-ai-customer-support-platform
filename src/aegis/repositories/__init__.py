"""Data access. Every query is built with SQLAlchemy expressions (bound parameters, no string
SQL); methods that serve customers take the owning ``customer_id``/``user_id`` and filter on it
in SQL, so ownership is enforced by the query itself rather than checked after loading.
"""
