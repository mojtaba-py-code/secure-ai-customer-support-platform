"""Version 1 of the public API.

Every v1 router carries the full ``/api/v1/...`` prefix itself (instead of inheriting it from a
parent router), so the matched route template - used as the metrics and access-log label - is the
complete public path.
"""

API_V1_PREFIX = "/api/v1"
