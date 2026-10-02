"""Short-lived shared state: rate-limit counters, locks, budgets and conversation state.

Only non-sensitive, expiring data goes here (counters, flags, ids). Every key has a TTL, values
are plain strings / JSON validated on read (never pickle), and keys that would contain user
input are hashed.
"""
