"""Model access. The model is treated as an untrusted component: adapters here only move text
and tool *requests* in and out - they cannot reach the database, the filesystem or the network
beyond the configured provider endpoint (enforced by import-linter contracts).
"""
