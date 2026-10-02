"""Security primitives: identity, cryptography, input/output sanitisation and abuse detection.

Everything here is pure (no I/O, no web framework) so each control can be unit-tested in
isolation and reused by the API, the agent, the tools and the workers.
"""
