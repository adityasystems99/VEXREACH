"""Simulated dependency AST fixture that raises if ever imported/executed."""

raise RuntimeError("Dependency source MUST NEVER be executed or imported!")


def load(stream, Loader=None):
    return stream
