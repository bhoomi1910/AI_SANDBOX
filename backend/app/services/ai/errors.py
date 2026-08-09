"""Phase 4 AI engine error types.

Both exceptions are *expected* control-flow signals, never crashes:
- AIUnavailable: the provider is unreachable, has no models, or the model is
  missing. The investigation keeps its deterministic result.
- AIValidationError: the model responded but its output was rejected by the
  strict validator (non-JSON, wrong types, invented techniques). The response
  is discarded; nothing unvalidated is ever stored or shown.
"""


class AIUnavailable(Exception):
    """Ollama is unreachable or has no usable model."""


class AIValidationError(ValueError):
    """Model output failed strict schema/anti-hallucination validation."""
