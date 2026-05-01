"""
backends/__init__.py
====================
Platform-agnostic LLM backend interface for the risk classifier.

Any LLM provider (Anthropic, OpenAI, Ollama, etc.) can be used with the LLM
labeling mode by implementing the LLMBackend protocol — the only requirement is
a `complete(system, user) -> str` method that accepts a system prompt and a
user message and returns raw response text.

Provided implementations:
    AnthropicBackend — Anthropic Messages API (claude-* models)
                       Import from classifier.backends.anthropic_backend
"""

from typing import Protocol, runtime_checkable


@runtime_checkable
class LLMBackend(Protocol):
    """
    Minimal interface that all LLM provider backends must satisfy.

    WHAT:
        A callable object with a single `complete` method that sends a
        system prompt and a user message to an LLM and returns the raw
        response text.

    WHY:
        Keeping the interface to one method makes it trivial to add new
        providers (OpenAI, Ollama, local models) without changing any
        calling code in sbom_extractor or data_loader.

    HOW TO IMPLEMENT:
        class MyBackend:
            def complete(self, system: str, user: str) -> str:
                # call your LLM API here
                return response_text
    """

    def complete(self, system: str, user: str) -> str:
        """
        Send a system prompt and a user message to the LLM.

        Args:
            system: The system prompt (labeling rubric and output format).
            user:   The user message (compact JSON feature vector for one image).

        Returns:
            Raw response text from the model. Callers are responsible for
            parsing the text into a structured LabelResult.
        """
        ...


__all__ = ["LLMBackend"]
