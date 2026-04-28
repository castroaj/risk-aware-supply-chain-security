"""
backends/anthropic_backend.py
==============================
Anthropic Messages API backend for LLM-assisted SBOM labeling.

Requires the `anthropic` package, installed via the `llm` optional extra:

    pip install 'risk-classifier[llm]'

The `anthropic` SDK is imported lazily inside __init__ so that the base
package remains importable without it — only LLM mode invocations will fail
if the extra is not installed.
"""

import logging

_log = logging.getLogger(__name__)


class AnthropicBackend:
    """
    LLMBackend implementation backed by the Anthropic Messages API.

    WHAT:
        Wraps the `anthropic` Python SDK to expose the single `complete()`
        method required by the LLMBackend protocol. Uses temperature=0 to
        maximize output determinism across labeling runs.

    WHY:
        Claude models (Sonnet, Opus, Haiku) are suitable for security-domain
        reasoning tasks and return well-structured JSON when given an explicit
        output schema in the system prompt.

    Args:
        api_key:    Anthropic API key. Obtain from https://console.anthropic.com/
        model:      Model identifier string, e.g. "claude-sonnet-4-6" or
                    "claude-haiku-4-5-20251001". Prefer the most capable model
                    available for security-critical labeling.
        max_tokens: Maximum tokens to generate in the response. 4608 provides
                    sufficient headroom for the structured JSON label output and
                    up to 90-word justifications defined in the system prompt.
    """

    def __init__(self, api_key: str, model: str, max_tokens: int = 4608) -> None:
        try:
            import anthropic
        except ImportError as exc:
            raise ImportError(
                "The 'anthropic' package is required for LLM labeling mode. "
                "Install it with: pip install 'risk-classifier[llm]'"
            ) from exc

        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model
        self._max_tokens = max_tokens
        _log.debug("AnthropicBackend: initialized model=%s max_tokens=%d", model, max_tokens)

    def complete(self, system: str, user: str) -> str:
        """
        Send a system prompt and user message to the Anthropic API.

        Uses temperature=0 to reduce non-determinism across labeling runs.
        The caller (parse_llm_response in llm_labeler.py) is responsible for
        parsing the returned text into a LabelResult.

        Args:
            system: System prompt encoding the labeling rubric and output schema.
            user:   Compact JSON string containing the feature vector for one image.

        Returns:
            Raw text content of the first response block.
        """
        _log.debug("AnthropicBackend.complete: sending request to model=%s", self._model)
        response = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            temperature=0,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = response.content[0].text
        _log.debug("AnthropicBackend.complete: received %d chars", len(text))
        return text
