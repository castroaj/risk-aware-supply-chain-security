"""
backends/gemini_backend.py
==========================
Google Gemini API backend for LLM-assisted SBOM labeling.

Requires the `google-genai` package, installed via the `gemini` optional extra:

    pip install 'risk-classifier[gemini]'

The SDK is imported lazily inside __init__ so that the base package remains
importable without it — only Gemini mode invocations will fail if the extra
is not installed.
"""

import logging

_log = logging.getLogger(__name__)


class GeminiBackend:
    """
    LLMBackend implementation backed by the Google Gemini API.

    WHAT:
        Wraps the `google-genai` Python SDK to expose the single `complete()`
        method required by the LLMBackend protocol. Uses temperature=0 to
        maximise output determinism across labeling runs.

    WHY:
        Gemini models offer an alternative inference backend when Anthropic
        is unavailable or when cost/latency trade-offs favour Google's API.
        The same SYSTEM_PROMPT and structured JSON output format defined in
        llm_labeler.py work without modification across both providers.

    Args:
        api_key:    Google AI Studio API key. Obtain from
                    https://aistudio.google.com/app/apikey
        model:      Model identifier string, e.g. "gemini-2.0-flash" or
                    "gemini-1.5-pro". Gemini 2.0 Flash is recommended for
                    cost-efficient labeling runs.
        max_tokens: Maximum tokens to generate in the response. 512 is
                    sufficient for the structured JSON label output defined
                    in the system prompt.
    """

    def __init__(self, api_key: str, model: str, max_tokens: int = 2048) -> None:
        try:
            from google import genai
            from google.genai import types as genai_types
        except ImportError as exc:
            raise ImportError(
                "The 'google-genai' package is required for Gemini labeling mode. "
                "Install it with: pip install 'risk-classifier[gemini]'"
            ) from exc

        self._client = genai.Client(api_key=api_key)
        self._model_name = model
        self._max_tokens = max_tokens
        self._genai_types = genai_types
        _log.debug("GeminiBackend: initialized model=%s max_tokens=%d", model, max_tokens)

    def complete(self, system: str, user: str) -> str:
        """
        Send a system prompt and user message to the Gemini API.

        Uses temperature=0 to reduce non-determinism across labeling runs.
        The system prompt is passed via `system_instruction` in the generation
        config so it is not counted against the user-turn token budget. The
        caller (parse_llm_response in llm_labeler.py) is responsible for
        parsing the returned text into a LabelResult.

        Args:
            system: System prompt encoding the labeling rubric and output schema.
            user:   Compact JSON string containing the feature vector for one image.

        Returns:
            Raw text content of the first response candidate.
        """
        config = self._genai_types.GenerateContentConfig(
            system_instruction=system,
            temperature=0,
            max_output_tokens=self._max_tokens,
        )
        _log.debug("GeminiBackend.complete: sending request to model=%s", self._model_name)
        response = self._client.models.generate_content(
            model=self._model_name,
            contents=user,
            config=config,
        )
        text = response.text
        _log.debug("GeminiBackend.complete: received %d chars", len(text))
        return text
