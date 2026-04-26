VENV        := .venv
PYTHON      := $(VENV)/bin/python
PIP         := $(VENV)/bin/pip

MANIFESTS    := data/image-lists/
DATA_ROOT    := data/scans/
LABELS_ROOT  := data/labels/
RUNS_DIR     := training-runs
TIMESTAMP    := $(shell date +%Y%m%d-%H%M%S)
OUTPUT_DIR   := $(RUNS_DIR)/$(TIMESTAMP)

# Hyper-params
MAX_DEPTH := 4
MIN_SAMPLES_SPLIT := 4
MIN_SAMPLES_LEAF := 2
CLASS_WEIGHT := '{"ALLOW":4, "WARN":2, "BLOCK":3}'

# LLM labeling — set via environment or make argument.
#
# Anthropic (default):
#   make label-llm-anthropic
#   make label-llm-anthropic LLM_MODEL=claude-haiku-4-5-20251001
#   make label-llm-anthropic SYSTEM_PROMPT=config/system-prompt-v2.md
#   ANTHROPIC_API_KEY=sk-ant-... make label-llm-anthropic
#
# Gemini:
#   make label-llm-gemini
#   make label-llm-gemini GEMINI_MODEL=gemini-2.5-flash
#   make label-llm-gemini SYSTEM_PROMPT=config/system-prompt-v2.md
#   GEMINI_API_KEY=AIza... make label-llm-gemini
LLM_MODEL            ?= claude-sonnet-4-6
LLM_API_KEY          ?= $(ANTHROPIC_API_KEY)
GEMINI_MODEL         ?= gemini-2.5-flash
GEMINI_API_KEY       ?= $(GEMINI_API_KEY)
SYSTEM_PROMPT        ?= config/system-prompt-v2.md

.PHONY: install label label-llm-anthropic label-llm-gemini test train clean build

## install  — create venv and install package in editable mode with dev extras
install:
	./setup.sh

## label     — extract features and assign rule labels (threshold mode); write per-bucket CSVs
label:
	$(VENV)/bin/risk-classifier-label \
		--manifests-dir $(MANIFESTS) \
		--data-root $(DATA_ROOT) \
		--output-dir $(LABELS_ROOT)

## label-llm-anthropic — LLM-assisted labels via Anthropic (claude-sonnet-4-6 by default)
label-llm-anthropic:
	$(VENV)/bin/risk-classifier-label \
		--manifests-dir $(MANIFESTS) \
		--data-root $(DATA_ROOT) \
		--output-dir $(LABELS_ROOT) \
		--labeler-mode llm \
		--llm-provider anthropic \
		--llm-model $(LLM_MODEL) \
		--llm-api-key $(LLM_API_KEY) \
		--system-prompt $(SYSTEM_PROMPT)

## label-llm-gemini — LLM-assisted labels via Google Gemini (gemini-2.5-flash by default)
label-llm-gemini:
	$(VENV)/bin/risk-classifier-label \
		--manifests-dir $(MANIFESTS) \
		--data-root $(DATA_ROOT) \
		--output-dir $(LABELS_ROOT) \
		--labeler-mode llm \
		--llm-provider gemini \
		--llm-model $(GEMINI_MODEL) \
		--llm-api-key $(GEMINI_API_KEY) \
		--system-prompt $(SYSTEM_PROMPT)

## test     — run the full test suite
test:
	$(PYTHON) -m pytest tests/ -v

## train    — train the Decision Tree; artifacts written to training-runs/YYYYMMDD-HHMMSS/
train:
	@echo "Output dir: $(OUTPUT_DIR)"
	$(VENV)/bin/risk-classifier-train \
		--labels-dir $(LABELS_ROOT) \
		--output-dir $(OUTPUT_DIR) \
		--max-depth $(MAX_DEPTH) \
		--min-samples-split $(MIN_SAMPLES_SPLIT) \
		--min-samples-leaf $(MIN_SAMPLES_LEAF) \
		--class-weight $(CLASS_WEIGHT)

## build    — build a source distribution and wheel into dist/
build:
	$(PIP) install --quiet build
	$(PYTHON) -m build

## clean    — remove build artifacts and Python cache files
clean:
	rm -rf dist/ build/ src/*.egg-info src/risk_classifier.egg-info
	find . -path ./.venv -prune -o -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -path ./.venv -prune -o -type f -name "*.pyc" -delete 2>/dev/null || true

help:
	@grep -E '^##' Makefile | sed 's/## /  make /'
