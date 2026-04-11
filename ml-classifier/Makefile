VENV        := .venv
PYTHON      := $(VENV)/bin/python
PIP         := $(VENV)/bin/pip

MANIFESTS   := data/image-lists/
DATA_ROOT   := data/scans/
OUTPUT_DIR  := analysis/

.PHONY: install test train clean build

## install  — create venv and install package in editable mode with dev extras
install:
	./setup.sh

## test     — run the full test suite
test:
	$(PYTHON) -m pytest tests/ -v

## train    — train the Decision Tree on all three SBOM buckets
train:
	$(VENV)/bin/risk-classifier train \
		--manifests-dir $(MANIFESTS) \
		--data-root $(DATA_ROOT) \
		--output-dir $(OUTPUT_DIR)

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
