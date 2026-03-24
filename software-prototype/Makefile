# Makefile for software-prototype

.PHONY: install run build docker-build docker-run clean

# Install dependencies with uv
install:
	uv sync

# Run the application
run:
	uv run software-prototype

# Build the project (if needed)
build:
	uv build

# Build Docker image
docker-build:
	docker build -t software-prototype .

# Run Docker container
docker-run:
	docker run software-prototype

# Clean up
clean:
	rm -rf dist/
	docker rmi software-prototype || true
