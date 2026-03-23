FROM python:3.12-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy pyproject.toml and lock file if exists
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-install-project

# Copy the rest
COPY . .

# Install the project
RUN uv sync --frozen

# Run the app
CMD ["uv", "run", "software-prototype"]
