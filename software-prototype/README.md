# Software Prototype

This is the skeleton for the Risk-Aware Compliance-as-Code CI/CD Pipeline software prototype.

## Prerequisites

- Python 3.14 or higher
- uv (fast Python package installer)

### Installing uv

#### macOS

If you have Python installed, you can use pip:

```bash
pip install uv
```

Alternatively, using the installer script:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Or using Homebrew:

```bash
brew install uv
```

#### Linux

If you have Python installed, you can use pip:

```bash
pip install uv
```

Alternatively, using the installer script:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

#### Windows

If you have Python installed, you can use pip:

```bash
pip install uv
```

Alternatively, using PowerShell:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Or using winget (if available):

```bash
winget install --id=astral-sh.uv  --source winget
```

For more details or other installation methods, see the [uv installation guide](https://docs.astral.sh/uv/getting-started/installation/).

## Setup

1. Clone or navigate to the project directory.

2. Install dependencies:

```bash
make install
```

This runs `uv sync` to create a virtual environment and install dependencies.

## Running the Application

To run the application locally:

```bash
make run
```

This executes `uv run software-prototype`, which will print "Pipeline starting...".

## Building and Running with Docker

To build the Docker image:

```bash
make docker-build
```

To run the application in a Docker container:

```bash
make docker-run
```

## CI Build Workflow

The repository includes a GitHub Actions workflow at
`.github/workflows/software-prototype-build.yml` to define build processing for
this prototype.

It runs when:

- A pull request changes files under `software-prototype/`
- A push to `main` changes files under `software-prototype/`
- Triggered manually with `workflow_dispatch`

Workflow steps:

1. Set up Python 3.14 on `ubuntu-latest`
2. Install `uv` and sync dependencies with `uv sync --frozen`
3. Run a smoke test using `uv run software-prototype`
4. Build package artifacts with `uv build`
5. Build a Docker image (`software-prototype:ci`) for security scanning
6. Generate a CycloneDX SBOM with Trivy (`trivy-sbom.cdx.json`)
7. Generate a vulnerability report in JSON (`trivy-vuln-report.json`)
8. Enforce policy by failing CI when any `CRITICAL` vulnerability is detected
9. Upload `dist/*` and security scan reports as CI artifacts

## Project Structure

- `app/`: Python package containing the application code
  - `__init__.py`: Package initializer
  - `main.py`: Main entry point
- `pyproject.toml`: Project configuration for uv
- `Dockerfile`: Docker configuration
- `Makefile`: Build and run commands
- `README.md`: This file

## Development

To add dependencies, edit `pyproject.toml` and run `uv sync`.

To activate the virtual environment manually:

#### macOS/Linux

```bash
source .venv/bin/activate
```

#### Windows (Command Prompt)

```cmd
.venv\Scripts\activate
```

#### Windows (PowerShell)

```powershell
.venv\Scripts\activate.ps1
```

## Cleaning Up

To clean build artifacts and Docker images:

```bash
make clean
```
