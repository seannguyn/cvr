# PCCS Container Vulnerability Report (CVR)

A full-stack application to generate and view container vulnerability reports.

## Architecture
-   **Backend**: FastAPI (Python)
-   **Frontend**: React (TypeScript, Vite)
-   **Infrastructure**: Kubernetes (Helm)

## Prerequisites
-   Python 3.9+
-   Node.js 18+
-   Kubernetes Cluster (for deployment)

## Local Development

### 1. Directory Structure
Ensure `raws/` and `reports/` directories exist at the project root:
```bash
mkdir -p raws reports
```

### 2. Backend
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
# The app looks for ../raws and ../reports by default
uvicorn src.pccs_cvr.app:app --reload --port 8000
```

### 3. Frontend
```bash
cd frontend
npm install
npm run dev
```

Access the UI at `http://localhost:5173`.

## Docker Build
```bash
# Backend
docker build -t pccs-cvr-backend:latest ./backend

# Frontend
docker build -t pccs-cvr-frontend:latest ./frontend
```

## Deployment
Deploy to Kubernetes using Helm:
```bash
helm install pccs-cvr ./charts/pccs-cvr
```

### 2. Create Configuration

Create `pyproject.toml` in the root:

```toml
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "pccs-cvr"
version = "0.1.0"
description = "PCCS CVR"
authors = [{ name = "PCSS" }]
requires-python = ">=3.9"
license={"text="MIT"}

[project.scripts]
pccs-cvr = "pccs_cvr.main:main"
```

### 3. Create Source Code

Create `src/pccs_cvr/__init__.py` (empty file):

```bash
touch src/pccs_cvr/__init__.py
```

Create `src/pccs_cvr/main.py`:

```python
import logging
import sys

def setup_logging():
    """Configure logging for the application."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

def main():
    """Main entry point of the application."""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    logger.info("Starting application")
    print("Hello World")
    logger.info("Application finished")

if __name__ == "__main__":
    main()
```

### 4. Setup and Run

Create a virtual environment, install the package, and run it:

```bash
# Create virtual environment
python3 -m venv .venv

# Activate it
source .venv/bin/activate

python3 -m pip install --upgrade pip

pip list

# Install the package in editable mode
pip install -e .

# Run the application
pccs-cvr
```
