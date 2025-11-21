# PCCS Container Vulnerabilities Report

Find and report container vulnerabilities based on pod labels.

## Prerequisites

Ensure you have the following tools installed:

- **Python**: >= 3.9
- **pip**: >= 25.3 (Required for editable installs with `pyproject.toml`)
- **setuptools**: >= 61.0 (Build backend)

## Recreating the Project from Scratch

Follow these steps to recreate this project structure and code.

### 1. Create Project Structure

Create the directories:

```bash
mkdir -p pccs.container.vulnerabilities/src/pccs_cvr
cd pccs.container.vulnerabilities
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
