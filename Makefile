.PHONY: build test lint run

# Build Docker images
build-backend:
	docker build -t pccs-cvr-backend:latest ./backend

build-frontend:
	docker build -t pccs-cvr-frontend:latest ./frontend

build-all: build-backend build-frontend

# Run unit tests
test-backend:
	cd backend && . .venv/bin/activate && pytest tests

# Code linting
lint-backend:
	cd backend && . .venv/bin/activate && flake8 src tests

lint-frontend:
	cd frontend && npm run lint

# Run locally
run-backend:
	cd backend && . .venv/bin/activate && uvicorn src.pccs_cvr.app:app --reload --port 8000

run-frontend:
	cd frontend && npm run dev

run-all:
	(make run-backend & make run-frontend)
