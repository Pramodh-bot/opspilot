.PHONY: setup test lint eval frontend-test build up down seed-demo

setup:
	python3 -m venv .venv && . .venv/bin/activate && pip install -r backend/requirements-dev.txt
	cd frontend && npm ci

test:
	cd backend && ../.venv/bin/python -m pytest --cov=app

lint:
	cd backend && ../.venv/bin/ruff check . && ../.venv/bin/ruff format --check .

eval:
	cd backend && DATABASE_URL=sqlite:// ../.venv/bin/python -m app.agent.eval --dataset eval/dataset.json
	cd backend && DATABASE_URL=sqlite:// ../.venv/bin/python -m app.agent.eval --dataset eval/holdout.json

frontend-test:
	cd frontend && npm run typecheck && npm test

build:
	cd frontend && npm run build

up:
	test -f .env || (echo "Copy .env.example to .env and set secrets first" && exit 1)
	docker compose up --build -d

down:
	docker compose down

seed-demo:
	docker compose run --rm --no-deps backend python -m app.seed --demo
