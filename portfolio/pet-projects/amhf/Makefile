# AMHF Makefile — Linux/macOS/WSL targets.
# For native Windows (PowerShell) see tasks.ps1.

PYTHON ?= python
VENV   ?= .venv
PIP    := $(VENV)/bin/pip
PY     := $(VENV)/bin/python

.PHONY: help install lint typecheck test cov demo \
        stand-up stand-down stand-reset baseline full clean

help:
	@echo "Common targets:"
	@echo "  install     create venv and install -e .[dev]"
	@echo "  lint        ruff check"
	@echo "  typecheck   mypy --strict amhf/"
	@echo "  test        pytest with coverage gate"
	@echo "  demo        amhf demo"
	@echo "  baseline    run scenarios/s1_baseline.yaml"
	@echo "  full        run scenarios/s4_adaptive.yaml"
	@echo "  stand-up    docker compose up -d in stand/"
	@echo "  stand-down  docker compose down in stand/"

install:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"

lint:
	$(PY) -m ruff check amhf tests

typecheck:
	$(PY) -m mypy --strict amhf

test:
	$(PY) -m pytest --cov=amhf --cov-fail-under=70

cov:
	$(PY) -m pytest --cov=amhf --cov-report=html

demo:
	$(PY) -m amhf demo

stand-up:
	docker compose -f stand/docker-compose.yml up -d --build

stand-down:
	docker compose -f stand/docker-compose.yml down

stand-reset:
	docker compose -f stand/docker-compose.yml down -v
	docker compose -f stand/docker-compose.yml up -d --build

baseline:
	$(PY) -m amhf run -c configs/scenarios/s1_baseline_modsec_p1_flag.yaml

full:
	$(PY) -m amhf run -c configs/scenarios/s4_adaptive_modsec_p1_flag.yaml

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache
