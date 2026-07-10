PYTHON ?= python3

.PHONY: check demo format lint playbooks test

check:
	$(PYTHON) scripts/check.py

demo:
	$(PYTHON) -m penpal --workspace penpal-workspace init 10.10.10.5 --name demo --force
	$(PYTHON) -m penpal --workspace penpal-workspace parse-nmap demo examples/pi/demo-nmap.xml
	$(PYTHON) -m penpal --workspace penpal-workspace suggest demo

format:
	$(PYTHON) -m ruff format --check .

lint:
	$(PYTHON) -m ruff check .

playbooks:
	$(PYTHON) -m penpal playbooks playbooks

test:
	$(PYTHON) -m unittest discover -v
