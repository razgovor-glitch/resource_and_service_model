PY ?= $(shell [ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)

.PHONY: help venv demo demo-open test run report open policy netbox-plan clean-demo

help:
	@echo "make venv        — виртуальное окружение + зависимости"
	@echo "make demo        — демо-парк ~290 серверов, 3 дня discovery, отчёт в demo-data/reports"
	@echo "make demo-open   — открыть отчёт демо"
	@echo "make test        — юнит-тесты"
	@echo "make run         — прогон на реальных данных из data/raw"
	@echo "make open        — открыть отчёт data/reports/index.html"
	@echo "make policy      — проверка примеров policy-as-code"
	@echo "make netbox-plan — dry-run синхронизации с NetBox"

venv:
	python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt

demo:
	$(PY) -m rsm --data-dir demo-data demo

demo-open:
	open demo-data/reports/index.html 2>/dev/null || xdg-open demo-data/reports/index.html

test:
	$(PY) -m unittest discover -s tests -v

run:
	$(PY) -m rsm run

report:
	$(PY) -m rsm report

open:
	open data/reports/index.html 2>/dev/null || xdg-open data/reports/index.html

policy:
	-$(PY) -m rsm policy check examples/policy

netbox-plan:
	$(PY) -m rsm netbox sync

clean-demo:
	rm -rf demo-data
