.PHONY: help clean clean-pyc clean-build list test fmt test-all coverage docs \
	shell fixtures fixture all-fixtures aws-scan dynamodb requirements

AWS := $(shell which aws)
JQ := $(shell which jq)
TABLES := users nodes dashboards exports names
DJSON = ./bin/djson

DYNAMODB = $(shell which dynamodb-local)
DB_PATH ?= . # run in current directory
DB_PORT = 8091

help:
	@echo "clean-build - remove build artifacts"
	@echo "clean-pyc - remove Python file artifacts"
	@echo "lint - check style with flake8"
	@echo "test - run tests quickly with the default Python"
	@echo "testall - run tests on every Python version with tox"
	@echo "coverage - check code coverage quickly with the default Python"
	@echo "shell - starts an interactive Python REPL"
	@echo "fixture - Export a single record from table to fixtures folder"
	@echo "fixtures - Export all data from table to fixtures folder"
	@echo "all-fixtures - Runs fixtures and fixture on all tables"
	@echo "aws-scan - Dumps data from table to STDOUT"
	@echo "dynamodb - starts a local DynamoDB service"

init:
	pipenv shell
	pipenv install
	pre-commit install

shell:
	ipython

format:
	black .

clean: clean-pyc

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '.pytest_cache' -exec rm -rf {} +

lint:
	flake8 flowers tests
# flake8 --ignore=E501,F401,E128,E402,E731,F821 flowers

fmt:
	black .

test: clean
	py.test -s

requirements:
	@pipenv lock --pre
	@pipenv lock -r > requirements.txt


test-all:
	tox

coverage:
	coverage run --source flowers setup.py test
	coverage report -m
	coverage html
	open htmlcov/index.html

aws-scan:
	@$(AWS) dynamodb scan --table-name flowers-staging-$(table)

fixtures:
	@echo "==> Exporting $(table) to fixtures/$(table).json"
	@$(AWS) dynamodb scan --table-name flowers-staging-$(table) | $(JQ) '.Items' | $(DJSON) | jq > tests/fixtures/$(table).json

fixture:
	$(eval item = $(table:s=))
	@echo "==> Exporting $(item) to fixture/$(item).json"
	@$(AWS) dynamodb scan --table-name flowers-staging-$(table) | $(JQ) '.Items[0]' | $(DJSON) | jq > tests/fixtures/$(item).json

all-fixtures:
	@echo "==> Generating fixtures for tables: $(TABLES)"
	@for table in $(TABLES) ; do \
	echo $$table ; \
	$(MAKE) fixtures table=$$table; \
	$(MAKE) fixture table=$$table; \
	done

dynamodb:
	@echo "==> Starting local DynamoDB"
	$(DYNAMODB) -port $(DB_PORT) -sharedDb -dbPath $(DB_PATH)
