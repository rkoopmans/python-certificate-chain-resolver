ENV_DIR = ./env
PIP := $(ENV_DIR)/bin/pip

.PHONY: all tests coverage clean pyclean

all: tests

$(PIP):
	python3 -m venv env

.reqs: $(PIP) requirements.txt
	$(PIP) install -r requirements.txt
	@touch $@

.reqs_dev: $(PIP) requirements_dev.txt
	$(PIP) install -r requirements_dev.txt
	@touch $@

tests: .reqs .reqs_dev
	./env/bin/tox $(TEST_ARGS)

coverage:
	./env/bin/py.test --cov-report html --cov=cert_chain_resolver --cov-fail-under=90

pyclean:
	find . -type f -name '*.py[co]' -delete -o -type d -name __pycache__ -delete

clean: pyclean
	rm -rf .reqs_dev .reqs $(ENV_DIR) .tox
