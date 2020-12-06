ENV_DIR = ./env
PIP = $(ENV_DIR)/bin/pip

.PHONY: all tests

all: tests

$(PIP):
	python3 -m venv env

.reqs: $(PIP) requirements.txt
	$(PIP) install -r requirements.txt
	@touch $@

.reqs_dev: $(PIP) requirements_dev.txt
	$(PIP) install -r requirements_dev.txt
	@touch $@

.build: .reqs
	$(dir $(PIP))/python setup.py bdist_wheel  --universal
	touch $@

build: .build

publish: tests .build
	twine upload dist/*

tests: .reqs .reqs_dev
	./env/bin/tox $(TEST_ARGS)

clean:
	rm -rf dist .build .reqs_dev .reqs $(ENV_DIR) .tox
