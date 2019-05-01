
PIP = ./env/bin/pip

all: .reqs
.PHONY = all

$(PIP):
	python3 -m venv env

.reqs: $(PIP) requirements.txt
	$(PIP) install -r requirements.txt
	@touch $@

.build:
	$(dir $(PIP))/python setup.py bdist_wheel  --universal
	touch $@

build: .build

publish: .build
	twine upload dist/*

clean:
	rm -rf dist/ .build
