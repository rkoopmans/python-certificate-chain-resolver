
PIP = ./env/bin/pip

all: .reqs
.PHONY = all

$(PIP):
	python3 -m venv env

.reqs: $(PIP) requirements.txt
	$(PIP) install -r requirements.txt
	@touch $@
