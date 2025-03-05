.PHONY: all test bench clean lint

PYTHON ?= python3

all: test

test:
	$(PYTHON) -m unittest discover -s tests -p "test_*.py" -v

bench:
	$(PYTHON) -m benchmarks.run_all_benchmarks

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete

lint:
	$(PYTHON) -m py_compile crypto_toolkit/**/*.py tests/*.py benchmarks/*.py
