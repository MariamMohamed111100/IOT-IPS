.PHONY: install test demo samples calibrate lint clean

install:            ## install the package and the test tools
	pip install -e ".[dev]"

test:               ## run every unit test
	python -m pytest

demo:               ## run the whole demo
	python run_demo.py

samples:            ## rebuild examples/sample_reports from the pipeline output
	python scripts/make_samples.py

calibrate:          ## false alarms on generated normal traffic (docs/calibration-report.md)
	python scripts/calibrate.py

clean:              ## remove generated files
	rm -rf output .pytest_cache build *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
