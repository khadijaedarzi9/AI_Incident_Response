.PHONY: install test scenarios benchmark auditability demo audit package docker-smoke all clean

install:
	python -m pip install -e ".[test]"

test:
	python -m pytest --cov=app --cov=auditor --cov=benchmarks --cov-branch

scenarios:
	python -m demo.scenarios.run --output artifacts/scenarios/results.json

benchmark:
	python -m benchmarks.ablation --output artifacts/benchmark

auditability:
	python -m benchmarks.auditability \
		--output artifacts/benchmark/auditability.json

demo:
	python -m demo.run --output artifacts/demo

audit:
	python -m auditor.verify \
		--manifest artifacts/demo/manifest.json \
		--evidence artifacts/demo/evidence.jsonl \
		--receipt artifacts/demo/receipt.json \
		--operator-key artifacts/demo/operator-key.json

package:
	python scripts/build_submission.py

docker-smoke:
	docker compose -f compose.boundary-smoke.yaml up --build \
		--abort-on-container-exit --exit-code-from agent-probe
	docker compose -f compose.boundary-smoke.yaml down --volumes --remove-orphans

all: scenarios benchmark auditability demo audit test package

clean:
	python -c "import shutil; [shutil.rmtree(p, ignore_errors=True) for p in ('.pytest_cache', 'htmlcov', 'build', 'dist')]"

