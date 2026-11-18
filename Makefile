.PHONY: demo check report package

demo:
	go run ./reference/go --manifest examples/status/ocs.json --resource demo

check:
	uv run --locked python -m unittest discover -s conformance -p 'test_*.py' -v
	go test ./...
	uv run --locked python conformance/run.py --report out/conformance.json

report:
	uv run --locked python conformance/run.py --report out/conformance.json

package:
	uv run --locked python tools/package.py examples/status out/status.ocsx
