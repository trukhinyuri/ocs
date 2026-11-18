.PHONY: demo check report package

OCS_BASELINE ?= 6f6e22842347806f2963ef1984d9ea592fdddaf0

demo:
	go run ./reference/go --manifest examples/status/ocs.json --resource demo

check:
	uv run --locked python -m unittest discover -s conformance -p 'test_*.py' -v
	go test ./...
	uv run --locked python conformance/run.py --report out/conformance.json
	uv run --locked python conformance/compatibility.py "$(OCS_BASELINE)"

report:
	uv run --locked python conformance/run.py --report out/conformance.json

package:
	uv run --locked python tools/package.py examples/status out/status.ocsx
