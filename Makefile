.PHONY: demo check check-reference check-safe-push check-safe-push-history check-safe-push-hosted-history check-safe-push-operating-catalog qualify stand report package

OCS_BASELINE ?= 6f6e22842347806f2963ef1984d9ea592fdddaf0
export OCS_BASELINE
OCS_ASSURANCE_BASELINE ?= e09a5d7d0ae15d35910e72243c4a466974f09401
export OCS_ASSURANCE_BASELINE
export OCS_KUBECONFIG OCS_CONTEXT OCS_NAMESPACE OCS_IMAGE OCS_STORAGE OCS_OCI_PROOF

demo:
	go run ./reference/go --manifest examples/status/ocs.json --resource demo

check-reference:
	uv run --locked python conformance/fixture_suite.py
	uv run --locked python conformance/run.py --report out/conformance.json
	uv run --locked python conformance/compatibility.py "$$OCS_BASELINE"

check-safe-push:
	uv run --locked python safe_push/check.py --report out/safe-push/check.json

check-safe-push-history:
	uv run --locked python safe_push/check.py --history-only --report out/safe-push/history.json

check-safe-push-hosted-history:
	uv run --locked python safe_push/check.py --hosted-refusal-only --report out/safe-push/hosted-history.json

check-safe-push-operating-catalog:
	uv run --locked python safe_push/check.py --operating-catalog-only --report out/safe-push/operating-catalog.json

ifneq ($(strip $(OCS_HOSTED_REFUSAL_HISTORY)),)
qualify: check-safe-push-hosted-history
endif

check: check-safe-push
	uv run --locked python assurance/launch.py local --subject . --accepted "$$OCS_ASSURANCE_BASELINE"

qualify: check-safe-push check-safe-push-history
	uv run --locked python assurance/launch.py full --subject . --accepted "$$OCS_ASSURANCE_BASELINE"

stand:
	uv run --locked python stand/kubernetes/deploy.py --local

report:
	uv run --locked python conformance/run.py --report out/conformance.json

package:
	uv run --locked python tools/package.py examples/status out/status.ocsx
