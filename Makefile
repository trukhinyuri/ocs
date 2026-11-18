.PHONY: demo check check-reference qualify stand report package

OCS_BASELINE ?= 6f6e22842347806f2963ef1984d9ea592fdddaf0
export OCS_BASELINE
OCS_ASSURANCE_BASELINE ?= 3dabb569d49ca28eb7cd22cf04e2f6f41c9ae391
export OCS_ASSURANCE_BASELINE
export OCS_KUBECONFIG OCS_CONTEXT OCS_NAMESPACE OCS_IMAGE OCS_STORAGE OCS_OCI_PROOF

demo:
	go run ./reference/go --manifest examples/status/ocs.json --resource demo

check-reference:
	uv run --locked python conformance/fixture_suite.py
	uv run --locked python conformance/run.py --report out/conformance.json
	uv run --locked python conformance/compatibility.py "$$OCS_BASELINE"

check:
	uv run --locked python assurance/launch.py local --subject . --accepted "$$OCS_ASSURANCE_BASELINE"

qualify:
	uv run --locked python assurance/launch.py full --subject . --accepted "$$OCS_ASSURANCE_BASELINE"

stand:
	uv run --locked python stand/kubernetes/deploy.py --local

report:
	uv run --locked python conformance/run.py --report out/conformance.json

package:
	uv run --locked python tools/package.py examples/status out/status.ocsx
