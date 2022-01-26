HYPERFINE := $(shell command -v hyperfine 2> /dev/null)
SOURCE_FILES := $(shell test -e src/ && find src -type f)

policy.wasm: $(SOURCE_FILES) Cargo.*
	cargo build --target=wasm32-unknown-unknown --release
	mv target/wasm32-unknown-unknown/release/*.wasm policy.wasm

annotated-policy.wasm: policy.wasm metadata.yml
	kwctl annotate -m metadata.yml -o annotated-policy.wasm policy.wasm


.PHONY: publish
publish: build registry
	wasm-to-oci push target/wasm32-unknown-unknown/release/pod_toleration_policy.wasm localhost:5000/admission-wasm/pod-toleration-policy:v1

.PHONY: fmt
fmt:
	cargo fmt --all -- --check

.PHONY: lint
lint:
	cargo clippy -- -D warnings


.PHONY: test
test: fmt lint
	cargo test

.PHONY: e2e-tests
e2e-tests: annotated-policy.wasm
	@echo "Dummy target to allow using the reusable github actions to build, test and release policies"

.PHONY: clean
clean:
	cargo clean
	rm -f policy.wasm annotated-policy.wasm
