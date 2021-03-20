HYPERFINE := $(shell command -v hyperfine 2> /dev/null)

.PHONY: build
build:
	cargo build --target=wasm32-unknown-unknown --release

.PHONY: registry
registry:
	@sh -c 'docker inspect registry &> /dev/null || docker run -d -p 5000:5000 --name registry registry:2'

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

.PHONY: clean
clean:
	cargo clean
