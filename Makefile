DAPP_PUBLIC ?= ../public
WASM_PACK ?= $(HOME)/.cargo/bin/wasm-pack

.PHONY: all clean copy-dapp

all: ./wasm_pkg_mt ./wasm_pkg_st ./mint.params.b64

./wasm_pkg_mt:
	RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals' rustup run nightly $(WASM_PACK) build --target web --out-dir wasm_pkg_mt . -- -Z build-std=panic_abort,std --features multicore

./wasm_pkg_st:
	$(WASM_PACK) build --target web --out-dir wasm_pkg_st . -- --no-default-features

./mint.params.b64: mint.params
	base64 -w0 mint.params > mint.params.b64

# Copy wasm artifacts into the Cloak dApp public/ tree (includes wasm_pkg_mt/snippets/).
copy-dapp: ./wasm_pkg_mt ./wasm_pkg_st
	rsync -a --delete --exclude='.gitignore' wasm_pkg_st/ $(DAPP_PUBLIC)/wasm_pkg_st/
	rsync -a --delete --exclude='.gitignore' wasm_pkg_mt/ $(DAPP_PUBLIC)/wasm_pkg_mt/
	@if [ -f mint.params.b64 ]; then cp -f mint.params.b64 $(DAPP_PUBLIC)/mint.params.b64; fi

clean:
	rm -rf ./wasm_pkg_mt ./wasm_pkg_st ./mint.params.b64
