DAPP_PUBLIC ?= ../public
WASM_PACK ?= $(HOME)/.cargo/bin/wasm-pack
# Required for shared WebAssembly.Memory (wasm-bindgen-rayon / recent nightlies).
MT_RUSTFLAGS := -C target-feature=+atomics,+bulk-memory,+mutable-globals \
	-Clink-arg=--shared-memory -Clink-arg=--max-memory=1073741824 -Clink-arg=--import-memory \
	-Clink-arg=--export=__wasm_init_tls -Clink-arg=--export=__tls_size \
	-Clink-arg=--export=__tls_align -Clink-arg=--export=__tls_base \
	-Clink-arg=--export=__heap_base

.PHONY: all clean copy-dapp verify-mt-glue

all: ./wasm_pkg_mt ./wasm_pkg_st ./mint.params.b64

verify-mt-glue:
	@grep -q 'shared:true' wasm_pkg_mt/zeos_caterpillar.js || (echo "wasm_pkg_mt/zeos_caterpillar.js missing shared WebAssembly.Memory glue (shared:true)" && exit 1)

./wasm_pkg_mt:
	RUSTFLAGS='$(MT_RUSTFLAGS)' rustup run nightly $(WASM_PACK) build --target web --out-dir wasm_pkg_mt . -- -Z build-std=panic_abort,std --features multicore
	@$(MAKE) verify-mt-glue

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
