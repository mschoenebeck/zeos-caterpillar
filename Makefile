all: ./wasm_pkg_mt ./wasm_pkg_st ./mint.params.b64

./wasm_pkg_mt:
	RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals' rustup run nightly wasm-pack build --target web --out-dir wasm_pkg_mt . -- -Z build-std=panic_abort,std --features multicore

./wasm_pkg_st:
	wasm-pack build --target web --out-dir wasm_pkg_st . -- --no-default-features

./mint.params.b64: mint.params
	base64 -w0 mint.params > mint.params.b64

clean:
	rm -rf ./wasm_pkg_mt ./wasm_pkg_st ./mint.params.b64
