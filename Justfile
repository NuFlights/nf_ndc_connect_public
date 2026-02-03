# List available commands
default:
    @just --list

# Build Python Wheel (Develop)
py-dev:
    maturin develop --features python

# Build Python Wheel (Release)
py-build:
    maturin build --release --features python

# Build Wasm Package (Web)
wasm:
    wasm-pack build --target web -- --features wasm

# Clean artifacts
clean:
    cargo clean
    rm -rf pkg
