# List available commands
default:
    @just --list

# ==============================================================================
#  BUILD & TEST
# ==============================================================================

# Build Python Wheel (Develop)
py-dev:
    maturin develop --features python

# Build Python Wheel (Release)
py-build:
    maturin build --release --out dist --features python

# Build Wasm Package (Node/Web)
wasm:
    wasm-pack build --target nodejs --scope dhilipsiva -- --features wasm

# Run standard cargo tests
test:
    cargo test

# Clean artifacts
clean:
    cargo clean
    rm -rf pkg .venv target

# ==============================================================================
#  RELEASE FLOW
# ==============================================================================

# Bump version and git tag (Usage: just release 0.2.0)
release version:
    @echo "📦 Preparing release v{{version}}..."
    
    # 1. Run the python bump script
    python3 scripts/bump.py {{version}}
    
    # 2. Update Cargo.lock to match new Cargo.toml version
    cargo check
    
    # 3. Git commit and tag
    git add Cargo.toml Cargo.lock pyproject.toml
    git commit -m "chore: release v{{version}}"
    git tag v{{version}}
    
    @echo "✅ Release v{{version}} ready!"
    @echo "👉 Run 'git push && git push --tags' to trigger the GitHub Action."
