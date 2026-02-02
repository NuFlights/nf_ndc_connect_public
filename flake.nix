{
  description = "Casdoor Claims: Rust, Python (Maturin), and Wasm (Wasm-Pack) Workspace";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Define Rust Toolchain with WASM target support
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" ];
          targets = [ "wasm32-unknown-unknown" ];
        };
      in
      {
        # ======================================================================
        #  DEV SHELL
        #  Usage: `nix develop`
        # ======================================================================
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # 1. Rust Core
            rustToolchain
            pkg-config
            openssl
            just

            # 2. Python / Maturin Utils
            maturin
            python3
            python3Packages.virtualenv
            python3Packages.pip
            rye

            # 3. Wasm / Node Utils
            wasm-pack
            nodejs_24
            binaryen 
          ];

          shellHook = ''
            export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1
            echo "🚀 Casdoor Claims Hybrid Environment Loaded"
            echo "-------------------------------------------"
            echo "Rust:   $(rustc --version)"
            echo "Python: $(python3 --version) | Maturin: $(maturin --version)"
            echo "Node:   $(node --version)    | Wasm-Pack: $(wasm-pack --version)"
            echo "-------------------------------------------"
          '';
        };

        # ======================================================================
        #  PACKAGE: Pure Rust Crate
        # ======================================================================
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "casdoor-claims";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          
          buildFeatures = []; 
          
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.openssl ];
        };
      }
    );
}
