# Rust dev shell. Uses whatever <nixpkgs> points to on your machine.
# direnv: `direnv allow` once, then cd into this repo.

{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  packages = with pkgs; [
    rustc
    cargo
    rustfmt
    clippy
    pkg-config
    pcsclite
    pcsc-tools
  ];

  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";

  shellHook = ''
    echo "Rust: $(rustc --version)"
    echo "Cargo: $(cargo --version)"
  '';
}
