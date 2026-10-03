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
    opensc
  ];

  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";

  # pkcs11-tool loads this when --module is omitted.
  OPENSC_PKCS11 = "${pkgs.opensc}/lib/opensc-pkcs11.so";

  shellHook = ''
    export SMARTCARD_PKCS11="''${CARGO_TARGET_DIR:-$PWD/target}/release/libsmartcard_pkcs11.so"
    echo "Rust: $(rustc --version)"
    echo "Cargo: $(cargo --version)"
    echo "OpenSC module: $OPENSC_PKCS11"
    echo "smartcard-rs module: $SMARTCARD_PKCS11"
  '';
}
