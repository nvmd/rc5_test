{ pkgs ? import <nixpkgs> {} }:

# https://nixos.wiki/wiki/Rust

pkgs.mkShell {
  buildInputs = with pkgs; [ libiconv ];
  nativeBuildInputs = with pkgs; [ rustc
                                   cargo
                                   rustfmt
                                   clippy
                                 ];

  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
}
