{ pkgs ? import <nixpkgs> {} }:

  pkgs.mkShell {
    nativeBuildInputs = [ pkgs.clang ];
    buildInputs = with pkgs; [
      glibc
      rustup
      openssl
      pkgconfig
      llvmPackages.libclang
      ncurses
      glibcLocales
      tor
    ];
    shellHook = ''
      export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib";
    '';
  }