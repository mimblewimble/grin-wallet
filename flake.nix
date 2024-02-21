{
  description = "Reference Grin Wallet.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-23.11";
  };

  outputs = { self, nixpkgs, }:
    let
      forAllSystems = with nixpkgs;
        lib.genAttrs lib.systems.flakeExposed;

      nixpkgsFor = forAllSystems (system: import nixpkgs
        { inherit system; overlays = [ self.overlay ]; }
      );
    in
    {
      overlay = final: prev:
        with final;
        {
          grin-wallet = pkgs.rustPlatform.buildRustPackage {
            pname = "grin-wallet";
            version = "5.2.0";
            src = ./.;

            cargoLock = {
              lockFile = ./Cargo.lock;
              outputHashes = {
                "grin_api-5.3.0-alpha.1" = "sha256-qxMmWCJBtiYsqBJgDA6km7XsToLR2fv/PUUZyM1uAF4=";
              };
            };

            nativeBuildInputs = with pkgs; [ pkg-config clang ];
            buildInputs = [ pkgs.openssl ];
            LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";

            # do not let test results block the build process
            doCheck = false;
          };
        };

      packages = forAllSystems (
        system: {
          default = nixpkgsFor.${system}.grin-wallet;
        }
      );
    };
}
