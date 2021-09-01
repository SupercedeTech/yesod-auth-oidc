{ compiler ? "ghc884"
, config ? import ./nix/pkgconfig.nix { inherit compiler; }
, pkgs ? import ./nix/nixpkgs.nix { inherit config; }
}:

let
  ignore = import ./nix/gitignoreSource.nix { inherit (pkgs) lib; };
  yesod-auth-oidc = pkgs.haskell.packages."${compiler}".callCabal2nix "yesod-auth-oidc" (ignore.gitignoreSource ./.) {};
in
pkgs.haskell.lib.overrideCabal yesod-auth-oidc (drv: {
  src = ignore.gitignoreSource ./.;
  configureFlags = ["-f-library-only"];
  buildTools = [ pkgs.cabal-install ];
  testToolDepends = [ pkgs.haskell.packages."${compiler}".hspec-discover ];
  doCheck = true;
  doHaddock = true;
  enableLibraryProfiling = false;
  enableSeparateDataOutput = false;
  enableSharedExecutables = false;
  isLibrary = true;
  isExecutable = false;
  enableSeparateDocOutput = true;
})
