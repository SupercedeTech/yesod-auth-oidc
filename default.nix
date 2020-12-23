{ settings ? import ../../nix/settings.nix
}:

let
  pkgs = settings.pkgs;
  compiler = settings.compiler;
  ignore = import ../../nix/gitignoreSource.nix { inherit (pkgs) lib; };
  yesod-auth-oidc = settings.hpkgs.callCabal2nix "yesod-auth-oidc" (ignore.gitignoreSource ./.) {};
in
pkgs.haskell.lib.overrideCabal yesod-auth-oidc (drv: {
  src = ignore.gitignoreSource ./.;
  configureFlags = ["-f-library-only"];
  doCheck = false;
  doHaddock = false; # By default you don't want to wait on this
  testHaskellDepends = [];
  testToolDepends = [];
  enableLibraryProfiling = settings.enableProfiling;
  enableSeparateDataOutput = false;
  enableSharedExecutables = false;
  isLibrary = true;
  isExecutable = false;
  enableSeparateDocOutput = true;
})
