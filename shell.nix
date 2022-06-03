{pkgs ? import ./nix/nixpkgs.nix { config= import ./nix/pkgconfig.nix; }}:
pkgs.haskellPackages.shellFor {
  packages = ps: [ps.yesod-auth-oidc ];
  buildInputs = [ pkgs.cabal-install ];
}
