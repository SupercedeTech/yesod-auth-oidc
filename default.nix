{pkgs ? import ./nix/nixpkgs.nix { config= import ./nix/pkgconfig.nix; }
}:

let
  ignore = import ./nix/gitignoreSource.nix { inherit (pkgs) lib; };
in
pkgs.haskellPackages.callCabal2nix "yesod-auth-oidc" (ignore.gitignoreSource ./.) {}
