{ packageOverrides = pkgs: {
    haskellPackages = pkgs.haskellPackages.extend(hpNew: hpOld: {
            # The tests make connections to google which can fail on CI setups
            oidc-client = pkgs.haskell.lib.markUnbroken
              (pkgs.haskell.lib.dontCheck hpOld.oidc-client);

            jose-jwt = pkgs.haskell.lib.markUnbroken hpOld.jose-jwt;

            yesod-auth-oidc = hpNew.callPackage ../. {};

            broch = hpOld.callCabal2nix "broch"
              (builtins.fetchGit {
                url = "https://github.com/SupercedeTech/broch";
                rev = "548be56666a490cc15b8442d96a38952f2e9a0ca";
                ref = "make-it-build-with-latest-nixpkgs";
              }) {};

        });
  };
}
