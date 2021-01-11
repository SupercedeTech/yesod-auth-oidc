{ compiler }:
{ packageOverrides = pkgs: {
    haskell = pkgs.haskell // {
      packages = pkgs.haskell.packages // {
        "${compiler}" = pkgs.haskell.packages."${compiler}".override {
          overrides = hpNew: hpOld: rec {

            # The tests make connections to google which can fail on CI setups
            oidc-client = pkgs.haskell.lib.markUnbroken
              (pkgs.haskell.lib.dontCheck hpOld.oidc-client);

            broch = hpOld.callCabal2nix "broch"
              (builtins.fetchGit {
                url = "https://github.com/tekul/broch";
                rev = "885ace4652cad4dcd806c8c31c1a59bf6a9a3337";
                ref = "master";
              }) {};
          };
        };
      };
    };
  };
}
