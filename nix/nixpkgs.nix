let
  # release-22.11, committed on Nov 30 2022
  rev = "4d2b37a84fad1091b9de401eb450aae66f1a741e";
  url = "https://github.com/NixOS/nixpkgs/archive/${rev}.tar.gz";
in
  import (builtins.fetchTarball url)
