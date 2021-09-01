let
  # first 21.05 release
  rev = "07ca3a021f05d6ff46bbd03c418b418abb781279";
  url = "https://github.com/NixOS/nixpkgs/archive/${rev}.tar.gz";
in
  import (builtins.fetchTarball url)
