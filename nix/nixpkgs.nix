let
  # https://releases.nixos.org/nixos/20.09/nixos-20.09.1500.edb26126d98
  rev = "edb26126d98bc696f4f3e206583faa65d3d6e818";
  url = "https://github.com/NixOS/nixpkgs/archive/${rev}.tar.gz";
in
  import (builtins.fetchTarball url)
