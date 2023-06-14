# Changelog for yesod-auth-oidc

## 0.1.4

+ Add release command that excludes the test suite from the hackage release
  The test suite causes serious issues with stackage, since broch isn't on hackage.

## 0.1.3

+ drop executable for the test suite,
  this should prune a bunch of hackage dependencies.
+ bump bounds.
+ Run cabal fmt

## 0.1.2

+ add support for `oidc-client` versions from `0.7` onward
+ add support for `reroute` versions from `0.7` onwards

## 0.1.1

+ add ghc9 support

## 0.1.0

* Just the first release, from nothing
