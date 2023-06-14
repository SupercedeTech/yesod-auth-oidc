
# hackage (or stackage) somehow still sees the test suite dependencies as mandatory,
# (even though it's not listed!)
# which normally isn't a problem, however this particular package has broch as a dependency in the test suite,
# which the author didn't even care for publishing (cuz who doesn't love some SSO work right?)
# and I don't want to maintain it either.
# so this command filters the test suite out of cabal
release:
		git diff-index --quiet HEAD -- || (echo "branch dirty, commit first" && false)
		sed -i '/common test-properties/,$$d' ./yesod-auth-oidc.cabal
		cabal sdist
		git reset --hard
