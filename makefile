
release:
		git diff-index --quiet HEAD -- || (echo "branch dirty, commit first" && false)
		sed -i '/common test-properties/,$$d' ./yesod-auth-oidc.cabal
		cabal sdist
		git reset --hard
