# yesod-auth-oidc

A Yesod authentication plugin for multi-tenant Single Sign-on (SSO) via [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) (OIDC Core 1.0), using Authorization Code flow (AKA server flow), as defined in OIDC Core OIDC Core §3 and §3.1.

* Supports multiple Identity Providers with callbacks based on the login_hint (typically an email).
* Each provider can be configured either through OIDC Discovery or manually. (The Dynamic Registration OIDC extension is not supported).
* Uses with your Yesod app's session library plus a small middleware. That means there's no need to rely on encrypted JWTs in the browser if you use server-side sessions.
* Works great with [yesod-auth-simple](https://github.com/riskbook/yesod-auth-simple).

# Using the library

This library abstracts many details of OIDC for you, but you may need to understand the basics of OIDC to integrate this with your app. The steps are:

1. Implement the `YesodAuthOIDC` class for your Yesod `App`. See the Haddocks for documentation.

2. Add `Yesod.Auth.OIDC.authOIDC` to your list of authPlugins.

3. Add the `Yesod.Auth.OIDC.oidcSessionExpiryMiddleware` to your WAI middleware. This ensures the user is logged out upon the token's expiry. You should be able to implement something more fancy than a hard logout without modifying this libary.

4. Add some extra UI logic for choosing between login methods if you have more than one auth plugin. Yesod provides some defaults here for getting started.

Also see this library's test suite, especially `test/ExampleApp.hs` and `test/Yesod/Auth/OIDCSpec.hs`.

# Relation to other Haskell libraries

* [Broch](https://github.com/tekul/broch): a Haskell implementation of an OpenID _Provider_. `yesod-auth-oidc` implements an OpenID _Relying Party_ (AKA client).

* [oidc-client](https://hackage.haskell.org/package/oidc-client): `yesod-auth-oidc` uses this utility library. It handles important parts such as token validation, and is not tied to Yesod.

* [yesod-auth](https://hackage.haskell.org/package/yesod-auth), it's `Yesod.Auth.OpenID` module, and the the [authenticate](https://hackage.haskell.org/package/authenticate) library: this appears to be an implementation of [OpenID Authentication 2.0](https://openid.net/specs/openid-authentication-2_0.html), which is the previous "generation" of the OpenID Foundation's efforts. OpenID doesn't seem to be supported by many off-the-shelf SSO Providers (e.g. Azure AD, Auth0), unlike OIDC.

* [yesod-auth-oauth2](https://hackage.haskell.org/package/yesod-auth-oauth2): Offers authentication using the authorisation protocol [OAuth 2.0](https://tools.ietf.org/html/rfc6749). OIDC defines some extras on top of OAuth 2.0 to securely implement authentication.

# Limitations

* Only Authorization Code flow is supported. This is the most widely compatible version of OIDC, which all compliant providers must support.

* Extras such as dynamic registration, single log-out, and automatic session extension via the "prompt" parameter are not implemented.

* The algorithm for determining HTTP cache lifecycle of the discovery document and JWK Set is not yet implemented. For now, you could implement most of this yourself in the appropriate callback however (or send.
