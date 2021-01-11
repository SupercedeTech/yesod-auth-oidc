# yesod-auth-oidc

A yesod-auth plugin for multi-tenant SSO via OpenID Connect, using
Authorization Code flow (AKA server flow).

* Supports multiple Identity Providers with callbacks based on the login_hint (typically an email)
* Each provider can be configured either through OIDC Discovery (with caching callbacks) or manually. Just implement the functions to retrieve either config from your database.
* Works with your session library, so no need to store JWTs in the browser if you use server-side sessions

More documentation is in the haddocks.
