{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
-- | A yesod-auth plugin for per-tenant SSO via OpenID Connect, using
-- Authorization Code flow (AKA server flow) with client_secret_post
-- client authentication.
--
-- Reserves "ya-oidc-*" as session keys.
--
-- Referenced standards:
-- * OIDC Core: https://openid.net/specs/openid-connect-core-1_0.html
-- * RFC 6749, OAuth 2.0: https://tools.ietf.org/html/rfc6749
-- * RFC 6750, OAuth 2.0 Bearer Token Usage: https://tools.ietf.org/html/rfc6750
module Yesod.Auth.OIDC
  ( oidcPluginName
  , authOIDC
  , ClientId(..)
  , ClientSecret(..)
  , UserInfo
  , UserInfoPreference(..)
  , YesodAuthOIDC(..)
  , OAuthErrorResponse(..)
  , oidcSessionExpiryMiddleware

  -- * Routes
  , oidcLoginR
  , oidcForwardR
  , oidcCallbackR

  -- * Re-exported from oidc-client
  , Configuration(..)
  , Provider(..)
  , IssuerLocation
  , Tokens(..)
  , IdTokenClaims(..)
  ) where

import ClassyPrelude.Yesod
import qualified "cryptonite" Crypto.Random as Crypto
import qualified Data.Aeson as J
import qualified Data.ByteString.Base64.URL as Base64Url
import qualified Data.HashMap.Strict as HM
import qualified Data.HashSet as HashSet
import qualified Data.Text as T
import Data.Time.Clock
import Data.Time.Clock.POSIX
import qualified Network.HTTP.Client as HTTP
import Web.OIDC.Client as Client
import Web.OIDC.Client.Settings
import qualified Web.OIDC.Client.Types as Scopes
import Yesod.Auth

data YesodAuthOIDCException
  = InvalidQueryParamsException Text
  | BadLoginHint
  | NoProviderConfigException
  | InvalidSecurityTokenException
  | TLSNotUsedException Text
  | UnknownTokenType Text
  deriving Show

instance Exception YesodAuthOIDCException

-- | Add this value to your YesodAuth instance's 'authPlugins' list
authOIDC :: (HasHttpManager site, YesodAuthOIDC site) => AuthPlugin site
authOIDC = AuthPlugin oidcPluginName dispatch loginW

-- | The login hint is sent as the `login_hint` query parameter to the
-- service provider's authentication URL. It is commonly an email
-- address and hence why oidcForwardR takes an "email" post
-- parameter. It can be used not only for this purpose but also as a
-- hint to your own app about which tenant configuration to use (based
-- on the email domain perhaps).
type LoginHint = Text

-- | Response of call to the UserInfo Endpoint. This library does not
-- currently support signed or encrypted responses to this particular
-- request (unlike the ID Token response which must be signed). C.f.
-- OIDC Core 5.3.2
type UserInfo = J.Object

-- | Write an instance of this class for your Yesod App
class (YesodAuth site) => YesodAuthOIDC site where
  -- | (Optional). If this is False, there will be no '/auth/page/oidc/login' with
  -- its default form asking for an email. This can be used if you
  -- consolidate your various yesod auth plugins into one login page
  -- outside of this plugin. In that case, you would initialise OIDC
  -- login by POSTing to 'oidcForwardR' with "email" and Yesod's
  -- 'defaultCsrfParamName' from your own page. Defaut is True.
  enableLoginPage :: Bool
  enableLoginPage = True

  -- | (Optional) A callback to your app in case oidcForwardR is
  -- called without the login_hint query parameter. Default
  -- implementation throws a 'BadLoginHint' exception.
  onBadLoginHint :: AuthHandler site TypedContent
  onBadLoginHint = throwIO BadLoginHint

  -- | Looks up configuration. If none can be found, you should handle
  -- the fallback / error call yourself. Returns the ClientID for the
  -- given identity provider, and either the provider configuration
  -- itself, or otherwise just the Issuer URI. If the latter, this
  -- library will use OIDC discovery to retrieve the configuration.
  --
  -- The Issuer URI should only consist of the scheme (which must be
  -- "https:") and fully qualified host name (e.g. example.com), with
  -- no path etc.
  --
  -- The full configuration could be hard-coded or the cached result
  -- of a previous discovery. Cf 'onProviderConfigDiscovered'.
  --
  -- Note that the 'Provider' is both the configuration and the result of
  -- retrieving the keyset from jwks_uri.
  getProviderConfig ::
    LoginHint -> AuthHandler site (Either Provider IssuerLocation, ClientId)

  -- | (Optional). If the tenant is configured via a discovery URL,
  -- this function will be called with the discovered result and that
  -- result's retrieved keyset. This can be used to cache the
  -- configuration for the given duration. Since the oidc-client
  -- library combines discovery with key retrieval, the given time is
  -- the minimum of the two remaining cache lifetimes returned by both
  -- http requests.
  onProviderConfigDiscovered ::
    Provider -> ClientId -> DiffTime -> AuthHandler site ()
  onProviderConfigDiscovered _ _ _ = pure ()

  -- | (Optional). Do something if the 'oidcCallbackR' was called with
  -- incorrect parameters or the Identity Provider returned an
  -- error. This could happen if the request is not legitimate or if
  -- the identity provider doesn't provide the required `state` or
  -- `code` query or post parameters.
  --
  -- Defaults to a simple page showing the error (sans the error_uri).
  onBadCallbackRequest ::
    Maybe OAuthErrorResponse
    -- ^ The OAuth Error Response if present (See RFC6749 §5.2 and
    -- OIDC §3.1.2.6). This will only be 'Just' if the "state" param
    -- (anti-CSRF token) is valid.
    -> AuthHandler site a
  onBadCallbackRequest mError = do
    errHtml <- authLayout $ toWidget widg
    sendResponseStatus status400 errHtml
    where
      widg =
        [whamlet|
          <h1>Error
          <p>There has been some miscommunication between your Identity Provider and our application.
          <p>Please try logging in again and contact support if the problem persists.
          $maybe OAuthErrorResponse err mErrDesc _ <- mError
            <p><i>Error code:</i> #{err}
            $maybe errDesc <- mErrDesc
              <p><i>Error description: </i>#{errDesc}
            $maybe errUri <- mErrDesc
              <p><i>More information: </i>#{errUri}
        |]

  -- | The printable-ASCII client_secret which you've set up with the
  -- provider ahead of time (this library does not support the dynamic
  -- registration spec).
  getClientSecret :: ClientId -> Configuration -> AuthHandler site ClientSecret

  -- | (Optional). The scopes that you are requesting. The "openid"
  -- scope will always be included in the eventual request whether or
  -- not you specify it here. Defaults to ["email"].
  getScopes :: ClientId -> Configuration -> AuthHandler site [ScopeValue]
  getScopes _ _ = pure [email]

  -- | (Optional). Configure the behaviour of when to request user
  -- information. The default behaviour is to only make this request
  -- if it's necessary satisfy the scopes in 'getScopes'.
  getUserInfoPreference ::
    LoginHint -> ClientId -> Configuration -> AuthHandler site UserInfoPreference
  getUserInfoPreference _ _ _ = pure GetUserInfoOnlyToSatisfyRequestedScopes

  -- | (Required). Should return a unique identifier for this user to
  -- use as the key in the yesod app's session backend. Sent after the
  -- user has successfully authenticated and right before telling
  -- Yesod that the user is authenticated. This function can still
  -- cancel authentication if it throws an error or short-circuits.
  --
  -- If you are using the underlying OAuth spec for non-OIDC reasons,
  -- you can do extra work here, such as storing the access and
  -- refresh tokens.
  onSuccessfulAuthentication ::
    LoginHint
    -- ^ *Warning*: This is original login hint (typically an email),
    -- does *not* assert anything about the user's identity. The user
    -- could have logged in with an email different to this one, or
    -- their email at the Identity Provider could just be different to
    -- this hint. Use the information in the ID Token and UserInfo
    -- Response for authentic identity information.
    -> ClientId
    -> Provider
    -> Tokens J.Object
    -- ^ The OIDC 'Token Response', including a fully validated ID
    -- Token. The 'otherClaims' value is purposefully an unparsed JSON
    -- object to provide maximum flexibility.
    -> Maybe UserInfo
    -- ^ The response of the userinfo endpoint is given depending on
    -- the 'getUserInfoPreference' and whether the request was
    -- actually successful. For flexibility, any exceptions in the
    -- course of getting the UserInfo are caught by this library;
    -- such errors only manifest as an unexpected 'Nothing' here.
    -> AuthHandler site Text

  -- | Defaults to clearing the credentials from the session and
  -- redirecting to the site's logoutDest (if not currently there
  -- already or out loginDest)
  onSessionExpiry :: HandlerFor site ()
  onSessionExpiry = clearCreds True

data UserInfoPreference
  = GetUserInfoIfAvailable
    -- ^ Always requests the userinfo, as long as the 'Provider'
    -- configuration has a userinfo endpoint.
  | GetUserInfoOnlyToSatisfyRequestedScopes
    -- ^ (Default). Only requests the user info if a) it's available
    -- and b) the token endpoint did not return all the scoped claims
    -- requested (cf 'getScopes'). For example, many Identity
    -- Providers will return "email" in the token response, and thus
    -- there is no need to request the user info if that's all your
    -- app wants.
  | NeverGetUserInfo
  deriving (Show, Eq)

-- | The name used to render this plugin's routes, "oidc".
oidcPluginName :: Text
oidcPluginName = "oidc"

-- | Optional route that reads in the "login hint" (commonly an email
-- address). Your app can use this for its main login screen, or it
-- could have a separate login screen not managed by this plugin but
-- which redirects to 'oidcForwardR' with the login_hint when
-- appropriate.
--
-- /auth/page/oidc/login
oidcLoginR :: AuthRoute
oidcLoginR = PluginR oidcPluginName ["login"]

-- | This accepts an `email` post param. Looks up or discovers
-- the OIDC provider associated with this login_hint, and redirects
-- the user to the provider's Authorization Endpoint.
--
-- /auth/page/oidc/forward
oidcForwardR :: AuthRoute
oidcForwardR = PluginR oidcPluginName ["forward"]

-- | This route is given to the provider so that the provider can
-- redirect the user here with the appropriate Authorisation Code, at
-- which point the library continues the authentication process.
--
-- /auth/page/oidc/callback
oidcCallbackR :: AuthRoute
oidcCallbackR = PluginR oidcPluginName ["callback"]

dispatch :: forall site. (HasHttpManager site, YesodAuthOIDC site)
         => Text -> [Text] -> AuthHandler site TypedContent
dispatch httpMethod uriPath = case (httpMethod, uriPath) of
  ("GET", ["login"]) -> if enableLoginPage @site then getLoginR else notFound
  ("POST", ["forward"]) -> postForwardR

  -- These two handlers are ultimately the same handler. Identity
  -- Providers may use GET or POST for the callback.
  ("GET", ["callback"]) -> handleCallback GET
  ("POST", ["callback"]) -> handleCallback POST
  _ -> notFound

loginW :: (Route Auth -> Route site) -> WidgetFor site ()
loginW toParentRoute = do
  mToken <- reqToken <$> liftHandler getRequest
  [whamlet|
    <h1>Sign in
    <p>
      Sign in with OpenID Connect (single sign on). Enter your email,
      and we'll redirect you to your company's login page.
    <form action="@{toParentRoute oidcForwardR}">
      $maybe token <- mToken
        <input type=hidden name=#{defaultCsrfParamName} value=#{token}>
      <input type=email name=email placeholder="Enter your corporate email">
      <button type=submit aria-label="Sign in">
  |]

getLoginR :: YesodAuthOIDC site => AuthHandler site TypedContent
getLoginR = do
  rtp <- getRouteToParent
  selectRep . provideRep . authLayout $ toWidget $ loginW rtp

findProvider :: (YesodAuthOIDC site, HasHttpManager site)
             => LoginHint -> AuthHandler site (Provider, ClientId)
findProvider loginHint = getProviderConfig loginHint >>= \case
  (Left provider, clientId) ->
    pure (provider, clientId)
  (Right issuerLoc, clientId) -> do
    unless ("https:" `T.isPrefixOf` issuerLoc
            || "http://localhost" `T.isPrefixOf` issuerLoc) $
      throwIO $ TLSNotUsedException
        $ "The issuer location doesn't start with 'https:'. \
          \OIDC requires all communication with the IdP to use TLS."
    mgr <- getHttpManager <$> getYesod
    provider <- liftIO $ discover issuerLoc mgr
    onProviderConfigDiscovered provider clientId 60
    pure (provider, clientId)

-- | Expects 'email' and '_token' post params.
postForwardR :: (YesodAuthOIDC site, HasHttpManager site)
            => AuthHandler site TypedContent
postForwardR = do
  checkCsrfParamNamed defaultCsrfParamName
  mLoginHint <- lookupPostParam "email"
  case mLoginHint of
    Nothing -> onBadLoginHint
    Just loginHint -> do
      (provider, clientId) <- findProvider loginHint
      forward loginHint provider clientId

-- Generates a 64-bit nonce encoded as uri-safe base64
genNonce :: IO ByteString
genNonce = Base64Url.encode <$> Crypto.getRandomBytes 64

sessionPrefix :: Text
sessionPrefix = "ya"

nonceSessionKey :: Text
nonceSessionKey = sessionPrefix <> "-oidc-nonce"

stateSessionKey :: Text
stateSessionKey = sessionPrefix <> "-oidc-state"

loginHintSessionKey :: Text
loginHintSessionKey = sessionPrefix <> "-oidc-login-hint"

-- oidc-client's CodeFlow functions have a `MonadCatch m` constraint,
-- and take a `SessionStore m` argument. Handlers in Yesod do not
-- implement MonadCatch, so we use m ~ IO, and then unliftIO to still
-- use Handler calls in the 'SessionStore IO'
makeSessionStore :: AuthHandler site (SessionStore IO)
makeSessionStore = do
  UnliftIO unlift <- askUnliftIO
  pure $ SessionStore
    { sessionStoreGenerate = genNonce
    , sessionStoreSave = \state nonce -> unlift $ do
        setSessionBS stateSessionKey state
        setSessionBS nonceSessionKey nonce
    , sessionStoreGet = unlift $
        (,) <$> lookupSessionBS stateSessionKey
            <*> lookupSessionBS nonceSessionKey
    , sessionStoreDelete = unlift $ do
        deleteSession stateSessionKey
        deleteSession nonceSessionKey
    }

newtype ClientId = ClientId { unClientId :: Text } deriving (Show, Eq, Ord)

newtype ClientSecret = ClientSecret { unClientSecret :: Text }

instance Show ClientSecret where
  show _ = "<redacted-client-secret>"

makeOIDC ::
  Provider
  -> ClientId
  -> ClientSecret
  -> AuthHandler site OIDC
makeOIDC provider (ClientId clientId) (ClientSecret clientSecret) = do
  urlRender <- getUrlRender
  toParent <- getRouteToParent
  pure $ OIDC
    { oidcAuthorizationServerUrl = authorizationEndpoint cfg
    , oidcTokenEndpoint = tokenEndpoint cfg
    , oidcClientId = encodeUtf8 clientId
    , oidcRedirectUri = encodeUtf8 $ urlRender $ toParent oidcCallbackR
    , oidcProvider = provider
    , oidcClientSecret = encodeUtf8 clientSecret
    }
  where cfg = configuration provider

forward :: (YesodAuthOIDC a)
        => LoginHint
        -> Provider
        -> ClientId
        -> AuthHandler a TypedContent
forward loginHint provider@(Provider cfg _keyset) clientId = do
  scopes <- getScopes clientId cfg
  setSession loginHintSessionKey loginHint
  -- The OIDC protocol must never use the Client Secret at this stage,
  -- but the oidc-client haskell library still asks for it inside the
  -- 'OIDC' type. We purposefully throw a 500 error if the value is used.
  oidc <- makeOIDC provider clientId (ClientSecret "DUMMY") <&> \oidc' -> oidc'
    { oidcClientSecret =
        error "client_secret should never be used in the authentication \
              \request as it would undesirably expose the secret to the user"
    }
  let extraParams =
        [("login_hint", Just $ urlEncode False $ encodeUtf8 loginHint)]
  sessionStore <- makeSessionStore
  -- This function internally prepends "openid" to the scope list (and
  -- also deduplicates it)
  uri <- liftIO $ prepareAuthenticationRequestUrl
         sessionStore oidc scopes extraParams
  redirect $ show uri

data CallbackInput = CallbackInput
  { ciState :: Text
  , ciCode :: Text
  }

-- | As defined in RFC6749 §5.2
data OAuthErrorResponse = OAuthErrorResponse
  { oaeError :: Text
  , oaeErrorDescription :: Maybe Text
  , oaeErrorUri :: Maybe Text
  } deriving Show

asTrustedState :: YesodAuthOIDC site
  => SessionStore IO -> [Text] -> AuthHandler site Text
asTrustedState sessionStore = \case
  [untrustedState] -> do
    (mState, _) <- liftIO $ sessionStoreGet sessionStore
    if fmap decodeUtf8 mState /= Just untrustedState
      then onBadCallbackRequest Nothing
      else pure untrustedState
  _ -> onBadCallbackRequest Nothing

processCallbackInput :: YesodAuthOIDC site
  => StdMethod -> SessionStore IO -> AuthHandler site CallbackInput
processCallbackInput reqMethod sessionStore = do
  validState <- params "state" >>= asTrustedState sessionStore
  codes <- params "code"
  errs <- params "error"
  case (codes, errs) of
    ([code], []) ->
      pure CallbackInput
        { ciState = validState
        , ciCode = code }
    ([], [err]) -> do
      mErrDesc <- listToMaybe <$> params "error_description"
      mErrUri <- listToMaybe <$> params "error_uri"
      onBadCallbackRequest $ Just $ OAuthErrorResponse err mErrDesc mErrUri
    _ -> onBadCallbackRequest Nothing
  where
    params = if reqMethod == GET
      then lookupGetParams
      else lookupPostParams

-- Providers may use GET or POST for the callback, so we
-- handle both cases in this function
handleCallback ::
  (HasHttpManager site, YesodAuthOIDC site)
  => StdMethod -> AuthHandler site TypedContent
handleCallback reqMethod = do
  loginHint <- lookupSession loginHintSessionKey
    >>= maybe (onBadCallbackRequest Nothing) pure
  deleteSession loginHintSessionKey
  sessionStore <- makeSessionStore
  CallbackInput{..} <- processCallbackInput reqMethod sessionStore
  (provider, clientId) <- findProvider loginHint
  clientSecret <- getClientSecret clientId $ configuration provider
  oidc <- makeOIDC provider clientId clientSecret
  mgr <- getHttpManager <$> getYesod
  tokens <- liftIO $ getValidTokens sessionStore oidc mgr
            (encodeUtf8 ciState) (encodeUtf8 ciCode)
  let posixExpiryTime = case Client.exp $ idToken tokens of
        IntDate posixTime -> floor @POSIXTime @Int posixTime
  userInfoPref <- getUserInfoPreference loginHint clientId (configuration provider)
  requestedClaims <- HashSet.delete Scopes.openId . HashSet.fromList
                     <$> getScopes clientId (configuration provider)
  let missingClaims = requestedClaims
        `HashSet.difference` HM.keysSet (otherClaims $ idToken tokens)
  mUserInfo <- case (userInfoPref, userinfoEndpoint $ configuration provider) of
    (GetUserInfoIfAvailable, Just uri) -> liftIO $
      handleAny (const (pure Nothing)) $ requestUserInfo mgr tokens uri
    (GetUserInfoOnlyToSatisfyRequestedScopes, Just uri)
      | not (HashSet.null missingClaims) -> liftIO $
        handleAny (const (pure Nothing)) $ requestUserInfo mgr tokens uri
    _ -> pure Nothing
  userId <- onSuccessfulAuthentication loginHint clientId provider tokens mUserInfo
  setSession sessionExpiryKey $ tshow posixExpiryTime
  setCredsRedirect Creds
    { credsPlugin = oidcPluginName
    , credsIdent = userId
    , credsExtra = [("iss", iss $ idToken tokens), ("exp", tshow posixExpiryTime)]
    }

sessionExpiryKey :: Text
sessionExpiryKey = sessionPrefix <> "-exp"

requestUserInfo ::
  HTTP.Manager -> Tokens J.Object -> Text -> IO (Maybe J.Object)
requestUserInfo mgr tokens uri = do
  unless ("https:" `T.isPrefixOf` uri
            || "http://localhost" `T.isPrefixOf` uri) $
    throwIO $ TLSNotUsedException $ "The URI of the UserInfo Endpoint must start with https"
  unless (T.toLower (tokenType tokens) == "bearer") $
    -- "The client MUST NOT use an access token if it does not
    -- understand the token type." (RFC6749 7.1). "The OAuth 2.0
    -- token_type response parameter value MUST be Bearer" (OIDC Core
    -- 3.1.3.3)
    throwIO $ UnknownTokenType $ tokenType tokens
  req0 <- HTTP.parseRequest $ T.unpack uri
  -- Use Bearer auth as defined in RFC6750 2.1
  let req = req0 {
        HTTP.requestHeaders = [
            ("Authorization" , encodeUtf8 $ "Bearer " <> accessToken tokens)]
        }
  resp <- HTTP.httpLbs req mgr
  pure $ J.decode $ responseBody resp

-- | Checks if the user has authenticated via the
-- `yesod-auth-oidc`. If so, checks for the session expiry time as
-- returned by the original ID Token. If expired, it removes the
-- 'sessionExpiryKey' from the session, then calls
-- 'onSessionExpired'. We can greatly improve this by following the
-- specs that can request re-authentication via the OIDC-defined
-- "prompt" parameter, but this is not implemented yet.
--
-- You should add this to your app's middleware. This library cannot
-- include it automatically.
oidcSessionExpiryMiddleware :: YesodAuthOIDC site => HandlerFor site a -> HandlerFor site a
oidcSessionExpiryMiddleware handler = do
  mExp <- lookupSession sessionExpiryKey
  case mExp of
    Just ex -> do
      let mExInt :: Maybe Int64 = readMay ex
      case mExInt of
        Nothing -> onSessionExpiry >> handler
        Just exInt -> do
          let expTime = posixSecondsToUTCTime $ realToFrac exInt
          now <- liftIO $ getCurrentTime
          if now > expTime
            then do
              deleteSession sessionExpiryKey
              onSessionExpiry
              -- The handler almost certainly will be
              -- short-circuited by now but for flexbility and
              -- easier typing, we include it here:
              handler
            else handler
    _ -> handler
