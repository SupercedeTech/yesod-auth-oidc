{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RecordWildCards #-}

module Yesod.Auth.OIDCSpec (spec) where

import Control.Lens ((^.))
import qualified Control.Lens.Regex.Text as Regex
import qualified Data.Map as M
import qualified Data.Set as Set
import qualified Data.Text as T
import Network.HTTP.Client
import Network.HTTP.Types.Status
import TestImport

spec :: Spec
spec = withServers $ do
  describe "login with OpenID Connect" $ do
    it "can login with OIDC" $ \(_, _, app@App{..}, BrochOptions{..}) -> do
      -- In this test, the ExampleProvider has already been populated
      -- with the user, and the ExampleApp is configured to insert new
      -- users into its local database upon successful
      -- authentication. We first configure our client app for this
      -- provider:
      unsafeHandler app $ runDB $ do
          insert_ $ OidcConfig
            { oidcConfigClientId = unClientId appBrochClientId
            , oidcConfigIssuer = boIssuerUri
            }
          let domains = Set.toList . Set.fromList
                $ map (snd . T.breakOnEnd "@" . fst) $ M.elems brochUsers
          insertMany_ $ flip map domains $ \domain -> OidcDomain
            { oidcDomainDomain = domain
            , oidcDomainClientId = unClientId appBrochClientId
            , oidcDomainIssuer = boIssuerUri
            }

      ur <- unsafeHandler app getUrlRender
      let
        mgr = appHttpManager
        mkReq = parseRequest_ . unpack . (appHost <>) . ur
        protectedReq = mkReq ProtectedResourceR
        tokenReq = mkReq CsrfTokenR
        forwardReq = mkReq $ AuthR oidcForwardR

      -- Assert that we can't get the ProtectedResource yet
      protectedRes0 <- httpNoBody protectedReq mgr
      liftIO $ responseStatus protectedRes0 `shouldBe` status403

      -- Get the csrf token (Yesod's default csrf handling is
      -- session-specific rather than request-specific).
      tokenResp <- httpLbs tokenReq mgr
      let token = toStrict $ responseBody tokenResp

      -- POST to the oidcForwardR with correct params.
      let (user1_id, (user1_email, user1_pw)) = user1
      respForwardR <- httpLbs
        (urlEncodedBody
          [ (encodeUtf8 defaultCsrfParamName, token)
          , ("email", encodeUtf8 user1_email)
          ] $ forwardReq { method = "POST"
                         , cookieJar = Just $ responseCookieJar tokenResp })
        mgr
      let
        respForwardR_body = toStrict $ decodeUtf8 (responseBody respForwardR)
        brochCsrfToken = respForwardR_body
          ^. [Regex.regex|name="_rid" value="([^"]*)">|]
          . Regex.group 0

      -- POST the provider's login URL with username and password.
      let loginReq = urlEncodedBody
            [ ("username", encodeUtf8 user1_id)
            , ("password", encodeUtf8 user1_pw)
            , ("_rid", encodeUtf8 brochCsrfToken)
            ] $ (parseRequest_ (unpack $ boIssuerUri <> "/login"))
            { method = "POST"
            , cookieJar = Just $ responseCookieJar respForwardR
            }
      respProviderLogin <- httpLbs loginReq mgr

      -- POST the provider's scope approval form
      let
        expiryParam =
          (toStrict $ decodeUtf8 $ responseBody respProviderLogin)
          ^. [Regex.regex|"expiry"><option value="([^"]*)"|]
          . Regex.group 0
        approvalReq = urlEncodedBody
          [ ("client_id", encodeUtf8 $ unClientId appBrochClientId)
          , ("expiry", encodeUtf8 expiryParam)
          , ("requested_scope", "openid")
          , ("scope", "openid")
          , ("scope", "email")
          ] $ (parseRequest_ (unpack $ boIssuerUri <> "/approval"))
          { method = "POST"
          , cookieJar = Just $ responseCookieJar respProviderLogin
          }
      respApproval <- httpLbs approvalReq mgr

      -- Assert that we can access previously unaccessible protected
      -- resource.
      protectedRes1 <- httpNoBody
        (protectedReq { cookieJar = Just $ responseCookieJar respApproval }) mgr

      liftIO $ responseStatus protectedRes1 `shouldBe` status200
