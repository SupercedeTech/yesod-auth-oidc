{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-
The code in this module is modified from that found in the
broch-server/broch.hs file in the 'broch' library, which is under the
following copyright and license:

----------------------

Copyright (c) 2014, Luke Taylor

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the name of the author nor the names of his contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-}
module ExampleProvider where

import ClassyPrelude
import ExampleProviderOpts

import Broch.Model
import Broch.Server
import Broch.Server.Config
import Broch.Server.Internal
import Broch.Server.Session (defaultKey, defaultLoadSession)
import qualified Broch.SQLite as BS
import Broch.URI
import Crypto.KDF.BCrypt (hashPassword)
import Data.Aeson
import qualified Data.Map as M
import Data.Pool (createPool, withResource)
import qualified Database.SQLite.Simple as SQLite
import Network.Wai.Application.Static (defaultWebAppSettings, staticApp)
import Network.Wai.Handler.Warp (run)
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import System.Directory
import qualified Web.Routing.Combinators as R
import qualified Web.Routing.SafeRouting as R
import Yesod.Auth.OIDC (ClientId(..), ClientSecret(..))

-- Adapted from Broch.SQLite
toJSONField :: ToJSON a => Maybe a -> SQLite.SQLData
toJSONField = maybe SQLite.SQLNull (SQLite.SQLText . decodeUtf8 . toStrict . encode)

-- Adapted from Broch.SQLite
insertClient :: SQLite.Connection -> Client -> IO ()
insertClient conn Client{..} =
    void $ SQLite.execute conn "INSERT INTO oauth2_client (id, secret, redirect_uri, allowed_scope, authorized_grant_types, access_token_validity, refresh_token_validity, auth_method, auth_alg, keys_uri, keys, id_token_algs, user_info_algs, request_obj_algs, sector_identifier, auto_approve) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)" ((clientId, clientSecret, redirectURIs, allowedScope, authorizedGrantTypes, accessTokenValidity, refreshTokenValidity, clientAuthMethodName tokenEndpointAuthMethod, fmap tshow tokenEndpointAuthAlg, clientKeysUri) SQLite.:. (toJSONField clientKeys, toJSONField idTokenAlgs, toJSONField userInfoAlgs, toJSONField requestObjAlgs, sectorIdentifier, autoapprove))

initDB :: BrochOptions -> SQLite.Connection -> IO ()
initDB BrochOptions{..} c = do
  void $ flip M.traverseWithKey boClients $ \(ClientId clientId) (ClientSecret secret, host, callback) ->
    insertClient c $ Client
      { clientId = clientId
      , clientSecret = Just secret
      , authorizedGrantTypes = [AuthorizationCode]
      , redirectURIs = case parseURI callback of
          Right url -> [url]
          Left e -> error $ "Can't initialise tests due to bad callback URL: " <> show e
      , accessTokenValidity = 3600
      , refreshTokenValidity = 7200
      , allowedScope = [OpenID, Profile, Email]
      , autoapprove = False
      , tokenEndpointAuthMethod = ClientSecretPost
      , tokenEndpointAuthAlg    = Nothing -- :: Maybe JwsAlg
      , clientKeysUri  = Nothing -- :: Maybe Text
      , clientKeys     = Just [] -- :: Maybe [Jwk]
      , idTokenAlgs    = Nothing -- :: Maybe AlgPrefs
      , userInfoAlgs   = Nothing -- :: Maybe AlgPrefs
      , requestObjAlgs = Nothing -- :: Maybe AlgPrefs
      , sectorIdentifier = host
      }
  void $ flip M.traverseWithKey boUsers $ \userId (emailAddr, pw) -> do
    pwHash :: ByteString <- hashPassword 6 (encodeUtf8 pw)
    void $ SQLite.execute c "INSERT OR REPLACE INTO op_user VALUES (?, ?, ?, 'key')" ((userId, userId, pwHash))
    void $ SQLite.execute c "INSERT OR REPLACE INTO user_info VALUES (?, 'name', 'first', 'last', 'middle', 'nick', 'name', 'http://placeholder', 'http://placeholder', 'http://placeholder', ?, 0, null, '2000-01-01', 'Europe/Paris', 'en-US', '+33 12 34 56 78', 0, '25 My Street, Village, 1234567, France', '25 My Street', 'Vilage', 'Shire', '1234567', 'EN', datetime('now'))" ((userId, emailAddr))


runBroch :: BrochOptions -> IO ()
runBroch opts@BrochOptions{..} = do
  sessionKey <- defaultKey
  kr <- defaultKeyRing
  rotateKeys kr True
  let dbFile = "broch.sqlite3"
  dbExists <- doesFileExist dbFile
  when dbExists $ removeFile dbFile
  pool <- createPool (SQLite.open dbFile) SQLite.close 1 60 20
  withResource pool BS.createSchema
  config <- BS.sqliteBackend pool <$> inMemoryConfig boIssuerUri kr Nothing
  let app = staticApp (defaultWebAppSettings "webroot")
      baseRouter = brochServer config defaultApprovalPage authenticatedSubject authenticateSubject
      authenticate username password = pure $ M.lookup username boUsers >>= \case
        (_, pw) | pw == password -> Just username
        _ -> Nothing
      extraRoutes =
          [ ("/home",   text "Hello, I'm the home page")
          , ("/login",  passwordLoginHandler defaultLoginPage authenticate)
          , ("/logout", invalidateSession >> text "You have been logged out")
          ]
      router = foldl' (\pathMap (r, h) -> R.insertPathMap' (R.toInternalPath (R.static r)) (const h) pathMap) baseRouter extraRoutes
      broch = routerToMiddleware (defaultLoadSession 3600 sessionKey) boIssuerUri router

  withResource pool $ initDB opts

  run boPort (logStdoutDev (broch app))
