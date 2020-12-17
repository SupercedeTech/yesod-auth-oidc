{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

module ExampleApp where

import ClassyPrelude.Yesod
import qualified Data.Aeson as J
import qualified Data.HashMap.Strict as HM
import qualified Data.Text as T
import Database.Persist.Sql
import ExampleProviderOpts
import Yesod.Auth
import Yesod.Auth.OIDC
import Yesod.Core.Types (Logger)

data App = App
  { appLogger   :: Logger
  , appHost :: Text
  , appConnPool :: ConnectionPool
  , appHttpManager :: Manager
  , appBrochClientId :: ClientId
  }

mkYesod "App" [parseRoutes|
/ HomeR GET
/auth AuthR Auth getAuth
/convenient-test-token CsrfTokenR GET
/protected/resource ProtectedResourceR GET
|]

getHomeR :: Handler ()
getHomeR = pure ()

getCsrfTokenR :: Handler Text
getCsrfTokenR = do
  setCsrfCookie
  reqToken <$> getRequest >>= \case
    Nothing -> error "app unexpectedly started without session storage"
    Just t -> pure t

getProtectedResourceR :: Handler J.Value
getProtectedResourceR = do
  uid <- requireAuthId
  pure $ J.String $ tshow uid

share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
OidcConfig
  clientId Text
  issuer Text
  Primary clientId issuer
  deriving Show

OidcDomain
  domain Text
  clientId Text
  issuer Text
  Primary domain
  Foreign OidcConfig oidc_domain_oidc_config_fk clientId issuer
  deriving Show

-- | Users in this example app come exclusively from OIDC
-- Providers. Users are created automatically on successful
-- authentication
User
  -- | We specifically do not make the email unique per-user, in
  -- accordance with the OIDC spec
  email Email

  -- | The unique issuer + subject pair could be made null-able in an
  -- app that also allows non-OIDC registrations
  issuer Text
  subject Text

  UniqueUser issuer subject
  deriving Show
|]

instance Yesod App where

instance YesodPersist App where
  type YesodPersistBackend App = SqlBackend

  runDB :: SqlPersistT Handler a -> Handler a
  runDB db = getsYesod appConnPool >>= runSqlPool db

instance YesodAuth App where
  type AuthId App = Key User
  loginDest _ = HomeR
  logoutDest _ = HomeR
  authPlugins _ = [ authOIDC ]
  getAuthId = return . fromPathPiece . credsIdent
  maybeAuthId = defaultMaybeAuthId

addProvider ::
  ( PersistStoreWrite (YesodPersistBackend (HandlerSite f))
  , YesodPersist (HandlerSite f)
  , MonadHandler f
  , BaseBackend (YesodPersistBackend (HandlerSite f)) ~ SqlBackend)
  => OidcConfig -> [Text] -> f ()
addProvider cfg domains = liftHandler . runDB $ do
  insert_ cfg
  insertMany_ $ flip map domains $ \domain ->
    OidcDomain { oidcDomainDomain = domain
               , oidcDomainClientId = oidcConfigClientId cfg
               , oidcDomainIssuer = oidcConfigIssuer cfg
               }

instance HasHttpManager App where
  getHttpManager = appHttpManager

instance YesodAuthOIDC App where
  getProviderConfig loginHint = do
    let domain = snd $ T.breakOnEnd "@" loginHint
    mConfig <- liftHandler . runDB $ get $ OidcDomainKey domain
    case mConfig of
      Just cfg -> pure ( Right $ oidcDomainIssuer cfg
                       , ClientId $ oidcDomainClientId cfg)
      Nothing -> error "No config for this domain"
  getClientSecret = pure . fakeClientSecret
  onSuccessfulAuthentication _originalLoginHint _clientId _provider tokens mUserInfo = do
    let idTok = idToken tokens
    -- The 'email' is sometimes in the ID Token, and sometimes in the
    -- UserInfo Response. Both are JSON objects.
    let emailVal =
          HM.lookup "email" (otherClaims idTok)
          <|> (mUserInfo >>= HM.lookup "email")
        emailAddr = case emailVal of
          Just (J.String em) -> em
          _ -> error "Spec-conforming email missing from ID token and/or User Info Response"
    mUser <- liftHandler . runDB $ getBy $ UniqueUser (iss idTok) (sub idTok)
    case mUser of
      Just (Entity uid u) -> do
        when (userEmail u /= emailAddr) $
          liftHandler . runDB $ update uid [ UserEmail =. emailAddr ]
        pure $ toPathPiece uid
      Nothing -> do
        fmap toPathPiece $ liftHandler . runDB $ insert $ User
          { userEmail = emailAddr
          , userIssuer = iss idTok
          , userSubject = sub idTok
          }

instance YesodAuthPersist App

instance RenderMessage App FormMessage where
  renderMessage _ _ = defaultFormMessage
