{-# LANGUAGE OverloadedStrings #-}
module ExampleProviderOpts where

import ClassyPrelude
import Yesod.Auth.OIDC

-- Quick-and-dirty type synonyms just for testing
type Domain = Text
type Email = Text
type SubjectId = Text
type ClientHost = Text
type CallbackUri = Text
type Password = Text

-- | You should store your client secrets as you would for other
-- credentials in your app.
fakeClientSecret :: ClientId -> ClientSecret
fakeClientSecret (ClientId cid) =
    -- You should not hardcode it like this:
    ClientSecret $ cid <> "_secret"

-- | We use the 'broch' library as a local OIDC Provider. You do not
-- need something like this in your client app.
data BrochOptions = BrochOptions
  { boIssuerUri :: Text
  , boPort :: Int
  , boUsers :: Map SubjectId (Email, Password)
  , boClients :: Map ClientId (ClientSecret, ClientHost, CallbackUri)
  }
