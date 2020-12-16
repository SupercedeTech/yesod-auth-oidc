{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}

module TestImport
  ( module TestImport
  , module X
  ) where

import ClassyPrelude as X hiding (Handler, delete, deleteBy)
import Control.Monad.Logger (runLoggingT)
import qualified Data.Map as M
import Database.Persist as X hiding (get)
import Database.Persist.Sql (runMigration, runSqlPool)
import Database.Persist.Sqlite (createSqlitePool)
import ExampleApp as X
import ExampleProvider as Broch
import ExampleProviderOpts as X
import Network.HTTP.Client
import Network.Wai.Handler.Warp
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import System.Directory
import System.Log.FastLogger (newStdoutLoggerSet)
import Test.Hspec as X
import Yesod hiding (get)
import Yesod.Auth.OIDC as X hiding (exp)
import Yesod.Core as X
import qualified Yesod.Core.Unsafe as Unsafe
import Yesod.Default.Config2 (makeYesodLogger)
import Yesod.Persist.Core as X

type TestArgs = (Async (), Async (), App, BrochOptions)

user1 :: (SubjectId, (Email, Password))
user1 = ("user1", ("user1@example.local", "password1"))

brochUsers :: Map SubjectId (Email, Password)
brochUsers = M.fromList
  [ user1
  , ("user2", ("user2@sub.example.local", "password2"))
  ]

withServers :: SpecWith TestArgs -> Spec
withServers = beforeAll runServers . afterAll stopServers
  where
    appPort = 4049
    appHost = "http://localhost:" <> tshow appPort
    boPort = 4050
    boIssuerUri = "http://localhost:" <> tshow boPort
    boUsers = brochUsers
    appBrochClientId = ClientId "client1"
    boClients = M.fromList
      [ (appBrochClientId, ( fakeClientSecret appBrochClientId
                           , appHost
                           , appHost <> "/auth/page/oidc/callback"))
      ]
    brochOptions = BrochOptions{..}
    runServers = do
      brochA <- async $ Broch.runBroch brochOptions
      appLogger <- newStdoutLoggerSet 1 >>= makeYesodLogger
      appHttpManager <- newManager defaultManagerSettings
      let mkFoundation appConnPool = App {..}
          tempFoundation = mkFoundation $ error "connPool forced in tempFoundation"
          logFunc = messageLoggerSource tempFoundation appLogger
      removeIfExists "auth.sqlite3"
      pool <- flip runLoggingT logFunc $ createSqlitePool "auth.sqlite3" 10
      runLoggingT (runSqlPool (runMigration migrateAll) pool) logFunc
      let app = mkFoundation pool
      waiApp <- toWaiAppPlain app
      appA <- async $ run appPort $ logStdoutDev waiApp
      pure (brochA, appA, app, brochOptions)
    stopServers (brochA, appA, _, _) = do
      cancel brochA
      cancel appA

unsafeHandler :: App -> Handler a -> IO a
unsafeHandler = Unsafe.fakeHandlerGetLogger appLogger

removeIfExists :: FilePath -> IO ()
removeIfExists f = do
  fileExists <- doesFileExist f
  when fileExists (removeFile f)
