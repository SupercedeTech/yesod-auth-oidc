module Main where

import ClassyPrelude
import qualified Spec
import Test.Hspec (hspec)

main :: IO ()
main = do
  config <- configure 2
  hspec Spec.spec
