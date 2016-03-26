{-# LANGUAGE OverloadedStrings #-}
module MiscSpec where

import           Network.HTTP.ECE

import           Test.Hspec

spec :: Spec
spec = do
  describe "Examples" $ do
    it "should do 1 + 1" $ 1 + 1 `shouldBe` 2
