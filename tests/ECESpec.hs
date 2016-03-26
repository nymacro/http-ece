{-# LANGUAGE OverloadedStrings #-}
module ECESpec where

import           Network.HTTP.ECE
import           Network.HTTP.ECE.Key

import           Test.Hspec

spec :: Spec
spec = do
  describe "KeyStore" $ do
    it "should do storage and retrieval" $ do
      key <- generateKey
      let x = getKey (ExplicitMethod, "a") $ addKey (ExplicitMethod, "a") key $ newKeyStore
      x `shouldBe` Just key

  describe "Encryption Parameters" $ do
    it "should decode single parameter (no value)" $ do
      decodeEncryptionParams "a" `shouldBe` Just [("a", Nothing)]

    it "should decode multi parameter (no value)" $ do
      decodeEncryptionParams "a; b" `shouldBe` Just [("a", Nothing), ("b", Nothing)]

    it "should decode multi parameter (no value, no space)" $ do
      decodeEncryptionParams "a;b" `shouldBe` Just [("a", Nothing), ("b", Nothing)]

    it "should decode single parameters (no quotes)" $ do
      decodeEncryptionParams "a=abc" `shouldBe` Just [("a", Just "abc")]

    it "should decode single parameters (quotes)" $ do
      decodeEncryptionParams "a=\"abc\"" `shouldBe` Just [("a", Just "abc")]

    it "should decode multi parameters (no quotes)" $ do
      decodeEncryptionParams "a=abc; b=def" `shouldBe` Just [("a", Just "abc"), ("b", Just "def")]

    it "should decode multi parameters (no quotes, no space)" $ do
      decodeEncryptionParams "a=abc;b=def" `shouldBe` Just [("a", Just "abc"), ("b", Just "def")]

    it "should decode multi parameters (quotes)" $ do
      decodeEncryptionParams "a=\"abc\"; b=\"def\"" `shouldBe` Just [("a", Just "abc"), ("b", Just "def")]

    it "should decode multi parameters (no space)" $ do
      decodeEncryptionParams "a=\"abc\";b=\"def\"" `shouldBe` Just [("a", Just "abc"), ("b", Just "def")]

    it "should decode encryption parameters correctly" $ do
      decodeEncryptionParams "keyid=\"http://example.org/bob/keys/123\";salt=\"XZwpw6o37R-6qoZjw6KwAw\"" `shouldBe` Just [ ("keyid", Just "http://example.org/bob/keys/123")
                                                                                                                         , ("salt", Just "XZwpw6o37R-6qoZjw6KwAw") ]
      decodeEncryptionParams "keyid=\"mailto:me@example.com\"; salt=\"m2hJ_NttRtFyUiMRPwfpHA\"" `shouldBe` Just [ ("keyid", Just "mailto:me@example.com")
                                                                                                                , ("salt", Just "m2hJ_NttRtFyUiMRPwfpHA")]

    it "should encode encryption parameters correctly" $ do
      encodeEncryptionParams [ ("keyid", Just "a1")
                             , ("salt", Just "b1") ] `shouldBe` "keyid=\"a1\"; salt=\"b1\""
