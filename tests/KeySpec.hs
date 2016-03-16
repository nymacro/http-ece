{-# LANGUAGE OverloadedStrings #-}
module KeySpec where

import qualified Data.ByteString.Base64.URL as UB64

import           Test.Hspec

import           Network.HTTP.ECE.Key
import           Network.HTTP.ECE.Shared

import           Debug.Trace

import qualified Data.ByteArray             as ByteArray
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as BS
import           Data.Monoid

import           Crypto.Cipher.AES
import           Crypto.Cipher.Types
import           Crypto.Error               (eitherCryptoError,
                                             maybeCryptoError)

spec :: Spec
spec = do
  describe "HTTP Encrypted Content-Encoding" $ do
    describe "Explicit Key" $ do
      it "should decrypt RFC example" $ do
        let salt       = UB64.decodeLenient "vr0o6Uq3w_KDWeatc27mUg"
            key        = UB64.decodeLenient "csPJEXBYA5U-Tal9EdJi-w"
            ciphertext = UB64.decodeLenient "VDeU0XxaJkOJDAxPl7h9JD5V8N43RorP7PfpPdZZQuwF"
        decrypt key salt ciphertext `shouldBe` Just "I am the walrus"
