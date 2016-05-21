{-# LANGUAGE OverloadedStrings #-}
module KeySpec where

import qualified Data.ByteString.Base64.URL as UB64

import           Test.Hspec

import           Network.HTTP.ECE
import           Network.HTTP.ECE.Key
import qualified Network.HTTP.ECE.Shared    as Shared
import           Network.HTTP.Types

import qualified Data.ByteArray             as ByteArray
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as BS
import           Data.Monoid
import           Data.Text.Encoding         (decodeUtf8, encodeUtf8)

import           Crypto.Cipher.AES
import           Crypto.Cipher.Types
import           Crypto.Error               (eitherCryptoError,
                                             maybeCryptoError)

spec :: Spec
spec = do
  describe "Explicit Key" $ do
    describe "Example" $ do
      it "should decrypt RFC example" $ do
        let salt       = "vr0o6Uq3w_KDWeatc27mUg"
            key        = "csPJEXBYA5U-Tal9EdJi-w"
            ciphertext = UB64.decodeLenient "VDeU0XxaJkOJDAxPl7h9JD5V8N43RorP7PfpPdZZQuwF"
            keyId      = "a1"
            headers    = [ ("Encryption", encodeEncryptionParams [ ("keyid", Just keyId)
                                                                 , ("salt", Just salt)])
                         , ("Crypto-Key", encodeEncryptionParams [ ("keyid", Just keyId)
                                                                 , ("aesgcm", Just key)])]
        explicitKeyDecrypt (headers, ciphertext) (const Nothing) `shouldBe` Just "I am the walrus"

    describe "Misc" $ do
      it "should encrypt/decrypt" $ do
        let salt      = UB64.decodeLenient "vr0o6Uq3w_KDWeatc27mUg"
            key       = UB64.decodeLenient "csPJEXBYA5U-Tal9EdJi-w"
            encrypted = encrypt "a1" (const $ Just key) salt "I am the walrus" :: Maybe (ExplicitKey ([Header], ByteString))
            decrypted = decrypt (const Nothing) =<< encrypted
        decrypted `shouldBe` Just "I am the walrus"

