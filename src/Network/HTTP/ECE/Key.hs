{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.HTTP.ECE.Key ( ExplicitKey (..)
                            , generateKey
                            , generateSalt
                            , explicitKeyLookup ) where

import           Network.HTTP.ECE
import qualified Network.HTTP.ECE.Shared    as Shared
import           Network.HTTP.Types

import qualified Data.ByteArray             as ByteArray
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Base64.URL as UB64
import           Data.Monoid
import           Data.Text
import           Data.Text.Encoding         (decodeUtf8, encodeUtf8)

import           Crypto.Random

data ExplicitKey a = ExplicitKey a

generateKey :: IO ByteString
generateKey = do
  rng <- getSystemDRG
  let (bytes, gen) = randomBytesGenerate 16 rng
  return bytes

generateSalt :: IO ByteString
generateSalt = do
  rng <- getSystemDRG
  let (bytes, gen) = randomBytesGenerate 16 rng
  return bytes

explicitKeyEncrypt :: ByteString
                   -> ByteString
                   -> ByteString
                   -> Maybe ([Header], ByteString)
explicitKeyEncrypt key salt plaintext =
  let keyId      = "a1"
      headers    = [ ("Content-Encoding", "aesgcm")
                   , ("Encryption", encodeEncryptionParams [ ("keyid", Just keyId)
                                                           , ("salt", Just $ decodeUtf8 $ UB64.encode salt)] )
                   , ("Crypto-Key", encodeEncryptionParams [ ("keyid", Just keyId)
                                                           , ("aesgcm", Just $ decodeUtf8 $ UB64.encode key) ])]
      ciphertext = Shared.encrypt key salt plaintext
  in case ciphertext of
    Just c  -> Just (headers, c)
    Nothing -> Nothing

explicitKeyDecrypt :: ([Header], ByteString)
                   -> (Text -> Maybe ByteString)
                   -> Maybe ByteString
explicitKeyDecrypt (headers, ciphertext) _ = do
  encryptionParams <- getHeader "Encryption" headers >>= decodeEncryptionParams . decodeUtf8
  cryptoKeyParams  <- getHeader "Crypto-Key" headers >>= decodeEncryptionParams . decodeUtf8
  key              <- getParam "aesgcm" cryptoKeyParams
  salt             <- getParam "salt" encryptionParams
  let keyBytes  = UB64.decodeLenient $ encodeUtf8 key
      saltBytes = UB64.decodeLenient $ encodeUtf8 salt
  Shared.decrypt keyBytes saltBytes ciphertext

-- | helper function for ExplicitKey key lookups
explicitKeyLookup :: ByteString -> KeyStore -> Maybe ByteString
explicitKeyLookup keyid = getKey (ExplicitMethod, keyid)

instance ContentEncoding ExplicitKey where
  encrypt key salt plaintext = ExplicitKey <$> explicitKeyEncrypt key salt plaintext
  decrypt _ (ExplicitKey x)  = explicitKeyDecrypt x (const Nothing)
