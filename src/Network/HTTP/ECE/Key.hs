{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.HTTP.ECE.Key ( ExplicitKey (..)
                            , generateKey
                            , generateSalt
                            , explicitKeyLookup
                            , explicitKeyDecrypt
                            , explicitKeyEncrypt ) where

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

explicitKeyContext :: ByteString
explicitKeyContext = ""

explicitKeyEncrypt :: Text
                   -> ByteString
                   -> ByteString
                   -> ByteString
                   -> Maybe ([Header], ByteString)
explicitKeyEncrypt keyId secret salt plaintext =
  let headers    = [ ("Content-Encoding", "aesgcm")
                   , ("Encryption", encodeEncryptionParams [ ("keyid", Just keyId)
                                                           , ("salt", Just $ decodeUtf8 $ UB64.encode salt)] )
                   , ("Crypto-Key", encodeEncryptionParams [ ("keyid", Just keyId)
                                                           , ("aesgcm", Just $ decodeUtf8 $ UB64.encode secret) ])]
      hkdfKey    = Shared.makeSharedKey salt secret explicitKeyContext
      hkdfSalt   = Shared.makeNonce salt secret explicitKeyContext
      ciphertext = Shared.encrypt hkdfKey hkdfSalt plaintext
  in case ciphertext of
    Just c  -> Just (headers, c)
    Nothing -> Nothing

explicitKeyDecrypt :: ([Header], ByteString)
                   -> (Text -> Maybe ByteString)
                   -> Maybe ByteString
explicitKeyDecrypt (headers, ciphertext) _ = do
  encryptionParams <- getHeader "Encryption" headers >>= decodeEncryptionParams . decodeUtf8
  cryptoKeyParams  <- getHeader "Crypto-Key" headers >>= decodeEncryptionParams . decodeUtf8
  secret           <- getParam "aesgcm" cryptoKeyParams
  salt             <- getParam "salt" encryptionParams
  let hkdfKey     = Shared.makeSharedKey saltBytes secretBytes explicitKeyContext
      hkdfSalt    = Shared.makeNonce saltBytes secretBytes explicitKeyContext
      secretBytes = UB64.decodeLenient $ encodeUtf8 secret
      saltBytes   = UB64.decodeLenient $ encodeUtf8 salt
  Shared.decrypt hkdfKey hkdfSalt ciphertext

-- | helper function for ExplicitKey key lookups
explicitKeyLookup :: ByteString -> KeyStore -> Maybe ByteString
explicitKeyLookup keyid = getKey (ExplicitMethod, keyid)

instance ContentEncoding ExplicitKey where
  encrypt keyId key salt plaintext = ExplicitKey <$> explicitKeyEncrypt keyId key salt plaintext
  decrypt _ (ExplicitKey x)  = explicitKeyDecrypt x (const Nothing)
