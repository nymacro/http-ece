{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.HTTP.ECE.Key where

import           Network.HTTP.ECE
import qualified Network.HTTP.ECE.Shared    as Shared

import qualified Data.ByteArray             as ByteArray
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Base64.URL as UB64
import           Data.Monoid

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

explicitKeyEncrypt :: ByteString -> ByteString -> ByteString -> (Params, ByteString)
explicitKeyEncrypt key iv plaintext =
  let params = [ ("Content-Encoding", "aesgcm")
               , ("Encryption", "keyid=\"a1\"; salt=\"" <> UB64.encode iv <> "\"")
               , ("Crypto-Key", "keyid=\"a1\"; aesgcm=\"" <> UB64.encode key <> "\"")]
  in (params, Shared.encrypt key iv plaintext)

-- explicitKeyDecrypt :: (Params, ByteString) -> Maybe ByteString
-- explicitKeyDecrypt (params, ciphertext) = do
--   let key =
--   in undefined

instance ContentEncoding ExplicitKey where
  encrypt key salt plaintext = ExplicitKey $ explicitKeyEncrypt key salt plaintext
  decrypt = undefined
