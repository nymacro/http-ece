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

explicitKeyEncrypt :: ByteString -> ByteString -> ByteString -> Maybe (Params, ByteString)
explicitKeyEncrypt key iv plaintext =
  let params = [ ("Content-Encoding", Just "aesgcm")
               , ("Encryption", Just $ "keyid=\"a1\"; salt=\"" <> (decodeUtf8 $ UB64.encode iv) <> "\"")
               , ("Crypto-Key", Just $ "keyid=\"a1\"; aesgcm=\"" <> (decodeUtf8 $ UB64.encode key) <> "\"")]
      ciphertext = Shared.encrypt key iv plaintext
  in case ciphertext of
    Just c  -> Just (params, c)
    Nothing -> Nothing

-- explicitKeyDecrypt :: (Params, ByteString) -> Maybe ByteString
-- explicitKeyDecrypt (params, ciphertext) = do
--   let key =
--   in undefined

instance ContentEncoding ExplicitKey where
  encrypt key salt plaintext = ExplicitKey <$> explicitKeyEncrypt key salt plaintext
  decrypt = undefined
