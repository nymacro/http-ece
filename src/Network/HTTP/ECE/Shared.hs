{-# LANGUAGE OverloadedStrings #-}
module Network.HTTP.ECE.Shared (encrypt, decrypt, authTagFromByteString) where

import           Control.Applicative
import           Control.Monad
import           Data.Bits
import qualified Data.ByteArray      as ByteArray
import           Data.ByteString     (ByteString)
import qualified Data.ByteString     as BS
import           Data.Monoid

import           Crypto.Cipher.AES
import           Crypto.Cipher.Types
import           Crypto.Error

import           Debug.Trace

-- traceMaybe msg a = case a of
--                      Just x -> Just x
--                      Nothing -> trace msg Nothing

-- TODO remove this
traceMaybe _ a = case a of
                   Just x -> Just x
                   Nothing -> Nothing

encrypt :: ByteString -- ^ encryption key
        -> ByteString -- ^ nonce
        -> ByteString -- ^ data to encrypt
        -> Maybe ByteString
encrypt encryptionKey nonce plaintext = do
  aesCipher <- traceMaybe "cipherINIT failed" $ maybeCryptoError (cipherInit encryptionKey) :: Maybe AES128
  iv        <- traceMaybe "IV failed" $ makeIV nonce :: Maybe (IV AES128)
  cipher    <- traceMaybe "aeadInit failed" $ maybeCryptoError $ aeadInit AEAD_GCM aesCipher iv
  -- add padding
  let padSizeLen = 2
      toEncrypt  = BS.replicate padSizeLen 0 <> plaintext
      (authTag, encrypted) = traceShowId $ aeadSimpleEncrypt cipher ("" :: ByteString) toEncrypt 16
  Just $ encrypted <> authTagToByteString authTag

authTagToByteString :: AuthTag -> ByteString
authTagToByteString = BS.pack . ByteArray.unpack . unAuthTag

authTagFromByteString :: ByteString -> AuthTag
authTagFromByteString = AuthTag . ByteArray.pack . BS.unpack

decrypt :: ByteString -- ^ encryption key
        -> ByteString -- ^ nonce
        -> ByteString -- ^ encrypted payload
        -> Maybe ByteString
decrypt encryptionKey nonce payload = do
  aesCipher <- traceMaybe "cipherINIT" $ maybeCryptoError (cipherInit encryptionKey) :: Maybe AES128
  iv        <- traceMaybe "makeIV" $ makeIV nonce :: Maybe (IV AES128)
  cipher    <- traceMaybe "aeadINIT" $ maybeCryptoError $ aeadInit AEAD_GCM aesCipher iv
  let (ciphertext, tag) = BS.splitAt (BS.length payload - 16) payload
  plaintext <- aeadSimpleDecrypt cipher ("" :: ByteString) ciphertext (authTagFromByteString tag)
  let padSizeLen  = 2
      paddingSize = BS.take padSizeLen plaintext
      padSize     = fromIntegral $ BS.foldl1 (\x y -> shift x 8 .|. y) paddingSize
      unpadded    = BS.drop (padSizeLen + padSize) plaintext
  if BS.take padSize plaintext /= BS.replicate padSize 0
  then Nothing -- error $ "bad padding! expected: " <> show padSize
  else Just unpadded
