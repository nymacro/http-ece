{-# LANGUAGE OverloadedStrings #-}
module Network.HTTP.ECE.Shared (encrypt, decrypt, authTagFromByteString) where

import           Data.Bits
import qualified Data.ByteArray      as ByteArray
import           Data.ByteString     (ByteString)
import qualified Data.ByteString     as BS
import           Data.Monoid

import           Crypto.Cipher.AES
import           Crypto.Cipher.Types
import           Crypto.Error        (eitherCryptoError, maybeCryptoError)

import           Debug.Trace

encrypt :: ByteString -- ^ encryption key
        -> ByteString -- ^ nonce
        -> ByteString -- ^ data to encrypt
        -> ByteString
encrypt encryptionKey nonce plaintext = payload
  where Just aesCipher   = maybeCryptoError (cipherInit encryptionKey) :: Maybe AES128
        Just iv          = makeIV nonce :: Maybe (IV AES128)
        Just cipher      = maybeCryptoError $ aeadInit AEAD_GCM aesCipher iv

        -- add padding
        padSizeLen  = 2
        toEncrypt   = BS.replicate padSizeLen 0 <> plaintext

        (authTag, encrypted) = aeadSimpleEncrypt cipher ("" :: ByteString) toEncrypt 16
        payload = encrypted <> authTagToByteString authTag


authTagToByteString :: AuthTag -> ByteString
authTagToByteString authTag = BS.pack $ ByteArray.unpack $ unAuthTag authTag

authTagFromByteString :: ByteString -> AuthTag
authTagFromByteString bs = AuthTag $ ByteArray.pack $ BS.unpack bs

decrypt :: ByteString -- ^ encryption key
        -> ByteString -- ^ nonce
        -> ByteString -- ^ encrypted payload
        -> Maybe ByteString
decrypt encryptionKey nonce payload =
  let Just aesCipher    = maybeCryptoError (cipherInit encryptionKey) :: Maybe AES128
      Just iv           = makeIV nonce :: Maybe (IV AES128)
      Just cipher       = maybeCryptoError $ aeadInit AEAD_GCM aesCipher iv
      (ciphertext, tag) = BS.splitAt (BS.length payload - 16) payload
      Just plaintext    = aeadSimpleDecrypt cipher ("" :: ByteString) ciphertext (authTagFromByteString tag)
      -- remove padding
      padSizeLen        = 2
      paddingSize       = BS.take padSizeLen plaintext
      padSize           = fromIntegral $ BS.foldl1 (\x y -> (shift x 8) .|. y) paddingSize
      unpadded          = BS.drop (padSizeLen + padSize) plaintext
  in if BS.take padSize plaintext /= BS.replicate padSize 0
     then error $ "bad padding! expected: " <> show padSize
     else Just unpadded

