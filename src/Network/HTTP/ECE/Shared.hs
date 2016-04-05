{-# LANGUAGE OverloadedStrings #-}
module Network.HTTP.ECE.Shared ( encrypt
                               , decrypt
                               , authTagFromByteString
                               , cekInfo
                               , nonceInfo
                               , traceMaybe
                               , makeSharedKey
                               , makeNonce ) where

import           Control.Applicative
import           Control.Monad
import           Data.Bits
import qualified Data.ByteArray         as ByteArray
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import           Data.Monoid

import           Crypto.Cipher.AES
import           Crypto.Cipher.Types
import           Crypto.Error
import           Crypto.Hash.Algorithms
import           Crypto.KDF.HKDF
import           Crypto.MAC.HMAC

import           Debug.Trace

traceMaybe msg a = case a of
                     Just x -> Just x
                     Nothing -> trace ("failed: " <> msg) Nothing

-- TODO remove this
-- traceMaybe _ a = case a of
--                    Just x -> Just x
--                    Nothing -> Nothing

makeSharedKey :: ByteString -- ^ salt
              -> ByteString -- ^ input key material (shared key)
              -> ByteString -- ^ context
              -> ByteString -- ^ 128-bit AES key
makeSharedKey salt keyMaterial context =
  let prk = extract salt keyMaterial :: PRK SHA256
  in expand prk (cekInfo context <> "\x01") 16

-- | https://tools.ietf.org/html/draft-thomson-http-encryption-01#section-3.3
makeNonce :: ByteString -- ^ salt
          -> ByteString -- ^ input key material (shared key)
          -> ByteString -- ^ context
          -> ByteString -- ^ 128-bit AES key
makeNonce salt keyMaterial context =
  let prk = extract salt keyMaterial :: PRK SHA256
  in expand prk (nonceInfo context <> "\x01") 12 <> BS.pack [0,0,0,0] -- FIXME 12 octet HKDF output <> 4 byte null. Should be just 12 octet

-- | info parameter to used for HKDF key derivation
cekInfo :: ByteString -> ByteString
cekInfo context = "Content-Encoding: aesgcm" <> "\x0" <> context

-- | info parameter used for nonce derivation
nonceInfo :: ByteString -> ByteString
nonceInfo context = "Content-Encoding: nonce" <> "\x0" <> context

-- | general encrypt
encrypt :: ByteString -- ^ encryption key
        -> ByteString -- ^ nonce
        -> ByteString -- ^ data to encrypt
        -> Maybe ByteString
encrypt encryptionKey nonce plaintext = do
  aesCipher <- traceMaybe "cipherInit" $ maybeCryptoError (cipherInit encryptionKey) :: Maybe AES128
  iv        <- traceMaybe "makeIV" $ makeIV nonce :: Maybe (IV AES128)
  cipher    <- traceMaybe "aeadInit" $ maybeCryptoError $ aeadInit AEAD_GCM aesCipher iv
  -- add padding
  let padSizeLen = 2
      toEncrypt  = BS.replicate padSizeLen 0 <> plaintext
      (authTag, encrypted) = traceShowId $ aeadSimpleEncrypt cipher ("" :: ByteString) toEncrypt 16
      -- (encrypted, ci) = aeadEncrypt cipher toEncrypt
      -- authTag    = aeadFinalize ci 16
  Just $ encrypted <> authTagToByteString authTag

authTagToByteString :: AuthTag -> ByteString
authTagToByteString = BS.pack . ByteArray.unpack . unAuthTag

authTagFromByteString :: ByteString -> AuthTag
authTagFromByteString = AuthTag . ByteArray.pack . BS.unpack

-- | general decrypt
decrypt :: ByteString -- ^ encryption key
        -> ByteString -- ^ nonce
        -> ByteString -- ^ encrypted payload
        -> Maybe ByteString
decrypt encryptionKey nonce payload = do
  aesCipher <- traceMaybe "cipherInit" $ maybeCryptoError (cipherInit encryptionKey) :: Maybe AES128
  iv        <- traceMaybe "makeIV" $ makeIV nonce :: Maybe (IV AES128)
  cipher    <- traceMaybe "aeadInit" $ maybeCryptoError $ aeadInit AEAD_GCM aesCipher iv
  let (ciphertext, tag) = BS.splitAt (BS.length payload - 16) payload
  plaintext <- traceMaybe "aeadSimpleDecrypt" $ aeadSimpleDecrypt cipher ("" :: ByteString) ciphertext (authTagFromByteString tag)
  let padSizeLen  = 2
      paddingSize = BS.take padSizeLen plaintext
      padSize     = fromIntegral $ BS.foldl1 (\x y -> shift x 8 .|. y) paddingSize
      unpadded    = BS.drop (padSizeLen + padSize) plaintext
  if BS.take padSize plaintext /= BS.replicate padSize 0
  then Nothing -- error $ "bad padding! expected: " <> show padSize
  else Just unpadded
