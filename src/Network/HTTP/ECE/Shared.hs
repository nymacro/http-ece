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

encrypt :: ByteString -- ^ encryption key
        -> ByteString -- ^ nonce
        -> ByteString -- ^ data to encrypt
        -> Maybe ByteString
encrypt encryptionKey nonce plaintext = do
  let aesCipher  = cipherInit encryptionKey :: CryptoFailable AES128
      iv         = case makeIV nonce :: Maybe (IV AES128) of
                     Just x  -> CryptoPassed x
                     Nothing -> CryptoFailed CryptoError_IvSizeInvalid
      cipher     = join $ aeadInit AEAD_GCM <$> aesCipher <*> iv
      -- add padding
      padSizeLen = 2
      toEncrypt  = BS.replicate padSizeLen 0 <> plaintext
  case cipher of
    CryptoPassed c -> do
      let (authTag, encrypted) = aeadSimpleEncrypt c ("" :: ByteString) toEncrypt 16
      Just $ encrypted <> authTagToByteString authTag
    CryptoFailed e -> traceShow e Nothing -- TODO remove trace


authTagToByteString :: AuthTag -> ByteString
authTagToByteString = BS.pack . ByteArray.unpack . unAuthTag

authTagFromByteString :: ByteString -> AuthTag
authTagFromByteString = AuthTag . ByteArray.pack . BS.unpack

decrypt :: ByteString -- ^ encryption key
        -> ByteString -- ^ nonce
        -> ByteString -- ^ encrypted payload
        -> Maybe ByteString
decrypt encryptionKey nonce payload =
  let Just aesCipher    = maybeCryptoError (cipherInit encryptionKey) :: Maybe AES128
      Just iv           = makeIV nonce :: Maybe (IV AES128)
      Just cipher       = maybeCryptoError $ aeadInit AEAD_GCM aesCipher iv
      (ciphertext, tag) = BS.splitAt (BS.length payload - 16) payload
      plaintext'        = aeadSimpleDecrypt cipher ("" :: ByteString) ciphertext (authTagFromByteString tag)
  in case plaintext' of
       Just plaintext ->
         -- remove padding
         let padSizeLen  = 2
             paddingSize = BS.take padSizeLen plaintext
             padSize     = fromIntegral $ BS.foldl1 (\x y -> (shift x 8) .|. y) paddingSize
             unpadded    = BS.drop (padSizeLen + padSize) plaintext
         in if BS.take padSize plaintext /= BS.replicate padSize 0
            then error $ "bad padding! expected: " <> show padSize
            else Just unpadded
       Nothing -> Nothing
