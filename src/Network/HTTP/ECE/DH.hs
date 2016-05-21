{-# LANGUAGE OverloadedStrings #-}
module Network.HTTP.ECE.DH
       ( ECDHKey (..)
       , generateP256
       , curve
       , Network.HTTP.ECE.DH.getShared
       , loadPublicPoint
       , loadPrivateKey
       , fromPrivateKey
       , fromPublicPoint
       , dhContext
       , PrivateNumber
       , PublicPoint
       , dhEncrypt
       , dhDecrypt ) where

import           Network.HTTP.ECE
import qualified Network.HTTP.ECE.Shared    as Shared
import           Network.HTTP.Types

import           Data.Binary.Put
import qualified Data.ByteArray             as ByteArray
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Base64.URL as UB64
import           Data.ByteString.Lazy       (toStrict)
import           Data.Either.Combinators    (rightToMaybe)
import           Data.Monoid
import           Data.Text
import           Data.Text.Encoding         (decodeUtf8, encodeUtf8)

import           Crypto.Error               (eitherCryptoError,
                                             maybeCryptoError)
import           Crypto.Number.Serialize
import           Crypto.PubKey.ECC.DH       as DH
import           Crypto.PubKey.ECC.Generate
import qualified Crypto.PubKey.ECC.P256     as P256
import           Crypto.PubKey.ECC.Types

data ECDHKey a = ECDHKey a

curve :: Curve
curve = getCurveByName SEC_p256r1

-- | Generate ECDH shared secret
getShared :: PrivateNumber -- ^ sender private number
          -> PublicPoint   -- ^ recipient public point
          -> ByteString    -- ^ shared key bytes
getShared priv pub =
  let (SharedKey key) = DH.getShared curve priv pub
  in ByteArray.convert key

-- | Generate P256 pair
generateP256 :: IO (PrivateNumber, PublicPoint)
generateP256 = do
  privatePoint <- generatePrivate curve
  let (Point x y) = calculatePublic curve privatePoint
      publicPoint = P256.pointFromIntegers (x, y)
  return (privatePoint, fromPoint publicPoint)

-- | get public point from private
-- getPublic :: PrivateNumber -> P256.Point
-- getPublic private = let (Point x y) = calculatePublic curve private
--                     in P256.pointFromIntegers (x, y)
getPublic :: PrivateNumber -> Point
getPublic private = calculatePublic curve private

-- | Convert P256.Point to Point type
fromPoint :: P256.Point -> Point
fromPoint point = let (x, y) = P256.pointToIntegers point
                  in Point x y

toPoint :: Point -> P256.Point
toPoint (Point x y) = P256.pointFromIntegers (x, y)

-- | Content Encryption Key context for ECDH
dhContext :: ByteString -> ByteString -> ByteString -> ByteString
dhContext label senderPublic recipientPublic =
  label <> "\x0"
    <> (toStrict . runPut $ putWord16be $ fromIntegral $ BS.length recipientPublic)
    <> recipientPublic
    <> (toStrict . runPut $ putWord16be $ fromIntegral $ BS.length senderPublic)
    <> senderPublic

nonceContext = dhContext

-- | load a P256 public point
loadPublicPoint :: ByteString -> Maybe Point
loadPublicPoint bs = do
  let (idByte, publicPointBytes) = BS.splitAt 1 bs
  case BS.head idByte of
    -- uncompressed point
    0x04 -> do
      point <- maybeCryptoError (P256.pointFromBinary publicPointBytes)
      let (x, y) = P256.pointToIntegers point
      return $ Point x y
    _ -> Nothing

fromPublicPoint :: Point -> ByteString
fromPublicPoint p = "\x04" <> (P256.pointToBinary $ toPoint p)

-- | Convert private number to bytestring
loadPrivateKey :: ByteString -> PrivateNumber
loadPrivateKey = os2ip

fromPrivateKey :: PrivateNumber -> ByteString
fromPrivateKey = i2osp

dhEncrypt :: Text       -- ^ keyid
          -> ByteString -- ^ private key
          -> ByteString -- ^ public key
          -> ByteString -- ^ recipient public key
          -> ByteString -- ^ salt
          -> ByteString -- ^ plaintext to encrypt
          -> Maybe ([Header], ByteString)
dhEncrypt keyId private public recipientPublic salt plaintext = do
  let headers       = [ ("Content-Encoding", "aesgcm")
                      , ("Encryption", encodeEncryptionParams [ ("keyid", Just keyId)
                                                              , ("salt", Just $ decodeUtf8 $ UB64.encode salt) ])
                      , ("Crypto-Key", encodeEncryptionParams [ ("keyid", Just keyId)
                                                              , ("dh", Just $ decodeUtf8 $ UB64.encode public) ]) ]
      privateNumber = loadPrivateKey private
  recipient <- loadPublicPoint recipientPublic
  let secret        = Network.HTTP.ECE.DH.getShared privateNumber recipient
      context       = dhContext (encodeUtf8 keyId) recipientPublic public
      hkdfKey       = Shared.makeSharedKey salt secret context
      hkdfSalt      = Shared.makeNonce salt secret context
  ciphertext <- Shared.encrypt hkdfKey hkdfSalt plaintext
  return (headers, ciphertext)

dhDecrypt :: ([Header], ByteString)
          -> ((Text, ECEKeyType) -> Maybe ByteString)
          -> Maybe ByteString
dhDecrypt (headers, ciphertext) retriever = do
  encryptionParams <- getHeader "Encryption" headers >>= decodeEncryptionParams . decodeUtf8
  cryptoKeyParams  <- getHeader "Crypto-Key" headers >>= decodeEncryptionParams . decodeUtf8
  keyId            <- getParam "keyid" encryptionParams
  salt             <- getParam "salt" encryptionParams
  dh               <- getParam "dh" cryptoKeyParams
  dhBytes          <- rightToMaybe . UB64.decode $ encodeUtf8 dh
  saltBytes        <- rightToMaybe . UB64.decode $ encodeUtf8 salt
  recipient        <- loadPublicPoint dhBytes
  -- retrieve the private key for keyid
  privateBytes     <- retriever (keyId, ECDHKeyType)
  private          <- return $ loadPrivateKey privateBytes
  publicPoint      <- return $ getPublic private
  public           <- return $ fromPublicPoint publicPoint
  let secret   = Network.HTTP.ECE.DH.getShared private recipient
      context  = dhContext (encodeUtf8 keyId) public dhBytes
      hkdfKey  = Shared.makeSharedKey saltBytes secret context
      hkdfSalt = Shared.makeNonce saltBytes secret context
  Shared.decrypt hkdfKey hkdfSalt ciphertext

instance ContentEncoding ECDHKey where
  encrypt keyId keyFunc salt plaintext = do
    keyBytes           <- keyFunc (keyId, ECDHKeyType)
    remotePublicBytes  <- keyFunc (keyId, RemotePublicKeyType)
    localPrivate       <- return $ loadPrivateKey keyBytes
    localPublic        <- return $ getPublic localPrivate
    localPublicBytes   <- return $ fromPublicPoint localPublic
    ECDHKey <$> dhEncrypt keyId keyBytes localPublicBytes remotePublicBytes salt plaintext

  decrypt keyFunc (ECDHKey x) = dhDecrypt x keyFunc
