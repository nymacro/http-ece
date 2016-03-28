{-# LANGUAGE OverloadedStrings #-}
module Network.HTTP.ECE.DH
       ( generateP256
       , curve
       , Network.HTTP.ECE.DH.getShared
       , loadPublicPoint
       , loadPrivateKey
       , dhContext
       , PrivateNumber
       , PublicPoint ) where

import           Network.HTTP.ECE
import qualified Network.HTTP.ECE.Shared    as Shared
import           Network.HTTP.Types

import           Data.Binary.Put
import qualified Data.ByteArray             as ByteArray
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Base64.URL as UB64
import           Data.ByteString.Lazy       (toStrict)
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

curve :: Curve
curve = getCurveByName SEC_p256r1

-- | Generate ECDH shared secret
getShared :: PrivateNumber -- ^ sender private number
          -> PublicPoint   -- ^ recipient public point
          -> ByteString    -- ^ shared key bytes
getShared priv pub =
  let (SharedKey key) = DH.getShared curve priv pub
  in i2osp key

-- | Generate P256 pair
generateP256 :: IO (PrivateNumber, PublicPoint)
generateP256 = do
  privatePoint <- generatePrivate curve
  let (Point x y) = calculatePublic curve privatePoint
      publicPoint = P256.pointFromIntegers (x, y)
  return (privatePoint, fromPoint publicPoint)

-- | get public point from private
getPublic :: PrivateNumber -> PublicPoint
getPublic private = let (Point x y) = calculatePublic curve private
                    in fromPoint $ P256.pointFromIntegers (x, y)

-- | Convert P256.Point to Point type
fromPoint :: P256.Point -> Point
fromPoint point = let (x, y) = P256.pointToIntegers point
                  in Point x y

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

-- | Convert private number to bytestring
loadPrivateKey :: ByteString -> PrivateNumber
loadPrivateKey = os2ip

dhEncrypt :: Text       -- ^ keyid
          -> ByteString -- ^ private point
          -> ByteString -- ^ public key
          -> ByteString -- ^ recipient public key
          -> ByteString -- ^ salt
          -> ByteString -- ^ plaintext to encrypt
          -> Maybe ([Header], ByteString)
dhEncrypt keyId private public recipientPublic salt plaintext = do
  let headers    = [ ("Content-Encoding", "aesgcm")
                   , ("Encryption", encodeEncryptionParams [ ("keyid", Just keyId)
                                                           , ("salt", Just $ decodeUtf8 $ UB64.encode salt) ])
                   , ("Crypto-Key", encodeEncryptionParams [ ("keyid", Just keyId)
                                                           , ("dh", Just $ decodeUtf8 $ UB64.encode public) ]) ]
      privateNumber = loadPrivateKey private
      context    = dhContext (encodeUtf8 keyId) public recipientPublic
  recipient <- loadPublicPoint recipientPublic
  let secret     = Network.HTTP.ECE.DH.getShared privateNumber recipient
      hkdfKey    = Shared.makeSharedKey salt secret context
      hkdfSalt   = Shared.makeNonce salt secret context
  ciphertext <- Shared.encrypt hkdfKey hkdfSalt plaintext
  return (headers, ciphertext)

dhDecrypt :: ([Header], ByteString)
          -> (Text -> Maybe ByteString)
          -> Maybe ByteString
dhDecrypt (headers, ciphertext) retriever = do
  encryptionParams <- getHeader "Encryption" headers >>= decodeEncryptionParams . decodeUtf8
  cryptoKeyParams  <- getHeader "Crypto-Key" headers >>= decodeEncryptionParams . decodeUtf8
  keyId            <- getParam "keyid" encryptionParams
  salt             <- getParam "salt" encryptionParams
  dh               <- getParam "dh" cryptoKeyParams
  dhBytes          <- return . UB64.decodeLenient $ encodeUtf8 dh
  saltBytes        <- return . UB64.decodeLenient $ encodeUtf8 salt
  recipient        <- loadPublicPoint dhBytes
  privateBytes     <- retriever keyId
  private          <- return $ loadPrivateKey privateBytes
  publicPoint      <- return $ getPublic private
  public           <- return "" -- FIXME
  let secret   = Network.HTTP.ECE.DH.getShared private recipient
      context  = dhContext (encodeUtf8 keyId) public dhBytes
      hkdfKey  = Shared.makeSharedKey saltBytes secret context
      hkdfSalt = Shared.makeNonce saltBytes secret context
  Shared.decrypt hkdfKey hkdfSalt ciphertext
