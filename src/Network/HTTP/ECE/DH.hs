{-# LANGUAGE OverloadedStrings #-}
module Network.HTTP.ECE.DH
       ( generateP256
       , makeSharedKey
       , curve
       , Network.HTTP.ECE.DH.getShared
       , cekInfo
       , loadPublicPoint
       , loadPrivateKey
       , PrivateNumber
       , PublicPoint
       , makeNonce ) where

import           Data.Binary.Put
import qualified Data.ByteArray             as ByteArray
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as BS
import           Data.ByteString.Lazy       (toStrict)
import           Data.Monoid

import           Crypto.Error               (eitherCryptoError,
                                             maybeCryptoError)
import           Crypto.Hash.Algorithms
import           Crypto.KDF.HKDF
import           Crypto.MAC.HMAC
import           Crypto.Number.Serialize
import           Crypto.PubKey.ECC.DH       as DH
import           Crypto.PubKey.ECC.Generate
import qualified Crypto.PubKey.ECC.P256     as P256
import           Crypto.PubKey.ECC.Types

curve :: Curve
curve = getCurveByName SEC_p256r1

getShared :: PrivateNumber
          -> PublicPoint
          -> ByteString
getShared priv pub =
  let (SharedKey key) = DH.getShared curve priv pub
  in i2osp key

generateP256 :: IO (PrivateNumber, PublicPoint)
generateP256 = do
  privatePoint <- generatePrivate curve
  let (Point x y) = calculatePublic curve privatePoint
      publicPoint = P256.pointFromIntegers (x, y)
  return (privatePoint, fromPoint publicPoint)

fromPoint :: P256.Point -> Point
fromPoint point = let (x, y) = P256.pointToIntegers point
                  in Point x y

-- | info parameter to used for HKDF
cekInfo :: ByteString -> ByteString
cekInfo context = "Content-Encoding: aesgcm128" <> "\x0" <> context

makeSharedKey :: ByteString -- ^ salt
              -> ByteString -- ^ input key material (shared key)
              -> ByteString -- ^ 128-bit AES key
makeSharedKey salt keyMaterial =
  let prk = extract salt keyMaterial :: PRK SHA256
  in expand prk (cekInfo "") 16

nonceInfo :: ByteString -> ByteString
nonceInfo context = "Content-Encoding: nonce" <> "\x0" <> context

-- | https://tools.ietf.org/html/draft-thomson-http-encryption-01#section-3.3
makeNonce :: ByteString -- ^ salt
          -> ByteString -- ^ input key material (shared key)
          -> ByteString -- ^ 128-bit AES key
makeNonce salt keyMaterial =
  let prk = extract salt keyMaterial :: PRK SHA256
  in expand prk (nonceInfo "") 12 <> BS.pack [0,0,0,0] -- 12 octect HKDF output <> 4 byte sequence number

trimIV :: ByteString -> Int -> ByteString
trimIV b ctr = let (mask, rest) = BS.splitAt 4 b
                   ctrBs = toStrict $ runPut $ putWord64be (fromIntegral ctr)
               in rest <> BS.pack (zipWith (^) (BS.unpack mask) (BS.unpack ctrBs))
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

loadPrivateKey :: ByteString -> PrivateNumber
loadPrivateKey = os2ip
