{-# LANGUAGE OverloadedStrings #-}
module Network.HTTP.ECE.DH
       ( generateP256
       , curve
       , Network.HTTP.ECE.DH.getShared
       , cekContext
       , loadPublicPoint
       , loadPrivateKey
       , PrivateNumber
       , PublicPoint ) where

import           Data.Binary.Put
import qualified Data.ByteArray             as ByteArray
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as BS
import           Data.ByteString.Lazy       (toStrict)
import           Data.Monoid

import           Crypto.Error               (eitherCryptoError,
                                             maybeCryptoError)
import           Crypto.Number.Serialize
import           Crypto.PubKey.ECC.DH       as DH
import           Crypto.PubKey.ECC.Generate
import qualified Crypto.PubKey.ECC.P256     as P256
import           Crypto.PubKey.ECC.Types

import qualified Network.HTTP.ECE.Shared    as Shared

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

-- | Content Encryption Key context
cekContext :: ByteString -> ByteString -> ByteString -> ByteString
cekContext label senderPublic recipientPublic =
  label <> "\x0"
    <> (toStrict . runPut $ putWord16be $ fromIntegral $ BS.length recipientPublic)
    <> recipientPublic
    <> (toStrict . runPut $ putWord16be $ fromIntegral $ BS.length senderPublic)
    <> senderPublic

nonceContext = cekContext

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
