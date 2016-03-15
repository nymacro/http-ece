{-# LANGUAGE OverloadedStrings #-}
module MiscSpec where

import qualified Data.ByteArray             as ByteArray
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as BS
import           Data.Monoid

import           Crypto.Cipher.AES
import           Crypto.Cipher.Types
import           Crypto.Error               (eitherCryptoError,
                                             maybeCryptoError)
import           Crypto.Hash.Algorithms
import           Crypto.KDF.HKDF
import           Crypto.MAC.HMAC
import           Crypto.Number.Serialize
-- import           Crypto.PubKey.ECC.DH
-- import           Crypto.PubKey.ECC.Generate
-- import qualified Crypto.PubKey.ECC.P256     as P256
-- import           Crypto.PubKey.ECC.Types

import qualified Data.ByteString.Base64.URL as UB64

import           Test.Hspec

import           Network.HTTP.ECE.DH

-- FIXME fixed salt
-- salt :: ByteString
-- salt = "                "

-- reciever
xPrivateKeyClient = UB64.decodeLenient "iCjNf8v4ox_g1rJuSs_gbNmYuUYx76ZRruQs_CHRzDg"
xPublicKeyClient  = UB64.decodeLenient "BPM1w41cSD4BMeBTY0Fz9ryLM-LeM22Dvt0gaLRukf05rMhzFAvxVW_mipg5O0hkWad9ZWW0uMRO2Nrd32v8odQ"

-- sender
xPrivateKeyServer = UB64.decodeLenient "W0cxgeHDZkR3uMQYAbVgF5swKQUAR7DgoTaaQVlA-Fg"
xPublicKeyServer  = UB64.decodeLenient "BLsyIPbDn6bquEOwHaju2gj8kUVoflzTtPs_6fGoock_dwxi1BcgFtObPVnic4alcEucx8I6G8HmEZCJnAl36Zg"

salt = UB64.decodeLenient "5hpuYfxDzG6nSs9-EQuaBg"
xCiphertext = UB64.decodeLenient "BmuHqRzdD4W1mibxglrPiRHZRSY49Dzdm6jHrWXzZrE"

spec :: Spec
spec = do
  describe "Misc" $ do
    it "misc tests" $ do
      misc

misc :: IO ()
misc = do
  -- (privateNumber1, publicPoint1) <- generateP256
  -- (privateNumber2, publicPoint2) <- generateP256

  -- let (SharedKey sharedKey1) = getShared curve privateNumber1 publicPoint2
  --     (SharedKey sharedKey2) = getShared curve privateNumber2 publicPoint1

  -- putStrLn ""

  -- print privateNumber1
  -- print privateNumber2

  -- print sharedKey1
  -- print sharedKey2

  -- -- make AES key
  -- let key1 = makeSharedKey salt (i2osp sharedKey1)
  --     key2 = makeSharedKey salt (i2osp sharedKey2)

  -- print key1
  -- print key2

  -- let encrypted1 = Main.encrypt key1 "Hello World"
  --     decrypted1 = decrypt key2 encrypted1
  -- print encrypted1
  -- print decrypted1

  -- SERVER SIDE
  -- (privateNumberServer, publicPointServer) <- generateP256
  let privateServer' = xPrivateKeyServer
      privateNumberServer = os2ip privateServer'
  -- let publicPointServer' = BS.drop 1 xPublicKeyServer
  --     Just (x, y) = P256.pointToIntegers <$> maybeCryptoError (P256.pointFromBinary publicPointServer')
  --     publicPointServer = Point x y
  let Just publicPointServer = loadPublicPoint xPublicKeyServer

  -- load up client point
  let Just publicPointClient = loadPublicPoint xPublicKeyClient

  -- get shared key
  let clientShared = getShared privateNumberServer publicPointClient
      sharedKey = makeSharedKey salt clientShared
      nonce = getNonce salt sharedKey


  let encrypted = encrypt sharedKey nonce "I am the walrus"

  print ""
  print salt
  print ""
  print encrypted
  print "expected: "
  print xCiphertext

  -- CLIENT SIDE
  -- reuse server public point from above

  -- load up client private
  let privateNumberClient = loadPrivateKey xPrivateKeyClient
      -- REUSE CLIENT POINT FROM ABOVE
      -- publicPointClient

  -- get shared key
  let serverShared = getShared privateNumberClient publicPointClient
      sharedKey' = makeSharedKey salt serverShared

  let decrypted = decrypt sharedKey' nonce encrypted
  print decrypted

  putStrLn ""
