{-# LANGUAGE OverloadedStrings #-}
module DHSpec where

import           Control.Applicative
import           Control.Monad
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Base16     as B16
import qualified Data.ByteString.Base64.URL as UB64
import           Data.Monoid

import           Crypto.PubKey.ECC.Types

import           Network.HTTP.ECE.DH
import qualified Network.HTTP.ECE.Key       as Key
import qualified Network.HTTP.ECE.Shared    as Shared

import qualified Data.CaseInsensitive       as CI
import           Test.Hspec

spec :: Spec
spec = do
  describe "ECDH" $ do
    describe "Example" $ do
      let --receiver
          receiverPrivate = UB64.decodeLenient "9FWl15_QUQAWDaD3k3l50ZBZQJ4au27F1V4F0uLSD_M"
          receiverPublic  = UB64.decodeLenient "BCEkBjzL8Z3C-oi2Q7oE5t2Np-p7osjGLg93qUP0wvqRT21EEWyf0cQDQcakQMqz4hQKYOQ3il2nNZct4HgAUQU"
          -- sender
          senderPrivate   = UB64.decodeLenient "vG7TmzUX9NfVR4XUGBkLAFu8iDyQe-q_165JkkN0Vlw"
          senderPublic    = UB64.decodeLenient "BDgpRKok2GZZDmS4r63vbJSUtcQx4Fq1V58-6-3NbZzSTlZsQiCEDTQy3CZ0ZMsqeqsEb7qW2blQHA4S48fynTk"
          -- shared
          salt            = UB64.decodeLenient "Qg61ZJRva_XBE9IEUelU3A"
          ciphertext      = UB64.decodeLenient "yqD2bapcx14XxUbtwjiGx69eHE3Yd6AqXcwBpT2Kd1uy"

      -- using hex string created from python `base64.b16encode(base64.urlsafe_b64decode("b64")`
      it "should decode receiver private key correctly" $ do
        CI.mk (B16.encode receiverPrivate) `shouldBe` CI.mk "F455A5D79FD05100160DA0F7937979D19059409E1ABB6EC5D55E05D2E2D20FF3"

      it "should decode receiver public key correctly" $ do
        CI.mk (B16.encode receiverPublic) `shouldBe` CI.mk "042124063CCBF19DC2FA88B643BA04E6DD8DA7EA7BA2C8C62E0F77A943F4C2FA914F6D44116C9FD1C40341C6A440CAB3E2140A60E4378A5DA735972DE078005105"

      it "should decode sender private key correctly" $ do
        CI.mk (B16.encode senderPrivate) `shouldBe` CI.mk "BC6ED39B3517F4D7D54785D418190B005BBC883C907BEABFD7AE49924374565C"

      it "should decode sender public key correctly" $ do
        CI.mk (B16.encode senderPublic) `shouldBe` CI.mk "04382944AA24D866590E64B8AFADEF6C9494B5C431E05AB5579F3EEBEDCD6D9CD24E566C4220840D3432DC267464CB2A7AAB046FBA96D9B9501C0E12E3C7F29D39"

      it "should decode salt correctly" $ do
        BS.length salt `shouldBe` 16
        salt `shouldBe` fst (B16.decode "420EB564946F6BF5C113D20451E954DC")

      it "should be able to load ECDH public point" $ do
        loadPublicPoint receiverPublic `shouldBe` Just (Point 14989973547132483796075281743893317665735935508759067642703581770435703011985
                                                               35925771156649037060116354393398966215775747835714497586449615447746272055557)

    describe "Appendix B" $ do
      -- FIXME.. This doesn't match, which is a big bad bad
      let senderPublic    = loadPublicPoint senderPublicB
          senderPublicB   = UB64.decodeLenient "BNoRDbb84JGm8g5Z5CFxurSqsXWJ11ItfXEWYVLE85Y7CYkDjXsIEc4aqxYaQ1G8BqkXCJ6DPpDrWtdWj_mugHU"
          senderPrivate   = loadPrivateKey  $ UB64.decodeLenient "nCScek-QpEjmOOlT-rQ38nZzvdPlqa00Zy0i6m2OJvY"
          receiverPublic  = loadPublicPoint receiverPublicB
          receiverPublicB = UB64.decodeLenient "BCEkBjzL8Z3C-oi2Q7oE5t2Np-p7osjGLg93qUP0wvqRT21EEWyf0cQDQcakQMqz4hQKYOQ3il2nNZct4HgAUQU"
          receiverPrivate = loadPrivateKey  $ UB64.decodeLenient "9FWl15_QUQAWDaD3k3l50ZBZQJ4au27F1V4F0uLSD_M"
          salt            = UB64.decodeLenient "lngarbyKfMoi9Z75xYXmkg"
          -- expected values
          -- sharedSecret    = UB64.decodeLenient "RNjC-NVW4BGJbxWPW7G2mowsLeDa53LYKYm4-NOQ6Y" -- 44D8C2F8D556E011896F158F5BB1B69A8C2C2DE0DAE772D82989B8F8D390E9
          (sharedSecret, _)  = B16.decode "44D8C2F8D556E011896F158F5BB1B69A8C2C2DE0DAE772D82989B8F8D390E9"

      it "should generate correct CEK Info" $ do
        let label = "P-256"
        Shared.cekInfo (dhContext label senderPublicB receiverPublicB) `shouldBe` UB64.decodeLenient "Q29udGVudC1FbmNvZGluZzogYWVzZ2NtAFAtMjU2AABBBCEkBjzL8Z3C-oi2Q7oE5t2Np-p7osjGLg93qUP0wvqRT21EEWyf0cQDQcakQMqz4hQKYOQ3il2nNZct4HgAUQUAQQTaEQ22_OCRpvIOWeQhcbq0qrF1iddSLX1xFmFSxPOWOwmJA417CBHOGqsWGkNRvAapFwiegz6Q61rXVo_5roB1"

      it "should generate correct shared key" $ do
        BS.length sharedSecret `shouldBe` 32
        getShared senderPrivate <$> receiverPublic `shouldBe` Just sharedSecret
        getShared receiverPrivate <$> senderPublic `shouldBe` Just sharedSecret

    describe "Misc" $ do
      it "should be able to generate shared point" $ do
        (privateNumber1, publicPoint1) <- generateP256
        (privateNumber2, publicPoint2) <- generateP256
        getShared privateNumber1 publicPoint2 `shouldBe` getShared privateNumber2 publicPoint1

      it "should be able to create shared key" $ do
        (privateNumber1, publicPoint1) <- generateP256
        (privateNumber2, publicPoint2) <- generateP256
        salt <- Key.generateSalt
        let cekInfo = Shared.cekInfo ""
            nonceInfo = Shared.nonceInfo ""
            share1 = getShared privateNumber1 publicPoint2
            share2 = getShared privateNumber2 publicPoint1
            key1 = Shared.makeSharedKey salt share1 cekInfo
            nonce1 = Shared.makeNonce salt share1 nonceInfo
            key2 = Shared.makeSharedKey salt share2 cekInfo
            nonce2 = Shared.makeNonce salt share2 nonceInfo

        key1 `shouldBe` key2
        nonce1 `shouldBe` nonce2

        let plaintext = "Hello World" :: ByteString
            encrypted1 = Shared.encrypt key1 nonce1 plaintext
            encrypted2 = Shared.encrypt key2 nonce2 plaintext

        (Shared.decrypt key2 nonce2 =<< encrypted1) `shouldBe` Just plaintext
        (Shared.decrypt key1 nonce1 =<< encrypted2) `shouldBe` Just plaintext

      it "should encrypt/decrypt" $ do
        (private, public)   <- generateP256 -- client
        (private', public') <- generateP256 -- server
        salt <- Key.generateSalt
        let label     = "P-256"
            privateB  = fromPrivateKey private
            publicB   = fromPublicPoint public
            privateB' = fromPrivateKey private'
            publicB'  = fromPublicPoint public'
            encrypted = dhEncrypt label privateB' publicB' publicB salt "I am the walrus"
        (flip dhDecrypt (const $ Just privateB) =<< encrypted) `shouldBe` Just "I am the walrus"

