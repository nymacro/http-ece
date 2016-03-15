{-# LANGUAGE OverloadedStrings #-}
module DHSpec where

import qualified Data.ByteString            as BS
import           Network.HTTP.ECE.DH
import           Test.Hspec

import           Crypto.PubKey.ECC.Types

import qualified Data.ByteString.Base16     as B16
import qualified Data.ByteString.Base64.URL as UB64

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
  describe "HTTP Encrypted-Content-Encoding" $ do
    describe "Decoding" $ do
      it "should decode receiver private key correctly" $ do
        B16.encode xPrivateKeyClient `shouldBe` "D3332E1CF749C05AA776927EF348C650000596714F33B91205FB8921C451DBB4"

      it "should decode receiver private key correctly" $ do
        B16.encode xPublicKeyClient `shouldBe` "044C4B524E06F633FE96CC68FE73A0952522777F1C3F23B360EDF066BA9531AF08EB2F9D8003B83DE3AE3BEB9BEE0A5CB9B3395A1987B980176CC30B517E06A45B"

      it "should decode sender private key correctly" $ do
        B16.encode xPrivateKeyServer `shouldBe` "4E5C131EDD75E64538C4ACF50629179F4F3FB03AD5EB5BAD4FEBF437E8AC483E"

      it "should decode sender private key correctly" $ do
        B16.encode xPublicKeyServer `shouldBe` "045A327A3192C8DC76D27FEF82694DC04E9AD060AF85DD931C281BC3A440EA15613C3670B7C06021D31CFABA81A827CC5E39E26F77C070C05F3C25E4DF7157D08F"

      it "correct salt len" $ do
        BS.length salt `shouldBe` 16
        salt `shouldBe` fst (B16.decode "E61A6E61FC43CC6EA74ACF7E110B9A06")
        -- BS.length (UB64.decodeLenient salt) `shouldBe` 16

    it "should be able to generate shared point" $ do
      (privateNumber1, publicPoint1) <- generateP256
      (privateNumber2, publicPoint2) <- generateP256
      getShared privateNumber1 publicPoint2 `shouldBe` getShared privateNumber2 publicPoint1

    it "should be able to create shared key" $ do
      (privateNumber1, publicPoint1) <- generateP256
      (privateNumber2, publicPoint2) <- generateP256
      let share1 = getShared privateNumber1 publicPoint2
          share2 = getShared privateNumber2 publicPoint1
          key1 = makeSharedKey salt share1
          nonce1 = getNonce salt share1
          key2 = makeSharedKey salt share2
          nonce2 = getNonce salt share2

      key1 `shouldBe` key2
      nonce1 `shouldBe` nonce2

      let encrypted1 = encrypt key1 nonce1 plaintext
          encrypted2 = encrypt key2 nonce2 plaintext
          plaintext = "Hello World"

      decrypt key2 nonce2 encrypted1 `shouldBe` Just plaintext
      decrypt key1 nonce1 encrypted2 `shouldBe` Just plaintext

    -- it "should generate the correct nonce" $ do
    --   let priv1 = loadPrivateKey xPrivateKeyClient
    --       pub1  = loadPublicPoint xPublicKeyClient
    --       priv2 = loadPrivateKey xPrivateKeyServer
    --       pub2  = loadPublicPoint xPublicKeyServer
    --       share = getShared priv1 <$> pub2

    it "should be able to load ECDH public point" $ do
      loadPublicPoint xPublicKeyClient `shouldBe` Just (Point 110007014751775540525562297837608235252671747216779544670154428477160159313209
                                                              78151973610564024074054410620959345729707977195367740423366101443779682410964)
