{-# LANGUAGE OverloadedStrings #-}
module Network.HTTP.ECE ( ECEMethod (..)
                        , KeyStore
                        , newKeyStore
                        , addKey
                        , removeKey
                        , getKey
                        , Params
                        , decodeEncryptionParams
                        , encodeEncryptionParams
                        , getParam
                        , getHeader
                        , ContentEncoding (..)
                        , ECEKeyType (..) ) where

import           Control.Applicative   ((<|>))
import           Control.Monad         (filterM)

import           Network.HTTP.Types

import           Data.Attoparsec.Text
import           Data.ByteString       (ByteString)
import qualified Data.ByteString       as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.List             as List
import qualified Data.Map.Strict       as Map
import           Data.Monoid
import           Data.Text             hiding (filter, head, length, null,
                                        takeWhile)
import           Data.Text.Encoding    (decodeUtf8, encodeUtf8)

import           Prelude               hiding (takeWhile)

data ECEKeyType = ExplicitKeyType     -- shared key
                | ECDHKeyType         -- private ECDH private key
                | RemotePublicKeyType -- public ECDH key
                deriving (Eq, Ord)

data ECEMethod = ExplicitMethod
               | DHMethod
               | PreSharedMethod
               deriving (Eq, Ord)

-- | Key storage for lookup. Probably needs a typeclass.
type KeyStore = Map.Map (ECEMethod, ByteString) ByteString

newKeyStore :: KeyStore
newKeyStore = Map.empty

addKey :: (ECEMethod, ByteString) -> ByteString -> KeyStore -> KeyStore
addKey = Map.insert

removeKey :: (ECEMethod, ByteString) -> KeyStore -> KeyStore
removeKey = Map.delete

getKey :: (ECEMethod, ByteString) -> KeyStore -> Maybe ByteString
getKey = Map.lookup

-- TODO allow multi-params sets i.e. comma seperated
type Params = [(Text, Maybe Text)]

-- | parse encryption params header string
parseEncryptionParams :: Parser Params
parseEncryptionParams = do
  let alphaNumeric = inClass "A-Za-z0-9"
      parameterName = takeWhile1 alphaNumeric
      parameter = do
        name  <- parameterName
        let quoted    = char '"' *> (pack <$> manyTill anyChar (char '"'))
            unquoted  = takeWhile1 (/= ';')
            withValue = char '=' *> (Just <$> choice [ quoted, unquoted ])
            noValue   = return Nothing
        value <- choice [ withValue, noValue ]
        return (name, value)
  sepBy1 parameter (char ';' <* skipSpace)

-- | parse encryption params header string
decodeEncryptionParams :: Text -> Maybe Params
decodeEncryptionParams = toMaybe . parseOnly parseEncryptionParams

toMaybe :: Either a b -> Maybe b
toMaybe x = case x of
              Right z -> Just z
              Left _  -> Nothing

getParam :: Text -> Params -> Maybe Text
getParam key params =
  let matches = filter (\x -> fst x == key) params
  in if null matches || length matches > 1
     then Nothing
     else snd $ head matches

encodeEncryptionParams :: Params -> ByteString
encodeEncryptionParams = mconcat . List.intersperse seperator . fmap paramPairToString
  where seperator = "; " :: ByteString
        paramPairToString (key, value) =
          encodeUtf8 $ case value of
                         Just v  -> key <> "=" <> "\"" <> v <> "\""
                         Nothing -> key

-- | get first header with specific name
getHeader :: HeaderName -> [Header] -> Maybe ByteString
getHeader key header =
  case filter (\x -> fst x == key) header of
    []         -> Nothing
    (_, v) : _ -> Just v

-- | Content encoding type
class ContentEncoding a where
  encrypt :: Text                      -- ^ key id
          -> ((Text, ECEKeyType) -> Maybe ByteString) -- ^ key retrieval func
          -> ByteString                -- ^ salt
          -> ByteString                -- ^ plaintext
          -> Maybe (a ([Header], ByteString))

  decrypt :: ((Text, ECEKeyType) -> Maybe ByteString) -- ^ key retrieval func
          -> a ([Header], ByteString)  -- ^ output from encrypt
          -> Maybe ByteString
