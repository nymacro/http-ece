{-# LANGUAGE OverloadedStrings #-}
module Network.HTTP.ECE where

import           Control.Applicative   ((<|>))
import           Data.Attoparsec.Text
import           Data.ByteString       (ByteString)
import qualified Data.ByteString       as BS
import qualified Data.ByteString.Char8 as BSC
import           Data.Text             hiding (filter, head, length, null,
                                        takeWhile)
import           Data.Text.Encoding    (decodeUtf8, encodeUtf8)
import           Prelude               hiding (takeWhile)

type Params = [(Text, Maybe Text)]

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

decodeEncryptionParams :: Text -> Either String Params
decodeEncryptionParams = parseOnly parseEncryptionParams

getParam :: Params -> Text -> Maybe Text
getParam params key =
  let matches = filter (\x -> fst x == key) params
  in if null matches || length matches > 1
     then Nothing
     else snd $ head matches

-- getParams :: Params -> ByteString -> Maybe Params
-- getParams

class ContentEncoding a where
  encrypt :: ByteString
          -> ByteString
          -> ByteString
          -> Maybe (a (Params, ByteString))

  decrypt :: (Params, ByteString)
          -> Maybe (a (Maybe ByteString))
