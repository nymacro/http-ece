module Network.HTTP.ECE where

import           Data.Attoparsec.ByteString.Char8
import           Data.ByteString                  (ByteString)
import           Prelude                          hiding (takeWhile)

type Params = [(ByteString, ByteString)]

parseEncryptionParams :: Parser [ByteString]
parseEncryptionParams = do
  let parameter = do
        takeWhile (\c -> isAlpha_ascii c && c /= ';')
  sepBy1 parameter (char ';')

-- parseEncryptionParams' :: Parser [(ByteString, Maybe ByteString)]
-- parseEncryptionParams' = do
--   let parameter = do
--         takeWhile (isAlpha_ascii && char ';')
--   sepBy1 parameter (char ';')

getParam :: Params -> ByteString -> Maybe ByteString
getParam params key =
  let matches = filter (\x -> fst x == key) params
  in if null matches || length matches > 1
     then Nothing
     else Just $ snd $ head matches

-- getParams :: Params -> ByteString -> Maybe Params
-- getParams

class ContentEncoding a where
  encrypt :: ByteString
          -> ByteString
          -> ByteString
          -> a (Params, ByteString)

  decrypt :: (Params, ByteString)
          -> a (Maybe ByteString)
