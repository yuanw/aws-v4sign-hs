{-# LANGUAGE OverloadedStrings #-}

import qualified   Data.ByteString as BS
import             Data.Maybe
import             Lib
import             Network.HTTP.Client
import             Network.HTTP.Simple
import             Network.HTTP.Types
import             Network.HTTP.Types.Header
import             Network.HTTP.Types.Method
import             Test.Hspec
import qualified   Control.Monad.Fail as Fail
import             Data.Time.Clock           (UTCTime)
import             Data.Time.Format (parseTimeM, defaultTimeLocale)
import             Data.Time.LocalTime (ZonedTime, zonedTimeToUTC)
import             Control.Monad.Catch (MonadThrow)

targetRequestM :: MonadThrow m => m Request
targetRequestM = do
    initReq <- parseUrlThrow "https://iam.amazonaws.com"
    let req = setRequestQueryString [("Action", Just "ListUsers"), ("Version", Just "2010-05-08")] initReq
                { requestHeaders =
                    [ ("X-Amz-Date", "20150830T123600Z"),
                      ("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")]
                }
    return req


--TODO: check whether ByteString endwith \n
readTestFile :: FilePath -> IO BS.ByteString
readTestFile path = do
  content <- BS.readFile path
  return $ BS.take ((BS.length content) -1) content

parseUTCTime :: Fail.MonadFail m => m UTCTime
parseUTCTime = zonedTimeToUTC <$> (parseTimeM False defaultTimeLocale "%Y%m%dT%H%M%S" "20150830T123600")


main :: IO ()
main = hspec $ do
  describe "canonicalRequest" $ do
    it "task 1" $ do
        expectedContent <- readTestFile "data/example.txt"
        request <- targetRequestM
        (canonicalRequest request "") `shouldBe` expectedContent

    it "hashed canonical request" $ do
      request <- targetRequestM
      hexHash (canonicalRequest request "") `shouldBe` "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"

    it "string to sign" $ do
      utcTime <- parseUTCTime
      expectedContent <- readTestFile "data/stringToSign.txt"
      stringToSign utcTime "us-east-1" "iam" "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59" `shouldBe` expectedContent

    it "calculate the signaute" $ do
      v4DerivedKey "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY." "20150830" "us-east-1" "iam" `shouldBe` "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
