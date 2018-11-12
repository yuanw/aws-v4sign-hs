{-# LANGUAGE OverloadedStrings #-}

module Lib where

import           Crypto.Hash               (Digest, SHA256, hash)
import           Crypto.MAC.HMAC           (hmac, hmacGetDigest)
import           Data.ByteString           (ByteString)
import qualified Data.ByteString.Base16    as B16 (encode)
import qualified Data.ByteString.Char8     as C
import           Data.CaseInsensitive      (original)
import           Data.Char                 (toLower)
import           Data.List                 (intersperse, lines, sortBy, sortOn)
import           Data.Maybe
import           Data.Monoid               ((<>))
import           Data.Time.Clock           (UTCTime)
import           Data.Time.Format          (FormatTime, defaultTimeLocale,
                                            formatTime)
import           Network.HTTP.Client
import           Network.HTTP.Simple
import           Network.HTTP.Types
import           Network.HTTP.Types.Header
import           Network.HTTP.Types.Method


--get request's headers and re
headers :: Request -> [Header]
headers req = sortBy (\(a,_) (b,_) -> compare a b) (("host", host req) : requestHeaders req)

canonicalHeaders :: Request -> ByteString
canonicalHeaders req = C.concat $ map (\(hn,hv) -> bsToLower (original hn) <> ":" <> hv <> "\n") hs
    where hs = headers req


canonicalQueryString :: Request -> ByteString
canonicalQueryString = renderQuery False . sortOn fst . parseQuery . queryString

canonicalRequest :: Request -> ByteString -> ByteString
canonicalRequest req body = C.concat $
        intersperse "\n"
            [ method req
            , path req
            , canonicalQueryString req
            , canonicalHeaders req
            , signedHeaders req
            , hexHash body
            ]

bsToLower :: ByteString -> ByteString
bsToLower = C.map toLower

hexHash :: ByteString -> ByteString
hexHash p = (C.pack . show) (hash p :: Digest SHA256)

signedHeaders :: Request -> ByteString
signedHeaders req = C.concat . intersperse ";"  $ map (\(hn,_) -> bsToLower (original hn)) hs
    where hs = headers req


-- Create a String to Sign for Signature Version 4

format :: UTCTime -> String
format = formatTime defaultTimeLocale "%Y%m%d"

formatAmzDate :: UTCTime -> String
formatAmzDate = formatTime defaultTimeLocale "%Y%m%dT%H%M%SZ"

stringToSign :: UTCTime    -> -- ^ current time
    ByteString -> -- ^ The AWS region
    ByteString -> -- ^ The AWS service
    ByteString -> -- ^ Hashed canonical request
    ByteString
stringToSign date region service hashConReq = C.concat
    [ "AWS4-HMAC-SHA256\n"
    , C.pack (formatAmzDate date) , "\n"
    , C.pack (format date) , "/"
    , region , "/"
    , service
    , "/aws4_request\n"
    , hashConReq
    ]


--- Task 3: Calculate the signature for AWS Signature Version 4
--- https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html ---
-- https://www.fpcomplete.com/blog/2017/09/cryptographic-hashing-haskell --
v4DerivedKey :: ByteString -> -- ^ AWS Secret Access Key
    ByteString -> -- ^ Date in YYYYMMDD format
    ByteString -> -- ^ AWS region
    ByteString -> -- ^ AWS service
    ByteString
v4DerivedKey secretAccessKey date region service = hmacSHA256 kService "aws4_request"
    where kDate = hmacSHA256 ("AWS4" <> secretAccessKey) date
          kRegion = hmacSHA256 kDate region
          kService = hmacSHA256 kRegion service


hmacSHA256 :: ByteString -> ByteString -> ByteString
hmacSHA256 key p = (C.pack . show) (hmacGetDigest $ hmac key p :: Digest SHA256)


--task 4: add the signature to the HTTP request
--https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
