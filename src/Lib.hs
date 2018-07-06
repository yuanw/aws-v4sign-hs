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
import           Network.HTTP.Client
import           Network.HTTP.Simple
import           Network.HTTP.Types
import           Network.HTTP.Types.Header
import           Network.HTTP.Types.Method

headers :: Request -> [Header]
headers req = sortBy (\(a,_) (b,_) -> compare a b) (("host", host req) : requestHeaders req)

canonicalHeaders :: Request -> ByteString
canonicalHeaders req = C.concat $ map (\(hn,hv) -> bsToLower (original hn) <> ":" <> hv <> "n") hs
    where hs = headers req

isChunckRequestBody :: RequestBody -> Bool
isChunckRequestBody (RequestBodyLBS _)       = False
isChunckRequestBody (RequestBodyBS _)        = False
isChunckRequestBody (RequestBodyBuilder _ _) = False
isChunckRequestBody _                        = True

isChunckRequest :: Request -> Bool
isChunckRequest = isChunckRequestBody . requestBody

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
