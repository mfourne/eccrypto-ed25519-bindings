-----------------------------------------------------------------------------
-- |
-- Module      :  Crypto.Sign.Ed25519
-- Copyright   :  (c) Marcel Fourné 20[19..]
-- License     :  BSD3
-- Maintainer  :  Marcel Fourné (haskell@marcelfourne.de)
-- Stability   :  stable
-- Portability :  Good
--
-- original implementation of this API is by Austin Seipp and can be found under: https://hackage.haskell.org/package/ed25519
--
-----------------------------------------------------------------------------

{-# LANGUAGE Safe #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.Sign.Ed25519
       (
         PublicKey(..)
       , SecretKey(..)
       , createKeypair
       , createKeypairFromSeed_
       , createKeypairFromSeed
       , toPublicKey

       , sign
       , verify

       , Signature(..)
       , dsign
       , dverify

       , sign'
       , verify'

       ) where

import safe Prelude (Eq,Show, Ord, IO, Either(Right,Left), Maybe, Bool, return, undefined, error, (==))
import safe GHC.Generics (Generic)
import safe qualified Crypto.ECC.Ed25519.Sign as S
import safe qualified Crypto.ECC.Ed25519.Internal.Ed25519 as I
import safe qualified Data.ByteString as BS

-- | http://hackage.haskell.org/package/ed25519-0.0.5.0/docs/Crypto-Sign-Ed25519.html
newtype PublicKey = PublicKey { unPublicKey :: BS.ByteString
                              }
        deriving (Eq, Show, Ord, Generic)

-- | http://hackage.haskell.org/package/ed25519-0.0.5.0/docs/Crypto-Sign-Ed25519.html
newtype SecretKey = SecretKey { unSecretKey :: BS.ByteString
                              }
        deriving (Eq, Show, Ord, Generic)

-- | http://hackage.haskell.org/package/ed25519-0.0.5.0/docs/Crypto-Sign-Ed25519.html
createKeypair :: IO (PublicKey, SecretKey)
createKeypair = do
  a <- S.genkeys
  case a of
    Right (I.SecKeyBytes sk, pk) -> return (PublicKey pk, SecretKey sk)
    Left e -> error e

-- | http://hackage.haskell.org/package/ed25519-0.0.5.0/docs/Crypto-Sign-Ed25519.html
createKeypairFromSeed_ :: BS.ByteString -> Maybe (PublicKey, SecretKey)
createKeypairFromSeed_ = undefined

-- | http://hackage.haskell.org/package/ed25519-0.0.5.0/docs/Crypto-Sign-Ed25519.html
createKeypairFromSeed :: BS.ByteString -> (PublicKey, SecretKey)
createKeypairFromSeed = undefined

-- | http://hackage.haskell.org/package/ed25519-0.0.5.0/docs/Crypto-Sign-Ed25519.html
toPublicKey  :: SecretKey -> PublicKey
toPublicKey sk = let (SecretKey sk') = sk
                     sk'' = I.SecKeyBytes sk'
                     a = S.publickey sk''
  in case a of
       Right pk -> PublicKey pk
       Left e -> error e

-- | http://hackage.haskell.org/package/ed25519-0.0.5.0/docs/Crypto-Sign-Ed25519.html
sign :: SecretKey -> BS.ByteString -> BS.ByteString
sign sk m = let SecretKey sk' = sk
                a = S.sign (I.SecKeyBytes sk') m
            in case a of
                 Right sigm -> sigm
                 Left e -> error e

-- | http://hackage.haskell.org/package/ed25519-0.0.5.0/docs/Crypto-Sign-Ed25519.html
verify :: PublicKey -> BS.ByteString -> Bool
verify pk m = let PublicKey pk' = pk
              in S.verify pk' m == Right I.SigOK

-- | http://hackage.haskell.org/package/ed25519-0.0.5.0/docs/Crypto-Sign-Ed25519.html
newtype Signature = Signature { unSignature :: BS.ByteString
                              }
        deriving (Eq, Show, Ord)

-- | http://hackage.haskell.org/package/ed25519-0.0.5.0/docs/Crypto-Sign-Ed25519.html
dsign :: SecretKey -> BS.ByteString -> Signature
dsign sk m = let SecretKey sk' = sk
                 a = S.dsign (I.SecKeyBytes sk') m
             in case a of
                  Right sig -> Signature sig
                  Left e -> error e

-- | http://hackage.haskell.org/package/ed25519-0.0.5.0/docs/Crypto-Sign-Ed25519.html
dverify :: PublicKey -> BS.ByteString -> Signature -> Bool
dverify pk m sig = let PublicKey pk' = pk
                       Signature sig' = sig
                   in S.dverify pk' sig' m == Right I.SigOK

-- | http://hackage.haskell.org/package/ed25519-0.0.5.0/docs/Crypto-Sign-Ed25519.html
sign' :: SecretKey -> BS.ByteString -> Signature
sign' sk m = dsign sk m

-- | http://hackage.haskell.org/package/ed25519-0.0.5.0/docs/Crypto-Sign-Ed25519.html
verify' :: PublicKey -> BS.ByteString -> Signature -> Bool
verify' pk m sig = dverify pk m sig
