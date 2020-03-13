-----------------------------------------------------------------------------
-- |
-- Module      :
-- Copyright   :  (c) Marcel Fourné 20[09..19]
-- License     :  BSD3
-- Maintainer  :  Marcel Fourné (haskell@marcelfourne.de)
--
-- benchmarking playground, not production quality
-- recommended:
-- $ ghc --make -O2 -feager-blackholing -fforce-recomp -fllvm -threaded bench.hs
-- best performance measured with just 1 thread
--
-----------------------------------------------------------------------------

{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE PackageImports #-}


import Crypto.ECC.Ed25519.Sign
import Crypto.ECC.Ed25519.Internal.Ed25519
import qualified Crypto.Fi as FP
import qualified Data.ByteString.Char8 as C8
import Data.Char(chr,ord)
import qualified "ed25519" Crypto.Sign.Ed25519 as R
import qualified "eccrypto-ed25519-bindings" Crypto.Sign.Ed25519 as RN
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import System.Environment
import qualified Crypto.Fi as FP

main::IO ()
main = do
  putStrLn "\ngenerate keys with homegrown code"
  let m = BS.pack [0..255]
  putStrLn $ "message m is: " ++ (show m)
  Right (SecKeyBytes sk2,pk2) <- genkeys
  let rsk2 = R.SecretKey (BS.append sk2 pk2)
      rpk2 = R.PublicKey pk2
  putStrLn $ "manual key format equal to generated: " ++ (show (R.toPublicKey rsk2 == rpk2))
  let sig2 = R.dsign rsk2 m
  putStrLn $ "sig from foreign code: " ++ (show sig2)
  putStrLn $ "sig with foreign re-generated key is ok: " ++ (show (R.dverify rpk2 m sig2))
  let Right mypk2 = bstopoint pk2
      Right mysk2 = bstopoint sk2
  putStrLn $ "own generated public key point is on curve: " ++ (show $ ison mypk2)
  putStrLn "\n___tests with foreign keys___"
  putStrLn "generate keys with foreign code"
  (R.PublicKey pk,sk) <- R.createKeypair
  print sk
  -- let skre = bstopoint (BS.take 32 $ R.unSecretKey sk)
  -- print $ show skre
  print pk
  let Right pkre = bstopoint pk
  putStrLn $ "pk re-encode sieht aus:  " ++ (show $ pointtobs pkre)
  putStrLn $ "pk regenerate:     " ++ (show $ publickey (SecKeyBytes (R.unSecretKey sk)))
  let (R.Signature sig) = R.dsign sk m
  print sig
  putStrLn $ "Sig ist ok? " ++ (show $ R.dverify (R.PublicKey pk) m (R.Signature sig))
  putStrLn $ "Sig ist ok, crosstest? " ++ (show $ RN.dverify (RN.PublicKey pk) m (RN.Signature sig))
  let sig0 = dsign (SecKeyBytes (BS.take 32 (R.unSecretKey sk))) m
  putStrLn $ "nachgebaute sig:   " ++ (show sig0)
  case sig0 of
    Right s -> do
      putStrLn $ "Sig ist ok? " ++ (show $ RN.dverify (RN.PublicKey pk) m (RN.Signature s))
      putStrLn $ "Sig ist ok, crosstest? " ++ (show $ R.dverify (R.PublicKey pk) m (R.Signature s))
    Left e -> print e
{-
  putStrLn "___reverse engineer parts from other libs___"
  let skfix = C8.pack "\216\199\155q3>v(\248 \152Y=M\180\132\251R\DC4\154\ENQ\EOT\150\GS\NULM'\235OR\204\226n\147\170~W\146\US\139\222\255@\158\196\183\237zm\RSq\174R\210\240\233\ESC\134n\229\186\172\GSX"
      pkfix = C8.pack "n\147\170~W\146\US\139\222\255@\158\196\183\237zm\RSq\174R\210\240\233\ESC\134n\229\186\172\GSX"
      sigfix = C8.pack "\176\165\170\235t_k\220\CAN\153lQ\240\188\152\134\234_\182\129\141\206\213\&1\FS\140\253\US\156%kMq\DC1\251\166i\158g\167\r\161\249kb\234\DC4%{\157\US\189\209\165i\200\248\211Ej%D\141\ENQ"
      skfixonly = BS.take 32 skfix
      Right recomppk = publickey skfixonly
      Right recompsig = dsign skfixonly m
  putStrLn $ "pk fix:    " ++ (show pkfix)
  putStrLn $ "pk reg:    " ++ (show recomppk)
  putStrLn $ "sig fix:   " ++ (show sigfix)
  putStrLn $ "sig reg:   " ++ (show recompsig)
  putStrLn $ "sig reg == sig fix: " ++ (show $ sigfix == recompsig)
  putStrLn $ "sigtest fix: " ++ (show $ dverify pkfix sigfix m)
  putStrLn $ "sigtest reg: " ++ (show $ dverify recomppk recompsig m)
-- -}

testaddneutral :: Bool
testaddneutral = bPoint == (scale $ padd bPoint inf)

testmulzero :: Bool
testmulzero = inf == (scale $ pmul bPoint 0)

testmulid :: Bool
testmulid = bPoint == (scale $ pmul bPoint 1)

testaddmul :: Int -> Bool
testaddmul num = let w = iterate (padd bPoint) bPoint
                 in (scale $ pmul bPoint (FP.fromInteger b (toInteger num))) == (scale $ head $ drop (num - 1) w)

-- multiplicative inverse of a point on the curve is (pmul point by (order of the curve minus 1)), so after padd'ing the point to it, it should be neutral
testfermatinv :: Bool
testfermatinv = inf == (scale $ padd bPoint $ pmul bPoint (l - 1))

-- | test clamp against known values
clamptest :: Bool
clamptest = do
  let Right r1 = clamp $ putFPrime (2^(256::Integer) - 1)
      Right r0 = clamp $ putFPrime 0
      r0_ = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
      r1_ = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0]
    in and [listofbits r1 == r1_,listofbits r0 == r0_]

-- | base point recomputed, only for verification
bPointtest :: Bool
bPointtest = let x = xrecover by 0
                 y = FP.redc q by
                 t = FP.mulr q x y
             in bPoint == Point (x, y, 1, t)

-- | convert a FPrime to a list of FPrimes, each 0 or 1 depending on the inputs bits, hard coded to use list length 256
listofbits :: FP.FPrime -> [FP.FPrime]
listofbits c = let ex erg pos
                     | pos == 512 = erg
                     | otherwise = ex (FP.condBit c pos:erg) (pos + 1)
               in ex [] (0::Int)
