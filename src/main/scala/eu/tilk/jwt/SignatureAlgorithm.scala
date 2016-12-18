package eu.tilk.jwt

import javax.crypto.spec.SecretKeySpec
import javax.crypto.Mac
import java.security.{Signature, PublicKey, KeyFactory}
import java.security.spec.{AlgorithmParameterSpec, MGF1ParameterSpec, PSSParameterSpec, KeySpec, RSAPublicKeySpec, ECPoint, ECParameterSpec}

trait SignatureAlgorithm {
  def test(secret : Jwk, data : Array[Byte], sig : Array[Byte]) : Boolean
}

class MacSignatureAlgorithm(algo : String) extends SignatureAlgorithm {
  def test(secret : Jwk, data : Array[Byte], sig : Array[Byte]) : Boolean = {
    import Parameter._
    if (secret.parameters[kty] != KeyType.oct || !secret.parameters.contains[k]) 
      throw new IllegalArgumentException()
    val mac = Mac.getInstance(algo)
    val ss = new SecretKeySpec(secret.parameters[k], algo)
    mac.init(ss)
    val mysig = mac.doFinal(data)
    java.util.Arrays.equals(sig, mysig)
  }
}

abstract class SecuritySignatureAlgorithm(algo : String, spec : Seq[AlgorithmParameterSpec] = Nil) extends SignatureAlgorithm {
  def test(secret : Jwk, data : Array[Byte], sig : Array[Byte]) : Boolean = {
    import Parameter._
    val ciph = Signature.getInstance(algo)
    spec.foreach(ciph.setParameter(_))
    ciph.initVerify(publicKey(secret))
    ciph.update(data)
    ciph.verify(sig)
  }
  def publicKey(secret : Jwk) : PublicKey
}

class RSASignatureAlgorithm(algo : String, spec : Seq[AlgorithmParameterSpec] = Nil) extends SecuritySignatureAlgorithm(algo, spec) {
  def publicKey(secret : Jwk) = {
    import Parameter._
    val spec = new RSAPublicKeySpec(secret.parameters[n], secret.parameters[e])
    val kf = KeyFactory.getInstance("RSA")
    kf.generatePublic(spec)
  }
}

class ECSignatureAlgorithm(algo : String, spec : Seq[AlgorithmParameterSpec] = Nil) extends SecuritySignatureAlgorithm(algo, spec) {
  def publicKey(secret : Jwk) = {
    import Parameter._
    val spec = null // TODO new ECPublicKeySpec()
    val kf = KeyFactory.getInstance("EC")
    kf.generatePublic(spec)
  }
}

object NoneSignatureAlgorithm extends SignatureAlgorithm {
  def test(secret : Jwk, data : Array[Byte], sig : Array[Byte]) : Boolean = true
}

object SignatureAlgorithm {
  def apply(alg : Algorithm) : SignatureAlgorithm = alg match {
    case Algorithm.HS256 => new MacSignatureAlgorithm("HmacSHA256")
    case Algorithm.HS384 => new MacSignatureAlgorithm("HmacSHA384")
    case Algorithm.HS512 => new MacSignatureAlgorithm("HmacSHA512")
    case Algorithm.RS256 => new RSASignatureAlgorithm("SHA256withRSA")
    case Algorithm.RS384 => new RSASignatureAlgorithm("SHA384withRSA")
    case Algorithm.RS512 => new RSASignatureAlgorithm("SHA512withRSA")
    case Algorithm.ES256 => new RSASignatureAlgorithm("SHA256withEDCSA")
    case Algorithm.ES384 => new RSASignatureAlgorithm("SHA384withEDCSA")
    case Algorithm.ES512 => new RSASignatureAlgorithm("SHA512withEDCSA")
    case Algorithm.PS256 => new RSASignatureAlgorithm("SHA256withRSAandMGF1", 
        List(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)))
    case Algorithm.PS384 => new RSASignatureAlgorithm("SHA384withRSAandMGF1",
        List(new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)))
    case Algorithm.PS512 => new RSASignatureAlgorithm("SHA512withRSAandMGF1", 
        List(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)))
    case Algorithm.none => NoneSignatureAlgorithm
    case _ => throw new UnsupportedOperationException(alg.toString)
  }
}