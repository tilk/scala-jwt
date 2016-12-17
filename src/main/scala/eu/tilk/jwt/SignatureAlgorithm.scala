package eu.tilk.jwt

import javax.crypto.spec.SecretKeySpec
import javax.crypto.Mac

trait SignatureAlgorithm {
  def apply(secret : Array[Byte], data : Array[Byte], sig : Array[Byte]) : Boolean
}

class MacSignatureAlgorithm(algo : String) extends SignatureAlgorithm {
  def apply(secret : Array[Byte], data : Array[Byte], sig : Array[Byte]) : Boolean = {
    val mac = Mac.getInstance(algo)
    val ss = new SecretKeySpec(secret, algo)
    mac.init(ss)
    val mysig = mac.doFinal(data)
    java.util.Arrays.equals(sig, mysig)
  }
}

object NoneSignatureAlgorithm extends SignatureAlgorithm {
  def apply(secret : Array[Byte], data : Array[Byte], sig : Array[Byte]) : Boolean = true
}

object SignatureAlgorithm {
  def apply(alg : Algorithm) : SignatureAlgorithm = alg match {
    case Algorithm.HS256 => new MacSignatureAlgorithm("HmacSHA256")
    case Algorithm.HS384 => new MacSignatureAlgorithm("HmacSHA384")
    case Algorithm.HS512 => new MacSignatureAlgorithm("HmacSHA512")
    case Algorithm.none => NoneSignatureAlgorithm
    case _ => throw new UnsupportedOperationException(alg.toString)
  }
}