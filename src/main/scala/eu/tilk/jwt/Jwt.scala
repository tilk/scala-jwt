package eu.tilk.jwt

import akka.http.scaladsl.model._
import java.util.Base64
import java.nio.charset.StandardCharsets
import java.time.Instant

case class Jwt(val headers : RecordSet[Header], val claims : RecordSet[Claim]) {
  def validate(audience : Option[String] = None) : Boolean = {
    import Claim._
    claims.get[exp].foreach { x => if (x.isBefore(Instant.now())) return false }
    claims.get[nbf].foreach { x => if (x.isAfter(Instant.now())) return false }
    claims.get[aud].foreach { x => audience.foreach { a => if (!x.contains(a)) return false }}
    true
  }
}

final class JwtValidator(audience : Option[String] = None) {
  import Header._
  def validate(s : String) : Jwt = { // RFC 7519 7.2
    // steps 1, 2, 3
    // only the Compact representation is supported for now
    val (sheader :: srest) = s.split('.').toList
    val (bheader :: brest) = (sheader::srest).map(Base64.getUrlDecoder.decode(_))
    // steps 4, 5
    val headers = HeaderSet(new String(bheader, StandardCharsets.UTF_8))
    // steps 6, 7
    val msg = if (headers.contains[enc]) { // JWE; RFC 7516 5.2
      // step 1
      val List(benckey, binitv, bctext, bauthtag) = brest
      // steps 2, 3, 4 implicit
      // TODO step 5
      // TODO steps 6-
      throw new UnsupportedOperationException()
    } else { // JWS; RFC 7515 5.2
      // step 1
      val List(spayload, ssignature) = srest
      val List(bpayload, bsignature) = brest
      // steps 2, 3, 4, 6, 7 implicit
      // TODO step 5
      val algo = SignatureAlgorithm(headers[alg])
      headers.get[jku].foreach { u =>
        // TODO JKU
      }
      headers.get[jwk].foreach { k =>
        // TODO JWK
      }
      headers.get[kid].foreach { i =>
        // TODO kid
      }
      headers.get[crit].foreach { c =>
        c.foreach { h => 
          if (!headers.contains(h))
            throw new IllegalArgumentException("header specified by crit does not exist")
          // TODO test support for the header
        }
      }
      // step 8
      val ssigninput = spayload ++ "." ++ ssignature
      // TODO verify the signature
      bpayload
    }
    // step 8
    if (headers.get[cty].map { x => x == MediaType.applicationWithOpenCharset("jwt") }.getOrElse(false)) {
      validate(new String(msg, StandardCharsets.UTF_8))
    } else { // step 9
      val claims = ClaimSet(new String(msg, StandardCharsets.UTF_8))
      val ret = new Jwt(headers, claims)
      println(ret)
      if (!ret.validate(audience)) throw new Exception()
      ret
    }
  }  
}
