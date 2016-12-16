package org.tilk.jwt

sealed abstract class Zip
object Zip extends Function1[String, Zip] {
  case object DEF extends Zip
  case class Unknown(val name : String) extends Zip { override def toString = name }
  def apply(s : String) = s match {
    case "DEF" => DEF
    case _ => Unknown(s)
  }
}

sealed abstract class Gender
object Gender extends Function1[String, Gender] {
  case object female extends Gender
  case object male extends Gender
  case class unknown(val name : String) extends Gender { override def toString = name }
  def apply(s : String) = s match {
    case "female" => female
    case "male" => male
    case _ => unknown(s)
  }
}

sealed abstract class Confirm
object Confirm extends Function1[String, Confirm] {
  case object jwk extends Confirm
  case object jwe extends Confirm
  case object jku extends Confirm
  def apply(s : String) = s match {
    case "jwk" => jwk
    case "jwe" => jwe
    case "jku" => jku
    case _ => throw new IllegalArgumentException()
  }
}

sealed abstract class Algorithm
object Algorithm extends Function1[String, Algorithm] {
  case object HS256 extends Algorithm
  case object HS384 extends Algorithm
  case object HS512 extends Algorithm
  case object RS256 extends Algorithm
  case object RS384 extends Algorithm
  case object RS512 extends Algorithm
  case object ES256 extends Algorithm
  case object ES384 extends Algorithm
  case object ES512 extends Algorithm
  case object PS256 extends Algorithm
  case object PS384 extends Algorithm
  case object PS512 extends Algorithm
  case object none extends Algorithm
  case object RSA1_5 extends Algorithm
  case object `RSA-OAEP` extends Algorithm
  case object `RSA-OAEP-256` extends Algorithm
  case object A128KW extends Algorithm
  case object A192KW extends Algorithm
  case object A256KW extends Algorithm
  case object dir extends Algorithm
  case object `ECDH-ES` extends Algorithm
  case object `ECDH-ES+A128KW` extends Algorithm
  case object `ECDH-ES+A192KW` extends Algorithm
  case object `ECDH-ES+A256KW` extends Algorithm
  case object A128GCMKW extends Algorithm
  case object A192GCMKW extends Algorithm
  case object A256GCMKW extends Algorithm
  case object `PBES2-HS256+A128KW` extends Algorithm
  case object `PBES2-HS384+A192KW` extends Algorithm
  case object `PBES2-HS512+A256KW` extends Algorithm
  def apply(s : String) = s match {
    case "HS256" => HS256
    case "HS384" => HS384
    case "HS512" => HS512
    case "RS256" => RS256
    case "RS384" => RS384
    case "RS512" => RS512
    case "ES256" => ES256
    case "ES384" => ES384
    case "ES512" => ES512
    case "PS256" => PS256
    case "PS384" => PS384
    case "PS512" => PS512
    case "none" => none
    case "RSA1_5" => RSA1_5
    case "RSA-OAEP" => `RSA-OAEP`
    case "RSA-OAEP-256" => `RSA-OAEP-256`
    case "A128KW" => A128KW
    case "A192KW" => A192KW
    case "A256KW" => A256KW
    case "dir" => dir
    case "ECDH-ES" => `ECDH-ES`
    case "ECDH-ES+A128KW" => `ECDH-ES+A128KW`
    case "ECDH-ES+A192KW" => `ECDH-ES+A192KW`
    case "ECDH-ES+A256KW" => `ECDH-ES+A256KW`
    case "A128GCMKW" => A128GCMKW
    case "A192GCMKW" => A192GCMKW
    case "A256GCMKW" => A256GCMKW
    case "PBES2-HS256+A128KW" => `PBES2-HS256+A128KW`
    case "PBES2-HS384+A192KW" => `PBES2-HS384+A192KW`
    case "PBES2-HS512+A256KW" => `PBES2-HS512+A256KW`
    case _ => throw new IllegalArgumentException()
  }
}