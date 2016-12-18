package eu.tilk.jwt

import io.circe._, io.circe.generic.auto._, io.circe.parser._, io.circe.syntax._

case class Jwk(val parameters : RecordSet[Parameter]) {
  
}

object Jwk {
  def apply(json : Json) : Jwk = {
    val ret = Jwk(ParameterSet(json))
    ret
  }
}