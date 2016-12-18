package eu.tilk.jwt

import akka.http.scaladsl.model._
import java.time.{Instant, LocalDate, ZoneId}
import io.circe._, io.circe.generic.auto._, io.circe.parser._, io.circe.syntax._
import java.util.Base64
import java.math.BigInteger

trait Record {
  type T
  def name : String = this.getClass.getSimpleName
  def value : T
  def jsonValue : Json
}
abstract class FRecord[U](f : U => Json) extends Record {
  type T = U
  def jsonValue = f(value)
}
abstract class SimpleRecord[U] extends FRecord((x : U) => Json.fromString(x.toString))
abstract class JValueRecord extends FRecord((x : Json) => x)
abstract class StringRecord extends FRecord(Json.fromString)
abstract class TimestampRecord extends FRecord((x : Instant) => Json.fromLong(x.getEpochSecond))
abstract class DateRecord extends SimpleRecord[LocalDate]
abstract class MediaTypeRecord extends FRecord((x : MediaType) => Json.fromString(if (x.isApplication) x.subType else x.toString))
abstract class UriRecord extends SimpleRecord[Uri]
abstract class ListRecord[T](f : T => Json) extends FRecord((x : List[T]) => Json.fromValues(x.map(f)))
abstract class BooleanRecord extends SimpleRecord[Boolean]
abstract class ZoneIdRecord extends SimpleRecord[ZoneId]
abstract class Base64Record extends FRecord((x : Array[Byte]) => Json.fromString(Base64.getUrlEncoder.encodeToString(x)))
abstract class Base64UIntRecord extends FRecord((x : BigInteger) => Json.fromString(Base64.getUrlEncoder.encodeToString(x.toByteArray)))

trait RecordType[+T <: Record] {
  def apply(json : Json) : T
  def name = getClass.getSimpleName.stripSuffix("$")
}
abstract class FRecordType[T <: Record](f : Json => T#T) extends RecordType[T] with Function1[T#T, T] {
  def apply(str : Json) : T = apply(f(str))
}
abstract class SimpleRecordType[T <: SimpleRecord[U], U](f : String => U) extends FRecordType[T](x => f(x.asString.get))
abstract class JValueRecordType[T <: JValueRecord] extends FRecordType[T](x => x)
abstract class StringRecordType[T <: StringRecord] extends FRecordType[T](_.asString.get)
abstract class TimestampRecordType[T <: TimestampRecord] extends FRecordType[T](x => Instant.ofEpochSecond(x.asNumber.get.toLong.get))
abstract class DateRecordType[T <: DateRecord] extends SimpleRecordType[T, LocalDate](LocalDate.parse)
abstract class MediaTypeRecordType[T <: MediaTypeRecord] extends FRecordType[T]({x => 
  val s = x.asString.get; MediaType.parse(if (s.indexOf('/') >= 0) s else "application/"+s).right.get})
abstract class UriRecordType[T <: UriRecord] extends SimpleRecordType[T, Uri](Uri.apply)
abstract class ListRecordType[T <: ListRecord[U], U](f : Json => U) extends FRecordType[T](_.asArray.get.map(f))
abstract class ListOrSingleRecordType[T <: ListRecord[U], U](f : Json => U) 
  extends FRecordType[T](x => x.asArray.map(_.map(f)).getOrElse(List(f(x))))
abstract class BooleanRecordType[T <: BooleanRecord] extends FRecordType[T](_.asBoolean.get)
abstract class ZoneIdRecordType[T <: ZoneIdRecord] extends SimpleRecordType[T, ZoneId](ZoneId.of)
abstract class Base64RecordType[T <: Base64Record] extends FRecordType[T](x => Base64.getUrlDecoder.decode(x.asString.get))
abstract class Base64UIntRecordType[T <: Base64UIntRecord] extends FRecordType[T](x => new BigInteger(1, Base64.getUrlDecoder.decode(x.asString.get)))

trait UnknownRecordType[+T <: Record] {
  def apply(name : String, json : Json) : T
}

trait RecordKind[T <: Record] {
  protected val recordTypes : List[RecordType[T]]
  private lazy val recordTypesMap = recordTypes.map(x => (x.name, x)).toMap
  val unknown : UnknownRecordType[T]
  def apply(name : String, json : Json) : T = recordTypesMap.get(name) match {
      case Some(tp) => tp(json)
      case None => unknown(name, json)
    }
}

trait Claim extends Record
object Claim extends RecordKind[Claim] {
  protected val recordTypes = List(iss, sub, aud, exp, nbf, iat, jti, name, given_name, family_name, middle_name, nickname, preferred_username, profile,
        picture, website, email, email_verified, gender, birthdate, zoneinfo, locale, phone_number, phone_number_verified, 
        address, updated_at, azp, nonce, auth_time, at_hash, c_hash, acr, amr, sub_jwk, cnf)
  
  // RFC7519
  
  case class iss(val value : String) extends StringRecord with Claim with Header
  object iss extends StringRecordType[iss]
  
  case class sub(val value : String) extends StringRecord with Claim with Header
  object sub extends StringRecordType[sub]
  
  case class aud(val value : List[String]) extends ListRecord(Json.fromString) with Claim with Header
  object aud extends ListOrSingleRecordType[aud, String](_.asString.get)
  
  case class exp(val value : Instant) extends TimestampRecord with Claim
  object exp extends TimestampRecordType[exp]
  
  case class nbf(val value : Instant) extends TimestampRecord with Claim
  object nbf extends TimestampRecordType[nbf]
  
  case class iat(val value : Instant) extends TimestampRecord with Claim
  object iat extends TimestampRecordType[iat]
  
  case class jti(val value : Instant) extends TimestampRecord with Claim
  object jti extends TimestampRecordType[jti]
  
  // OpenID Connect
  
  case class name(val value : String) extends StringRecord with Claim
  object name extends StringRecordType[name]
  
  case class given_name(val value : String) extends StringRecord with Claim
  object given_name extends StringRecordType[given_name]
  
  case class family_name(val value : String) extends StringRecord with Claim
  object family_name extends StringRecordType[family_name]
  
  case class middle_name(val value : String) extends StringRecord with Claim
  object middle_name extends StringRecordType[middle_name]
  
  case class nickname(val value : String) extends StringRecord with Claim
  object nickname extends StringRecordType[nickname]
  
  case class preferred_username(val value : String) extends StringRecord with Claim
  object preferred_username extends StringRecordType[preferred_username]
  
  case class profile(val value : Uri) extends UriRecord with Claim
  object profile extends UriRecordType[profile]

  case class picture(val value : Uri) extends UriRecord with Claim
  object picture extends UriRecordType[picture]

  case class website(val value : Uri) extends UriRecord with Claim
  object website extends UriRecordType[website]

  case class email(val value : String) extends StringRecord with Claim
  object email extends StringRecordType[email]
  
  case class email_verified(val value : Boolean) extends BooleanRecord with Claim
  object email_verified extends BooleanRecordType[email_verified]
  
  case class gender(val value : Gender) extends SimpleRecord[Gender] with Claim
  object gender extends SimpleRecordType[gender, Gender](Gender)
  
  case class birthdate(val value : LocalDate) extends DateRecord with Claim
  object birthdate extends DateRecordType[birthdate]
  
  case class zoneinfo(val value : ZoneId) extends ZoneIdRecord with Claim
  object zoneinfo extends ZoneIdRecordType[zoneinfo]
  
  case class locale(val value : String) extends StringRecord with Claim // TODO type for locales BCP47 (RFC5646)
  object locale extends StringRecordType[locale]
  
  case class phone_number(val value : String) extends StringRecord with Claim
  object phone_number extends StringRecordType[phone_number]
  
  case class phone_number_verified(val value : Boolean) extends BooleanRecord with Claim
  object phone_number_verified extends BooleanRecordType[phone_number_verified]
  
  case class address(val value : String) extends StringRecord with Claim
  object address extends StringRecordType[address]
  
  case class updated_at(val value : Instant) extends TimestampRecord with Claim
  object updated_at extends TimestampRecordType[updated_at]
  
  case class azp(val value : String) extends StringRecord with Claim
  object azp extends StringRecordType[azp]
  
  case class nonce(val value : String) extends StringRecord with Claim
  object nonce extends StringRecordType[nonce]
  
  case class auth_time(val value : Instant) extends TimestampRecord with Claim
  object auth_time extends TimestampRecordType[auth_time]
  
  case class at_hash(val value : String) extends StringRecord with Claim
  object at_hash extends StringRecordType[at_hash]
  
  case class c_hash(val value : String) extends StringRecord with Claim
  object c_hash extends StringRecordType[c_hash]
  
  case class acr(val value : String) extends StringRecord with Claim
  object acr extends StringRecordType[acr]
  
  case class amr(val value : List[String]) extends ListRecord(Json.fromString) with Claim
  object amr extends ListRecordType[amr, String](_.asString.get)
  
  case class sub_jwk(val value : String) extends StringRecord with Claim // TODO JWK
  object sub_jwk extends StringRecordType[sub_jwk]
  
  case class cnf(val value : Confirm) extends SimpleRecord[Confirm] with Claim
  object cnf extends SimpleRecordType[cnf, Confirm](Confirm)
  
  case class unknown(override val name : String, val value : Json) extends JValueRecord with Claim
  object unknown extends UnknownRecordType[unknown]
}

trait Header extends Record
object Header extends RecordKind[Header] {
  protected val recordTypes = List(typ, cty, alg, jku, jwk, kid, x5u, x5c, x5t, `x5t#S256`, crit, enc, zip,
      Claim.iss, Claim.sub, Claim.aud)
  
  // RFC 7519
  
  case class typ(val value : MediaType) extends MediaTypeRecord with Header
  object typ extends MediaTypeRecordType[typ]
  
  case class cty(val value : MediaType) extends MediaTypeRecord with Header
  object cty extends MediaTypeRecordType[cty]
  
  // RFC 7515, 7516
  
  case class alg(val value : Algorithm) extends SimpleRecord[Algorithm] with Header with Parameter
  object alg extends SimpleRecordType[alg, Algorithm](Algorithm)  
  
  case class jku(val value : Uri) extends UriRecord with Header
  object jku extends UriRecordType[jku]
  
  case class jwk(val value : String) extends StringRecord with Header // TODO JWK
  object jwk extends StringRecordType[jwk]
  
  case class kid(val value : String) extends StringRecord with Header with Parameter
  object kid extends StringRecordType[kid]
  
  case class x5u(val value : Uri) extends UriRecord with Header with Parameter
  object x5u extends UriRecordType[x5u]
  
  case class x5c(val value : List[String]) extends ListRecord(Json.fromString) with Header with Parameter
  object x5c extends ListRecordType[x5c, String](_.asString.get)
  
  case class x5t(val value : String) extends StringRecord with Header with Parameter
  object x5t extends StringRecordType[x5t]
  
  case class `x5t#S256`(val value : String) extends StringRecord with Header with Parameter
  object `x5t#S256` extends StringRecordType[`x5t#S256`]
  
  case class crit(val value : List[String]) extends ListRecord(Json.fromString) with Header
  object crit extends ListRecordType[crit, String](_.asString.get)
  
  case class enc(val value : String) extends StringRecord with Header
  object enc extends StringRecordType[enc]
  
  case class zip(val value : Zip) extends SimpleRecord[Zip] with Header
  object zip extends SimpleRecordType[zip, Zip](Zip)
  
  case class unknown(override val name : String, val value : Json) extends JValueRecord with Header
  object unknown extends UnknownRecordType[unknown]
}

trait Parameter extends Record
object Parameter extends RecordKind[Parameter] {
  protected val recordTypes = List(kty, use, key_ops, Header.alg, Header.kid, Header.x5u, Header.x5c, Header.x5t, Header.`x5t#S256`)
  
  case class kty(val value : KeyType) extends SimpleRecord[KeyType] with Parameter
  object kty extends SimpleRecordType[kty, KeyType](KeyType)
  
  case class use(val value : KeyUse) extends SimpleRecord[KeyUse] with Parameter
  object use extends SimpleRecordType[use, KeyUse](KeyUse)
  
  case class key_ops(val value : List[KeyOp]) extends ListRecord[KeyOp]((Json.fromString(_)) compose (_.toString)) with Parameter
  object key_ops extends ListRecordType[key_ops, KeyOp](KeyOp compose (_.asString.get))
  
  case class crv(val value : Curve) extends SimpleRecord[Curve] with Parameter
  object crv extends SimpleRecordType[crv, Curve](Curve)
  
  case class k(val value : Array[Byte]) extends Base64Record with Parameter
  object k extends Base64RecordType[k]
  
  case class x(val value : Array[Byte]) extends Base64Record with Parameter
  object x extends Base64RecordType[x]
  
  case class y(val value : Array[Byte]) extends Base64Record with Parameter
  object y extends Base64RecordType[y]
  
  case class d(val value : BigInteger) extends Base64UIntRecord with Parameter
  object d extends Base64UIntRecordType[d]
  
  case class n(val value : BigInteger) extends Base64UIntRecord with Parameter
  object n extends Base64UIntRecordType[n]

  case class e(val value : BigInteger) extends Base64UIntRecord with Parameter
  object e extends Base64UIntRecordType[e]
  
  case class p(val value : BigInteger) extends Base64UIntRecord with Parameter
  object p extends Base64UIntRecordType[p]
  
  case class q(val value : BigInteger) extends Base64UIntRecord with Parameter
  object q extends Base64UIntRecordType[q]
  
  case class dp(val value : BigInteger) extends Base64UIntRecord with Parameter
  object dp extends Base64UIntRecordType[dp]
  
  case class dq(val value : BigInteger) extends Base64UIntRecord with Parameter
  object dq extends Base64UIntRecordType[dq]
  
  case class qi(val value : BigInteger) extends Base64UIntRecord with Parameter
  object qi extends Base64UIntRecordType[qi]
  
  case class unknown(override val name : String, val value : Json) extends JValueRecord with Parameter
  object unknown extends UnknownRecordType[unknown]
}