package eu.tilk.jwt

import scala.reflect.ClassTag
import scala.collection.{AbstractMap, TraversableOnce}
import io.circe._, io.circe.generic.auto._, io.circe.parser._, io.circe.syntax._

final class RecordSet[+T <: Record] private[jwt] (params : Map[Class[_], T], nparams : Map[String, T]) extends AbstractMap[String, T] {
  def get[U <: Record : ClassTag] = params.get(implicitly[ClassTag[U]].runtimeClass).map(_.asInstanceOf[U].value)
  def get(s : String) = nparams.get(s)
  def apply[U <: Record : ClassTag] = params(implicitly[ClassTag[U]].runtimeClass).asInstanceOf[U].value
  def contains[U <: Record : ClassTag] = get[U].isDefined
  def +[U >: T <: Record](param : U) = new RecordSet(params + ((param.getClass, param)), nparams + ((param.name, param)))
  def +[U >: T](kv : (String, U)) = { val param = kv._2.asInstanceOf[T]; assert(kv._1 == param.name); this + param }
  def -(k : String) = new RecordSet(nparams.get(k).map(params - _.getClass).getOrElse(params), nparams - k)
  def ++[U >: T <: Record](params : TraversableOnce[U]) = 
    new RecordSet(this.params ++ params.map(p => (p.getClass, p)), this.nparams ++ params.map(p => (p.name, p)))
  def iterator = nparams.iterator
  def toJson = Json.fromFields(nparams.values.map(p => (p.name, p.jsonValue)))
}

object RecordSet {
  def apply[T <: Record](params : T*) : RecordSet[T] = 
    new RecordSet(params.map(p => (p.getClass, p)).toMap, params.map(p => (p.name, p)).toMap)
}

abstract class RecordSetFactory[T <: Record] (recordKind : RecordKind[T]) {
  def apply(params : T*) = RecordSet(params:_*)
  def apply(json : Json) : RecordSet[T] = apply(json.asObject.get.toList.map(p => recordKind(p._1, p._2)):_*)
  def apply(s : String) : RecordSet[T] = apply(parse(s).right.get)
}

import Claim._, Header._

object ClaimSet extends RecordSetFactory(Claim)

object HeaderSet extends RecordSetFactory(Header)

