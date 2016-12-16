package eu.tilk

package object jwt {
  type ClaimSet = RecordSet[Claim]
  type HeaderSet = RecordSet[Header]
}
