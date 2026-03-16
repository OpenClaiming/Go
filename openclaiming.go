package openclaiming

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

type OpenClaim struct {}

func Canonicalize(claim map[string]interface{}) ([]byte,error) {
	delete(claim,"sig")
	return json.Marshal(claim)
}

func Sign(claim map[string]interface{}, priv *ecdsa.PrivateKey) (string,error) {
	canon,_ := Canonicalize(claim)
	hash := sha256.Sum256(canon)
	r,s,_ := ecdsa.Sign(nil,priv,hash[:])
	sig := append(r.Bytes(), s.Bytes()...)
	return base64.StdEncoding.EncodeToString(sig),nil
}