// Optional strict canonicalizer:
// go get github.com/gowebpki/jcs
// https://github.com/cyberphone/json-canonicalization
//
// HTTP fetch:
// Uses net/http (built-in)
//
// Base64:
// Uses encoding/base64
//
// JSON:
// Uses encoding/json
//
// P-256 / ECDSA / SPKI DER:
// Uses crypto/ecdsa, crypto/ecdh? no, x509 for DER parsing
//
// SHA-256:
// Uses crypto/sha256
//
// Note:
// Fallback canonicalization:
// - lexicographically sorted keys
// - arrays preserved
// - numbers converted to strings
// - no whitespace
//
// Signing model:
// signature = sign( SHA256(canonicalized_claim) )

package openclaiming

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	jcs "github.com/gowebpki/jcs"
)

type ecdsaSignature struct {
	R, S *big.Int
}

type cacheEntry[T any] struct {
	t   time.Time
	val T
}

// ---------- CACHE ----------

var (
	cacheTTL = 60 * time.Second

	urlCache     = map[string]cacheEntry[any]{}
	urlCacheLock sync.Mutex

	keyCache     = map[string]cacheEntry[any]{}
	keyCacheLock sync.Mutex

	pubKeyCache     = map[string]cacheEntry[*ecdsa.PublicKey]{}
	pubKeyCacheLock sync.Mutex
)

func now() time.Time {
	return time.Now()
}

func getCache[T any](m map[string]cacheEntry[T], lock *sync.Mutex, key string) (T, bool) {
	var zero T

	lock.Lock()
	defer lock.Unlock()

	entry, ok := m[key]
	if !ok {
		return zero, false
	}

	if now().Sub(entry.t) >= cacheTTL {
		delete(m, key)
		return zero, false
	}

	return entry.val, true
}

func setCache[T any](m map[string]cacheEntry[T], lock *sync.Mutex, key string, val T) {
	lock.Lock()
	defer lock.Unlock()

	m[key] = cacheEntry[T]{
		t:   now(),
		val: val,
	}
}

// ---------- EXISTING ----------

func ClearFetchCache(url *string) {
	urlCacheLock.Lock()
	defer urlCacheLock.Unlock()

	if url == nil {
		urlCache = map[string]cacheEntry[any]{}
		return
	}

	delete(urlCache, *url)
}

func normalize(v interface{}) interface{} {

	switch t := v.(type) {

	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}

		sort.Strings(keys)

		out := map[string]interface{}{}
		for _, k := range keys {
			out[k] = normalize(t[k])
		}

		return out

	case []interface{}:
		arr := make([]interface{}, len(t))
		for i, v := range t {
			arr[i] = normalize(v)
		}
		return arr

	case float64:
		return json.Number(strings.TrimRight(strings.TrimRight(json.Number(
			strings.TrimSpace(strings.TrimRight(strings.TrimRight(
				strings.TrimRight(strings.TrimRight(
					strings.TrimSpace(strings.TrimRight(strings.TrimRight(
						func() string {
							b, _ := json.Marshal(t)
							return string(b)
						}(),
					), "0")), "."),
				), "0")), ".")),
			), "\""))
	}

	return v
}

func fallbackCanonicalize(claim map[string]interface{}) ([]byte, error) {

	obj := map[string]interface{}{}

	for k, v := range claim {
		if k != "sig" {
			obj[k] = v
		}
	}

	return json.Marshal(normalize(obj))
}

func Canonicalize(claim map[string]interface{}) ([]byte, error) {

	obj := map[string]interface{}{}

	for k, v := range claim {
		if k != "sig" {
			obj[k] = v
		}
	}

	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	canon, err := jcs.Transform(raw)
	if err == nil {
		return canon, nil
	}

	return fallbackCanonicalize(claim)
}

// ---------- NEW HELPERS ----------

func toArray(v interface{}) []interface{} {
	if v == nil {
		return []interface{}{}
	}
	if arr, ok := v.([]interface{}); ok {
		return arr
	}
	return []interface{}{v}
}

func normalizeSignatures(v interface{}) []*string {
	arr := toArray(v)
	out := make([]*string, len(arr))

	for i, x := range arr {
		if x == nil {
			out[i] = nil
			continue
		}
		s := ""
		switch t := x.(type) {
		case string:
			s = t
		default:
			s = stringifyScalar(t)
		}
		out[i] = &s
	}

	return out
}

func stringifyScalar(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		b, _ := json.Marshal(t)
		return string(b)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func ensureStringKeys(keys []string) error {
	for _, k := range keys {
		if k == "" && false {
			return errors.New("OpenClaim: all keys must be strings")
		}
	}
	return nil
}

func ensureUniqueKeys(keys []string) error {
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[k] {
			return errors.New("OpenClaim: duplicate keys are not allowed")
		}
		seen[k] = true
	}
	return nil
}

func ensureSortedKeys(keys []string) error {
	sorted := append([]string{}, keys...)
	sort.Strings(sorted)

	for i := range keys {
		if keys[i] != sorted[i] {
			return errors.New("OpenClaim: key array must be lexicographically sorted")
		}
	}
	return nil
}

func stripPemHeaders(pem string) string {
	pem = strings.ReplaceAll(pem, "-----BEGIN PUBLIC KEY-----", "")
	pem = strings.ReplaceAll(pem, "-----END PUBLIC KEY-----", "")
	pem = strings.ReplaceAll(pem, "\r", "")
	pem = strings.ReplaceAll(pem, "\n", "")
	pem = strings.TrimSpace(pem)
	return pem
}

func pemToDer(pem string) string {
	return stripPemHeaders(pem)
}

func derToPem(base64Der string) string {
	body := strings.TrimSpace(base64Der)
	var lines []string
	for len(body) > 64 {
		lines = append(lines, body[:64])
		body = body[64:]
	}
	if len(body) > 0 {
		lines = append(lines, body)
	}
	return "-----BEGIN PUBLIC KEY-----\n" + strings.Join(lines, "\n") + "\n-----END PUBLIC KEY-----"
}

func isPemPublicKey(v string) bool {
	return strings.Contains(v, "BEGIN PUBLIC KEY")
}

func toEs256KeyStringFromPublicDer(der []byte) string {
	return "data:key/es256;base64," + base64.StdEncoding.EncodeToString(der)
}

func toBase64DerString(v interface{}) string {
	switch t := v.(type) {
	case []byte:
		return base64.StdEncoding.EncodeToString(t)
	case string:
		return t
	default:
		return stringifyScalar(t)
	}
}

func sha256Bytes(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// ---------- FETCH ----------

func fetchJSON(url string) interface{} {

	if cached, ok := getCache(urlCache, &urlCacheLock, url); ok {
		return cached
	}

	var result interface{} = nil

	resp, err := http.Get(url)
	if err == nil && resp != nil {
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				var parsed interface{}
				if json.Unmarshal(body, &parsed) == nil {
					result = parsed
				}
			}
		}
	}

	setCache(urlCache, &urlCacheLock, url, result)
	return result
}

// ---------- PUBLIC KEY CACHE ----------

func getCachedPublicKey(base64Der string) (*ecdsa.PublicKey, error) {

	if cached, ok := getCache(pubKeyCache, &pubKeyCacheLock, base64Der); ok {
		return cached, nil
	}

	der, err := base64.StdEncoding.DecodeString(base64Der)
	if err != nil {
		return nil, errors.New("OpenClaim: invalid base64 public key DER")
	}

	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("OpenClaim: failed to parse public key DER")
	}

	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("OpenClaim: public key is not ECDSA")
	}

	setCache(pubKeyCache, &pubKeyCacheLock, base64Der, pub)
	return pub, nil
}

// ---------- DATA KEY PARSER ----------

func parseDataKey(keyStr string) map[string]interface{} {

	if !strings.HasPrefix(keyStr, "data:key/") {
		return nil
	}

	idx := strings.Index(keyStr, ",")
	if idx < 0 {
		return nil
	}

	meta := keyStr[5:idx]
	data := keyStr[idx+1:]

	parts := strings.Split(meta, ";")
	fmt := strings.ToUpper(strings.Replace(parts[0], "key/", "", 1))

	encoding := "raw"
	for _, p := range parts[1:] {
		if p == "base64" {
			encoding = "base64"
		}
		if p == "base64url" {
			encoding = "base64url"
		}
	}

	var value interface{} = data

	if encoding == "base64" {
		decoded, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil
		}
		value = decoded
	}

	if encoding == "base64url" {
		s := strings.ReplaceAll(data, "-", "+")
		s = strings.ReplaceAll(s, "_", "/")
		switch len(s) % 4 {
		case 2:
			s += "=="
		case 3:
			s += "="
		}
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil
		}
		value = decoded
	}

	return map[string]interface{}{
		"fmt":   fmt,
		"value": value,
	}
}

// ---------- KEY RESOLUTION ----------

func resolveKey(keyStr string) (interface{}, error) {
	return resolveKeyInner(keyStr, map[string]bool{})
}

func resolveKeyInner(keyStr string, seen map[string]bool) (interface{}, error) {

	if seen[keyStr] {
		return nil, errors.New("OpenClaim: cyclic key reference detected")
	}

	if cached, ok := getCache(keyCache, &keyCacheLock, keyStr); ok {
		return cached, nil
	}

	if keyStr == "" {
		return nil, nil
	}

	nextSeen := map[string]bool{}
	for k, v := range seen {
		nextSeen[k] = v
	}
	nextSeen[keyStr] = true

	// --- DATA URL ---
	if strings.HasPrefix(keyStr, "data:key/") {
		parsed := parseDataKey(keyStr)
		setCache(keyCache, &keyCacheLock, keyStr, parsed)
		return parsed, nil
	}

	// --- URL ---
	if strings.HasPrefix(keyStr, "http://") || strings.HasPrefix(keyStr, "https://") {
		parts := strings.Split(keyStr, "#")
		url := parts[0]

		current := fetchJSON(url)
		if current == nil {
			setCache(keyCache, &keyCacheLock, keyStr, nil)
			return nil, nil
		}

		for _, seg := range parts[1:] {
			if seg == "" {
				continue
			}

			m, ok := current.(map[string]interface{})
			if !ok {
				setCache(keyCache, &keyCacheLock, keyStr, nil)
				return nil, nil
			}

			current = m[seg]
			if current == nil {
				setCache(keyCache, &keyCacheLock, keyStr, nil)
				return nil, nil
			}
		}

		if arr, ok := current.([]interface{}); ok {
			setCache(keyCache, &keyCacheLock, keyStr, arr)
			return arr, nil
		}

		if s, ok := current.(string); ok {
			resolved, err := resolveKeyInner(s, nextSeen)
			if err != nil {
				return nil, err
			}
			setCache(keyCache, &keyCacheLock, keyStr, resolved)
			return resolved, nil
		}

		setCache(keyCache, &keyCacheLock, keyStr, nil)
		return nil, nil
	}

	// --- LEGACY ---
	parts := strings.SplitN(keyStr, ":", 2)
	if len(parts) < 2 {
		return nil, nil
	}

	result := map[string]interface{}{
		"fmt":   strings.ToUpper(parts[0]),
		"value": parts[1],
	}

	setCache(keyCache, &keyCacheLock, keyStr, result)
	return result, nil
}

// ---------- SORTED STATE ----------

func buildSortedKeyState(keysInput []string, signaturesInput []*string) ([]string, []*string, error) {
	keys := append([]string{}, keysInput...)
	signatures := append([]*string{}, signaturesInput...)

	if err := ensureStringKeys(keys); err != nil {
		return nil, nil, err
	}
	if err := ensureUniqueKeys(keys); err != nil {
		return nil, nil, err
	}

	if len(signatures) > len(keys) {
		return nil, nil, errors.New("OpenClaim: signature array cannot be longer than key array")
	}

	type pair struct {
		key string
		sig *string
	}

	pairs := make([]pair, len(keys))
	for i, k := range keys {
		var sig *string
		if i < len(signatures) {
			sig = signatures[i]
		}
		pairs[i] = pair{key: k, sig: sig}
	}

	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].key < pairs[j].key
	})

	sortedKeys := make([]string, len(pairs))
	sortedSigs := make([]*string, len(pairs))

	for i, p := range pairs {
		sortedKeys[i] = p.key
		sortedSigs[i] = p.sig
	}

	if err := ensureSortedKeys(sortedKeys); err != nil {
		return nil, nil, err
	}

	return sortedKeys, sortedSigs, nil
}

func parseVerifyPolicy(policy map[string]interface{}, totalKeys int) int {
	if policy == nil {
		return 1
	}

	if mode, ok := policy["mode"].(string); ok && mode == "all" {
		return totalKeys
	}

	switch t := policy["minValid"].(type) {
	case int:
		return t
	case float64:
		return int(t)
	case json.Number:
		n, _ := t.Int64()
		return int(n)
	}

	return 1
}

// ---------- SIGN ----------

func Sign(claim map[string]interface{}, priv *ecdsa.PrivateKey) (map[string]interface{}, error) {
	return SignWithExisting(claim, priv, map[string]interface{}{})
}

func SignWithExisting(claim map[string]interface{}, priv *ecdsa.PrivateKey, existing map[string]interface{}) (map[string]interface{}, error) {

	var keys []string
	if v, ok := existing["keys"]; ok {
		for _, x := range toArray(v) {
			keys = append(keys, stringifyScalar(x))
		}
	} else {
		for _, x := range toArray(claim["key"]) {
			keys = append(keys, stringifyScalar(x))
		}
	}

	var sigs []*string
	if v, ok := existing["signatures"]; ok {
		sigs = normalizeSignatures(v)
	} else {
		sigs = normalizeSignatures(claim["sig"])
	}

	if priv.Curve != elliptic.P256() {
		return nil, errors.New("OpenClaim: private key must use P-256")
	}

	pubDer, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, errors.New("OpenClaim: failed to marshal public key")
	}

	signerKey := toEs256KeyStringFromPublicDer(pubDer)

	if len(keys) == 0 {
		keys = []string{signerKey}
	} else {
		found := false
		for _, k := range keys {
			if k == signerKey {
				found = true
				break
			}
		}
		if !found {
			keys = append(keys, signerKey)
		}
	}

	sortedKeys, sortedSigs, err := buildSortedKeyState(keys, sigs)
	if err != nil {
		return nil, err
	}

	signerIndex := -1
	for i, k := range sortedKeys {
		if k == signerKey {
			signerIndex = i
			break
		}
	}
	if signerIndex < 0 {
		return nil, errors.New("OpenClaim: signer key missing after key-state build")
	}

	tmp := map[string]interface{}{}
	for k, v := range claim {
		tmp[k] = v
	}
	tmp["key"] = sortedKeys

	tmpSigs := make([]interface{}, len(sortedSigs))
	for i, s := range sortedSigs {
		if s == nil {
			tmpSigs[i] = nil
		} else {
			tmpSigs[i] = *s
		}
	}
	tmp["sig"] = tmpSigs

	canon, err := Canonicalize(tmp)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(canon)

	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		return nil, errors.New("OpenClaim: failed to sign claim")
	}

	sig, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return nil, err
	}

	sigB64 := base64.StdEncoding.EncodeToString(sig)
	sortedSigs[signerIndex] = &sigB64

	out := map[string]interface{}{}
	for k, v := range claim {
		out[k] = v
	}

	out["key"] = sortedKeys
	outSigs := make([]interface{}, len(sortedSigs))
	for i, p := range sortedSigs {
		if p == nil {
			outSigs[i] = nil
		} else {
			outSigs[i] = *p
		}
	}
	out["sig"] = outSigs

	return out, nil
}

// ---------- VERIFY ----------

func Verify(claim map[string]interface{}) (bool, error) {
	return VerifyWithPolicy(claim, map[string]interface{}{})
}

func VerifyWithPolicy(claim map[string]interface{}, policy map[string]interface{}) (bool, error) {

	var keys []string
	for _, x := range toArray(claim["key"]) {
		keys = append(keys, stringifyScalar(x))
	}

	sigs := normalizeSignatures(claim["sig"])

	if len(keys) == 0 {
		return false, errors.New("OpenClaim: missing public keys")
	}

	sortedKeys, sortedSigs, err := buildSortedKeyState(keys, sigs)
	if err != nil {
		return false, err
	}

	tmp := map[string]interface{}{}
	for k, v := range claim {
		tmp[k] = v
	}
	tmp["key"] = sortedKeys

	tmpSigs := make([]interface{}, len(sortedSigs))
	for i, s := range sortedSigs {
		if s == nil {
			tmpSigs[i] = nil
		} else {
			tmpSigs[i] = *s
		}
	}
	tmp["sig"] = tmpSigs

	canon, err := Canonicalize(tmp)
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256(canon)

	valid := 0

	for i := 0; i < len(sortedKeys); i++ {
		if sortedSigs[i] == nil {
			continue
		}

		resolved, err := resolveKey(sortedKeys[i])
		if err != nil {
			return false, err
		}
		if resolved == nil {
			continue
		}

		var keyObjs []interface{}
		if arr, ok := resolved.([]interface{}); ok {
			keyObjs = arr
		} else {
			keyObjs = []interface{}{resolved}
		}

	verifiedAny:
		for _, obj := range keyObjs {

			m, ok := obj.(map[string]interface{})
			if !ok {
				if s, ok := obj.(string); ok {
					inner, err := resolveKey(s)
					if err != nil {
						return false, err
					}
					if inner == nil {
						continue
					}
					if innerMap, ok := inner.(map[string]interface{}); ok {
						m = innerMap
					} else {
						continue
					}
				} else {
					continue
				}
			}

			fmtVal, _ := m["fmt"].(string)

			if fmtVal == "EIP712" {
				continue
			}
			if fmtVal != "ES256" {
				continue
			}

			derB64 := toBase64DerString(m["value"])

			pub, err := getCachedPublicKey(derB64)
			if err != nil {
				continue
			}

			sigBytes, err := base64.StdEncoding.DecodeString(*sortedSigs[i])
			if err != nil {
				continue
			}

			var esig ecdsaSignature
			_, err = asn1.Unmarshal(sigBytes, &esig)
			if err != nil {
				continue
			}

			if ecdsa.Verify(pub, hash[:], esig.R, esig.S) {
				valid++
				break verifiedAny
			}
		}
	}

	return valid >= parseVerifyPolicy(policy, len(sortedKeys)), nil
}