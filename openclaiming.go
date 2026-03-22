package openclaiming

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"math/big"
	"sort"

	jcs "github.com/gowebpki/jcs"
)

type ecdsaSignature struct {
	R, S *big.Int
}

// ---------- CACHE ----------

var (
	fetchCache     = map[string]struct{
		t time.Time
		data []byte
	}{}
	fetchCacheLock sync.Mutex
	fetchTtl       = 300 * time.Second
)

func fetchCached(url string) []byte {

	now := time.Now()

	fetchCacheLock.Lock()
	if entry, ok := fetchCache[url]; ok {
		if now.Sub(entry.t) < fetchTtl {
			data := entry.data
			fetchCacheLock.Unlock()
			return data
		}
	}
	fetchCacheLock.Unlock()

	var body []byte

	resp, err := http.Get(url)
	if err == nil && resp != nil {
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			body, _ = io.ReadAll(resp.Body)
		}
	}

	fetchCacheLock.Lock()
	fetchCache[url] = struct{
		t time.Time
		data []byte
	}{now, body}
	fetchCacheLock.Unlock()

	return body
}

func ClearFetchCache(url *string) {

	fetchCacheLock.Lock()
	defer fetchCacheLock.Unlock()

	if url == nil {
		fetchCache = map[string]struct{
			t time.Time
			data []byte
		}{}
		return
	}

	delete(fetchCache, *url)
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

	// Try strict RFC8785 canonicalization
	canon, err := jcs.Transform(raw)
	if err == nil {
		return canon, nil
	}

	// Fallback deterministic canonicalization
	return fallbackCanonicalize(claim)
}

// ---------- NEW HELPERS ----------

func resolveKey(keyStr string) (string, string, bool) {

	parts := strings.SplitN(keyStr, ":", 2)
	if len(parts) < 2 {
		return "", "", false
	}

	typ := strings.ToUpper(parts[0])
	rest := parts[1]

	if strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://") {

		segments := strings.Split(rest, "#")
		url := segments[0]

		raw := fetchCached(url)
		if raw == nil {
			return "", "", false
		}

		var data interface{}
		if err := json.Unmarshal(raw, &data); err != nil {
			return "", "", false
		}

		current := data

		for i := 1; i < len(segments); i++ {

			key := segments[i]
			if key == "" {
				continue
			}

			m, ok := current.(map[string]interface{})
			if !ok {
				return "", "", false
			}

			current = m[key]

			// OPTIONAL SAFETY: match behavior of other langs
			if current == nil {
				return "", "", false
			}
		}

		val, ok := current.(string)
		if !ok {
			return "", "", false
		}

		return typ, val, true
	}

	return typ, rest, true
}

func Sign(claim map[string]interface{}, priv *ecdsa.PrivateKey) (map[string]interface{}, error) {

	canon, err := Canonicalize(claim)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(canon)

	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		return nil, err
	}

	sig, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return nil, err
	}

	out := map[string]interface{}{}
	for k, v := range claim {
		out[k] = v
	}

	out["sig"] = base64.StdEncoding.EncodeToString(sig)

	return out, nil
}

func Verify(claim map[string]interface{}, pub *ecdsa.PublicKey) (bool, error) {

	sigB64, ok := claim["sig"].(string)
	if !ok {
		return false, errors.New("missing signature")
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, err
	}

	var esig ecdsaSignature
	_, err = asn1.Unmarshal(sig, &esig)
	if err != nil {
		return false, err
	}

	canon, err := Canonicalize(claim)
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256(canon)

	ok = ecdsa.Verify(pub, hash[:], esig.R, esig.S)

	return ok, nil
}