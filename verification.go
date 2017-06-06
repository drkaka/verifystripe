package verifystripe

import (
	"crypto/hmac"
	"crypto/sha256"
	"strconv"
	"strings"
	"time"
)

// Verify the webhook event.
func Verify(payload, sigHeader, secret string) (bool, error) {
	ts, sigs := parseHeader(sigHeader)
	if len(sigs) == 0 {
		return false, nil
	}

	if ok, err := checkSignature(ts+"."+payload, secret, sigs); err != nil {
		return false, err
	} else if !ok {
		return false, nil
	}

	now := time.Now().Unix()
	timestamp, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false, err
	}

	if now-timestamp > 300 {
		return false, nil
	}
	return true, nil
}

// parseHeader to get detail from header["Stripe-Signature"]
// return timestamp string and signature
func parseHeader(sigHeader string) (string, []string) {
	ts := "0"
	allSigs := make([]string, 0)

	sigs := strings.Split(sigHeader, ",")
	for _, one := range sigs {
		info := strings.Split(one, "=")
		if len(info) != 2 {
			return ts, allSigs
		}
		if info[0] == "t" {
			ts = info[1]
		} else if info[0] == "v1" {
			allSigs = append(allSigs, info[1])
		}
	}
	return ts, allSigs
}

func checkSignature(payload, secret string, sigs []string) (bool, error) {
	mac := hmac.New(sha256.New, []byte(secret))
	_, err := mac.Write([]byte(payload))
	if err != nil {
		return false, err
	}
	computed := mac.Sum(nil)
	for _, one := range sigs {
		if hmac.Equal(computed, []byte(one)) {
			return true, nil
		}
	}
	return false, nil
}
