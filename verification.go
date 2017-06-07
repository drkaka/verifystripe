package verifystripe

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// Verify the webhook event.
func Verify(payload []byte, sigHeader, secret string) (bool, error) {
	ts, sigs, err := parseHeader(sigHeader)
	if err != nil {
		return false, err
	} else if len(sigs) == 0 {
		return false, nil
	}

	realPayload := append(append([]byte(ts), '.'), payload...)
	if ok, err := checkSignature(realPayload, secret, sigs); err != nil {
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
func parseHeader(sigHeader string) (string, [][]byte, error) {
	ts := "0"
	var allSigs [][]byte

	sigs := strings.Split(sigHeader, ",")
	for _, one := range sigs {
		info := strings.Split(one, "=")
		if len(info) != 2 {
			return ts, allSigs, nil
		}
		if info[0] == "t" {
			ts = info[1]
		} else if info[0] == "v1" {
			oneSig, err := hex.DecodeString(info[1])
			if err != nil {
				return "", allSigs, err
			}
			allSigs = append(allSigs, oneSig)
		}
	}
	return ts, allSigs, nil
}

func checkSignature(payload []byte, secret string, sigs [][]byte) (bool, error) {
	mac := hmac.New(sha256.New, []byte(secret))
	_, err := mac.Write(payload)
	if err != nil {
		return false, err
	}
	computed := mac.Sum(nil)
	for _, one := range sigs {
		if hmac.Equal(computed, one) {
			return true, nil
		}
	}
	return false, nil
}
