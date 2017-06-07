package verifystripe

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestParseHeader(t *testing.T) {
	sigHeader := "t=1496656679,v1=7c93299e968c08149227647f19604a7d3feddaf361baeac4f2ecd3063278caaa,v0=91ca1c05bb657affb318a700e10ebe1a0cf90cd782bd7927673f9c4882c01223"

	ts, sigs, err := parseHeader(sigHeader)
	if err != nil {
		t.Error(err)
	}

	if ts != "1496656679" {
		t.Error("timestamp is wrong")
	}

	sig, err := hex.DecodeString("7c93299e968c08149227647f19604a7d3feddaf361baeac4f2ecd3063278caaa")
	if err != nil {
		t.Error(err)
	}

	if len(sigs) != 1 && reflect.DeepEqual(sigs[0], sig) {
		t.Error("signature is wrong")
	}
}
