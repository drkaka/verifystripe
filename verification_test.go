package verifystripe

import (
	"testing"
)

func TestParseHeader(t *testing.T) {
	sigHeader := "t=1496656679,v1=7c93299e968c08149227647f19604a7d3feddaf361baeac4f2ecd3063278caaa,v0=91ca1c05bb657affb318a700e10ebe1a0cf90cd782bd7927673f9c4882c01223"

	ts, sigs := parseHeader(sigHeader)
	if ts != "1496656679" {
		t.Error("timestamp is wrong")
	}
	if len(sigs) != 1 && sigs[0] != "7c93299e968c08149227647f19604a7d3feddaf361baeac4f2ecd3063278caaa" {
		t.Error("signature is wrong")
	}
}
