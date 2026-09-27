package checker

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// mcpcheck.go is shared verbatim between alertkick-poller/checker and
// alertkick-api/scheduler (only the package line differs). When you edit it,
// copy it to the other repo and update this hash in BOTH repos:
//
//	tail -n +2 mcpcheck.go | sha256sum
const mcpcheckSharedHash = "2fa6ecc31f0ca8068c9b603ad71ac6448dfa1e0d81604270d8cd5d5e5084c7d7"

func TestMCPCheckSharedCopyInSync(t *testing.T) {
	b, err := os.ReadFile("mcpcheck.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	body := s[strings.Index(s, "\n")+1:]
	sum := sha256.Sum256([]byte(body))
	if got := hex.EncodeToString(sum[:]); got != mcpcheckSharedHash {
		t.Fatalf("mcpcheck.go changed (hash %s); sync the other repo's copy and update mcpcheckSharedHash in both", got)
	}
}
