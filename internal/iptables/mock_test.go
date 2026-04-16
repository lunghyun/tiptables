package iptables_test

import (
	"strings"
	"testing"

	"github.com/nangm/iptables-lab/internal/iptables"
)

func TestAppendAndDelete(t *testing.T) {
	c := iptables.NewMockClient()

	// Append
	if _, err := c.Execute("iptables -A INPUT -p tcp --dport 22 -j ACCEPT"); err != nil {
		t.Fatalf("append failed: %v", err)
	}
	s := c.GetState()
	chain := s.Tables[iptables.TableFilter].Chains["INPUT"]
	if len(chain.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(chain.Rules))
	}
	if chain.Rules[0].Options["dport"] != "22" {
		t.Errorf("expected dport 22, got %s", chain.Rules[0].Options["dport"])
	}

	// Delete by number
	if _, err := c.Execute("iptables -D INPUT 1"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if len(chain.Rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(chain.Rules))
	}
}

func TestPolicy(t *testing.T) {
	c := iptables.NewMockClient()

	if _, err := c.Execute("iptables -P INPUT DROP"); err != nil {
		t.Fatalf("policy failed: %v", err)
	}
	chain := c.GetState().Tables[iptables.TableFilter].Chains["INPUT"]
	if chain.Policy != "DROP" {
		t.Errorf("expected DROP, got %s", chain.Policy)
	}
}

func TestNAT(t *testing.T) {
	c := iptables.NewMockClient()

	cmd := "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
	if _, err := c.Execute(cmd); err != nil {
		t.Fatalf("nat failed: %v", err)
	}
	chain := c.GetState().Tables[iptables.TableNAT].Chains["POSTROUTING"]
	if len(chain.Rules) != 1 {
		t.Fatalf("expected 1 nat rule, got %d", len(chain.Rules))
	}
	if chain.Rules[0].Target != "MASQUERADE" {
		t.Errorf("expected MASQUERADE, got %s", chain.Rules[0].Target)
	}
}

func TestFlush(t *testing.T) {
	c := iptables.NewMockClient()
	c.Execute("iptables -A INPUT -p tcp --dport 80 -j ACCEPT")
	c.Execute("iptables -A INPUT -p tcp --dport 443 -j ACCEPT")

	c.Execute("iptables -F INPUT")
	chain := c.GetState().Tables[iptables.TableFilter].Chains["INPUT"]
	if len(chain.Rules) != 0 {
		t.Fatalf("expected 0 rules after flush, got %d", len(chain.Rules))
	}
}

func TestInsert(t *testing.T) {
	c := iptables.NewMockClient()
	c.Execute("iptables -A INPUT -p tcp --dport 80 -j ACCEPT")
	c.Execute("iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT") // insert before 80

	chain := c.GetState().Tables[iptables.TableFilter].Chains["INPUT"]
	if len(chain.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(chain.Rules))
	}
	if chain.Rules[0].Options["dport"] != "22" {
		t.Errorf("expected rule #1 to be port 22, got %s", chain.Rules[0].Options["dport"])
	}
}

func TestDiff(t *testing.T) {
	c := iptables.NewMockClient()
	before := c.GetState().Clone()
	c.Execute("iptables -A INPUT -p tcp --dport 8080 -j ACCEPT")
	after := c.GetState().Clone()

	diffs := iptables.Diff(before, after)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Kind != iptables.DiffAdded {
		t.Errorf("expected DiffAdded, got %s", diffs[0].Kind)
	}
}

func TestHistory(t *testing.T) {
	c := iptables.NewMockClient()
	c.Execute("iptables -A INPUT -p tcp --dport 22 -j ACCEPT")
	c.Execute("iptables -A INPUT -p tcp --dport 80 -j ACCEPT")

	h := c.GetHistory()
	if len(h) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(h))
	}
}

func TestUserChain(t *testing.T) {
	c := iptables.NewMockClient()
	if _, err := c.Execute("iptables -N MYCHAIN"); err != nil {
		t.Fatalf("new chain failed: %v", err)
	}
	if _, err := c.Execute("iptables -X MYCHAIN"); err != nil {
		t.Fatalf("delete chain failed: %v", err)
	}
}

func TestErrorHandling(t *testing.T) {
	c := iptables.NewMockClient()

	// Unknown table
	if _, err := c.Execute("iptables -t badtable -L"); err == nil {
		t.Error("expected error for unknown table")
	}

	// Unknown chain
	if _, err := c.Execute("iptables -A BADCHAIN -j ACCEPT"); err == nil {
		t.Error("expected error for unknown chain")
	}

	// Missing target
	if _, err := c.Execute("iptables -A INPUT -p tcp"); err == nil {
		t.Error("expected error for missing target")
	}
}

func TestStateToSave(t *testing.T) {
	c := iptables.NewMockClient()
	c.Execute("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
	c.Execute("iptables -A INPUT -i lo -j ACCEPT")
	c.Execute("iptables -A INPUT -p tcp --dport 22 -j ACCEPT")
	c.Execute("iptables -A INPUT -p tcp --dport 80 -j ACCEPT")
	c.Execute("iptables -A INPUT -p icmp -j ACCEPT")
	c.Execute("iptables -P INPUT DROP")
	c.Execute("iptables -P FORWARD DROP")
	c.Execute("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
	c.Execute("iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.10:80")

	out := iptables.StateToSave(c.GetState())
	t.Log("\n" + out)

	checks := map[string]string{
		"*filter":    "filter 테이블 없음",
		":INPUT DROP": "INPUT DROP 정책 없음",
		"-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT": "state 규칙 없음",
		"-A INPUT -p tcp --dport 22 -j ACCEPT":                    "SSH 규칙 없음",
		"*nat":                           "nat 테이블 없음",
		"-A POSTROUTING -o eth0 -j MASQUERADE": "MASQUERADE 없음",
		"--to-destination 192.168.1.10:80":     "DNAT 없음",
		"COMMIT":                               "COMMIT 없음",
	}
	for needle, msg := range checks {
		if !strings.Contains(out, needle) {
			t.Error(msg)
		}
	}
}
