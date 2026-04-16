package iptables

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Table represents an iptables table name.
type Table string

const (
	TableFilter Table = "filter"
	TableNAT    Table = "nat"
	TableMangle Table = "mangle"
	TableRaw    Table = "raw"
)

// AllTables is the ordered list of all supported tables.
var AllTables = []Table{TableFilter, TableNAT, TableMangle, TableRaw}

// DefaultChains maps each table to its built-in chain names.
var DefaultChains = map[Table][]string{
	TableFilter: {"INPUT", "FORWARD", "OUTPUT"},
	TableNAT:    {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"},
	TableMangle: {"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"},
	TableRaw:    {"PREROUTING", "OUTPUT"},
}

// Rule represents a single iptables rule.
type Rule struct {
	Num      int               // Position in chain (1-indexed)
	Target   string            // ACCEPT, DROP, REJECT, LOG, DNAT, SNAT, MASQUERADE, ...
	Proto    string            // tcp, udp, icmp, all
	InIface  string            // -i (input interface)
	OutIface string            // -o (output interface)
	Source   string            // -s source IP/mask
	Dest     string            // -d destination IP/mask
	Options  map[string]string // --dport, --sport, --state, --to-destination, etc.
}

// ShortString returns a compact single-line representation of the rule.
func (r *Rule) ShortString() string {
	var parts []string
	parts = append(parts, fmt.Sprintf("%-12s", r.Target))
	parts = append(parts, fmt.Sprintf("%-6s", r.Proto))
	src := r.Source
	if src == "" {
		src = "0.0.0.0/0"
	}
	dst := r.Dest
	if dst == "" {
		dst = "0.0.0.0/0"
	}
	parts = append(parts, fmt.Sprintf("%-18s", src))
	parts = append(parts, fmt.Sprintf("%-18s", dst))

	var opts []string
	if r.InIface != "" {
		opts = append(opts, "in:"+r.InIface)
	}
	if r.OutIface != "" {
		opts = append(opts, "out:"+r.OutIface)
	}
	// Sort options for stable output
	keys := make([]string, 0, len(r.Options))
	for k := range r.Options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		opts = append(opts, k+":"+r.Options[k])
	}
	if len(opts) > 0 {
		parts = append(parts, strings.Join(opts, " "))
	}
	return strings.Join(parts, " ")
}

// Key returns a string uniquely identifying this rule's content (ignoring Num).
func (r *Rule) Key() string {
	keys := make([]string, 0, len(r.Options))
	for k := range r.Options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var opts []string
	for _, k := range keys {
		opts = append(opts, k+"="+r.Options[k])
	}
	return fmt.Sprintf("target=%s proto=%s in=%s out=%s src=%s dst=%s opts=[%s]",
		r.Target, r.Proto, r.InIface, r.OutIface, r.Source, r.Dest, strings.Join(opts, ","))
}

// Chain represents an iptables chain.
type Chain struct {
	Name   string  // e.g. INPUT, FORWARD, PREROUTING
	Policy string  // ACCEPT, DROP (built-in), or "-" (user-defined)
	Rules  []*Rule // Ordered list of rules
}

// TableState holds all chains within a single table.
type TableState struct {
	Chains map[string]*Chain
}

// State is the complete iptables state across all tables.
type State struct {
	Tables map[Table]*TableState
}

// Clone creates a deep copy of the state.
func (s *State) Clone() *State {
	if s == nil {
		return nil
	}
	ns := &State{Tables: make(map[Table]*TableState, len(s.Tables))}
	for t, ts := range s.Tables {
		nts := &TableState{Chains: make(map[string]*Chain, len(ts.Chains))}
		for name, chain := range ts.Chains {
			nc := &Chain{
				Name:   chain.Name,
				Policy: chain.Policy,
				Rules:  make([]*Rule, len(chain.Rules)),
			}
			for i, rule := range chain.Rules {
				nr := &Rule{
					Num:      rule.Num,
					Target:   rule.Target,
					Proto:    rule.Proto,
					InIface:  rule.InIface,
					OutIface: rule.OutIface,
					Source:   rule.Source,
					Dest:     rule.Dest,
					Options:  make(map[string]string, len(rule.Options)),
				}
				for k, v := range rule.Options {
					nr.Options[k] = v
				}
				nc.Rules[i] = nr
			}
			nts.Chains[name] = nc
		}
		ns.Tables[t] = nts
	}
	return ns
}

// Change records a single iptables command execution and its effect.
type Change struct {
	Command string
	Before  *State
	After   *State
	Output  string
	Err     error
	Time    time.Time
}
