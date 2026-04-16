package iptables

// DiffKind indicates whether a rule was added, removed, or a policy changed.
type DiffKind string

const (
	DiffAdded         DiffKind = "added"
	DiffRemoved       DiffKind = "removed"
	DiffPolicyChanged DiffKind = "policy"
)

// RuleDiff describes a change to a single rule or chain policy.
type RuleDiff struct {
	Kind      DiffKind
	Table     Table
	ChainName string
	Rule      *Rule  // the rule that was added or removed
	OldPolicy string // for DiffPolicyChanged
	NewPolicy string
}

// Diff computes the difference between two states and returns a list of changes.
func Diff(before, after *State) []RuleDiff {
	var diffs []RuleDiff
	for _, table := range AllTables {
		bt := before.Tables[table]
		at := after.Tables[table]
		if bt == nil || at == nil {
			continue
		}
		diffs = append(diffs, diffTable(table, bt, at)...)
	}
	return diffs
}

func diffTable(table Table, before, after *TableState) []RuleDiff {
	var diffs []RuleDiff

	// Collect all chain names
	allChains := make(map[string]bool)
	for name := range before.Chains {
		allChains[name] = true
	}
	for name := range after.Chains {
		allChains[name] = true
	}

	// For each chain, compute rule diffs
	for name := range allChains {
		bc := before.Chains[name]
		ac := after.Chains[name]
		diffs = append(diffs, diffChain(table, name, bc, ac)...)
	}
	return diffs
}

func diffChain(table Table, name string, before, after *Chain) []RuleDiff {
	var diffs []RuleDiff

	if before == nil {
		// Entirely new chain
		if after != nil {
			for _, r := range after.Rules {
				diffs = append(diffs, RuleDiff{Kind: DiffAdded, Table: table, ChainName: name, Rule: r})
			}
		}
		return diffs
	}
	if after == nil {
		// Chain deleted
		for _, r := range before.Rules {
			diffs = append(diffs, RuleDiff{Kind: DiffRemoved, Table: table, ChainName: name, Rule: r})
		}
		return diffs
	}

	// Policy change
	if before.Policy != after.Policy {
		diffs = append(diffs, RuleDiff{
			Kind:      DiffPolicyChanged,
			Table:     table,
			ChainName: name,
			OldPolicy: before.Policy,
			NewPolicy: after.Policy,
		})
	}

	// Build key sets
	beforeKeys := make(map[string]*Rule)
	afterKeys := make(map[string]*Rule)
	for _, r := range before.Rules {
		beforeKeys[r.Key()] = r
	}
	for _, r := range after.Rules {
		afterKeys[r.Key()] = r
	}

	// Rules removed
	for key, r := range beforeKeys {
		if _, ok := afterKeys[key]; !ok {
			diffs = append(diffs, RuleDiff{Kind: DiffRemoved, Table: table, ChainName: name, Rule: r})
		}
	}
	// Rules added
	for key, r := range afterKeys {
		if _, ok := beforeKeys[key]; !ok {
			diffs = append(diffs, RuleDiff{Kind: DiffAdded, Table: table, ChainName: name, Rule: r})
		}
	}
	return diffs
}

// HasChanges returns true if the diff contains any actual changes.
func HasChanges(diffs []RuleDiff) bool {
	return len(diffs) > 0
}
