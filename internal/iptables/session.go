package iptables

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Session is the data persisted to disk between tiptables runs.
type Session struct {
	State      *State   `json:"state"`
	CmdHistory []string `json:"cmd_history"`
}

// sessionPath returns the path to the session file (~/.tiptables/session.json).
func sessionPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".tiptables", "session.json")
}

// SaveSession writes the current state and command history to disk.
func SaveSession(state *State, cmdHistory []string) error {
	path := sessionPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	s := &Session{State: state, CmdHistory: cmdHistory}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadSession reads the session file and returns the saved Session.
// Returns nil, nil if no session file exists yet.
func LoadSession() (*Session, error) {
	path := sessionPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil // first run — no session yet
		}
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	// Ensure all maps are non-nil after JSON unmarshal
	if s.State != nil {
		s.State = sanitizeState(s.State)
	}
	return &s, nil
}

// sanitizeState ensures all nested maps and slices are non-nil after JSON decode.
func sanitizeState(s *State) *State {
	if s.Tables == nil {
		s.Tables = make(map[Table]*TableState)
	}
	for t, ts := range s.Tables {
		if ts == nil {
			s.Tables[t] = &TableState{Chains: make(map[string]*Chain)}
			continue
		}
		if ts.Chains == nil {
			ts.Chains = make(map[string]*Chain)
		}
		for name, chain := range ts.Chains {
			if chain == nil {
				ts.Chains[name] = &Chain{Name: name, Policy: "ACCEPT", Rules: []*Rule{}}
				continue
			}
			if chain.Rules == nil {
				chain.Rules = []*Rule{}
			}
			for _, rule := range chain.Rules {
				if rule != nil && rule.Options == nil {
					rule.Options = make(map[string]string)
				}
			}
		}
	}
	return s
}

// SetState replaces the client's internal state with the provided one.
func (c *MockClient) SetState(s *State) {
	c.state = s
}
