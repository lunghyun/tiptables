// Package iptables provides a mock iptables simulator for learning purposes.
// Commands are parsed and applied to an in-memory state without requiring
// root privileges or actual kernel iptables support.
package iptables

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MockClient simulates iptables entirely in memory.
type MockClient struct {
	state   *State
	history []*Change
}

// NewMockClient initializes a mock client with default tables and chains.
func NewMockClient() *MockClient {
	state := &State{Tables: make(map[Table]*TableState)}
	for table, chains := range DefaultChains {
		ts := &TableState{Chains: make(map[string]*Chain)}
		for _, name := range chains {
			policy := "ACCEPT"
			if name == "FORWARD" {
				policy = "DROP"
			}
			ts.Chains[name] = &Chain{Name: name, Policy: policy, Rules: []*Rule{}}
		}
		state.Tables[table] = ts
	}
	return &MockClient{state: state}
}

// GetState returns the current iptables state (read-only copy).
func (c *MockClient) GetState() *State { return c.state }

// GetHistory returns all recorded changes.
func (c *MockClient) GetHistory() []*Change { return c.history }

// Reset resets the state to defaults.
func (c *MockClient) Reset() {
	fresh := NewMockClient()
	c.state = fresh.state
}

// Execute parses and applies an iptables command, recording the change.
func (c *MockClient) Execute(command string) (string, error) {
	before := c.state.Clone()
	output, err := c.execute(strings.TrimSpace(command))
	after := c.state.Clone()
	c.history = append(c.history, &Change{
		Command: command,
		Before:  before,
		After:   after,
		Output:  output,
		Err:     err,
		Time:    time.Now(),
	})
	return output, err
}

// execute is the internal parser/executor.
func (c *MockClient) execute(cmd string) (string, error) {
	// Strip optional "sudo" prefix
	cmd = strings.TrimPrefix(cmd, "sudo ")
	cmd = strings.TrimSpace(cmd)

	// Must start with "iptables"
	if !strings.HasPrefix(cmd, "iptables") {
		return "", fmt.Errorf("명령어는 'iptables'로 시작해야 합니다")
	}
	rest := strings.TrimSpace(strings.TrimPrefix(cmd, "iptables"))

	args := splitArgs(rest)
	if len(args) == 0 {
		return c.helpText(), nil
	}

	// Extract -t <table>
	table := TableFilter
	filtered := args[:0]
	for i := 0; i < len(args); i++ {
		if (args[i] == "-t" || args[i] == "--table") && i+1 < len(args) {
			table = Table(args[i+1])
			if _, ok := c.state.Tables[table]; !ok {
				return "", fmt.Errorf("알 수 없는 테이블: %q (filter, nat, mangle, raw 중 하나)", args[i+1])
			}
			i++
		} else {
			filtered = append(filtered, args[i])
		}
	}
	args = filtered

	if len(args) == 0 {
		return c.helpText(), nil
	}

	action := args[0]
	rest2 := args[1:]

	switch action {
	case "-A", "--append":
		return c.doAppend(table, rest2)
	case "-I", "--insert":
		return c.doInsert(table, rest2)
	case "-D", "--delete":
		return c.doDelete(table, rest2)
	case "-R", "--replace":
		return c.doReplace(table, rest2)
	case "-F", "--flush":
		return c.doFlush(table, rest2)
	case "-P", "--policy":
		return c.doPolicy(table, rest2)
	case "-L", "--list":
		return c.doList(table, rest2)
	case "-N", "--new-chain":
		return c.doNewChain(table, rest2)
	case "-X", "--delete-chain":
		return c.doDeleteChain(table, rest2)
	case "-Z", "--zero":
		return "[카운터 초기화 (시뮬레이터에서는 무시됨)]", nil
	case "-n", "--numeric":
		return c.doList(table, rest2)
	default:
		return "", fmt.Errorf("알 수 없는 옵션: %q\n'iptables --help' 참고", action)
	}
}

// doAppend handles -A <chain> <rule-spec>
func (c *MockClient) doAppend(t Table, args []string) (string, error) {
	chain, rest, err := c.getChain(t, args)
	if err != nil {
		return "", err
	}
	rule, err := parseRuleSpec(rest)
	if err != nil {
		return "", err
	}
	rule.Num = len(chain.Rules) + 1
	chain.Rules = append(chain.Rules, rule)
	renumber(chain)
	return "", nil
}

// doInsert handles -I <chain> [rulenum] <rule-spec>
func (c *MockClient) doInsert(t Table, args []string) (string, error) {
	chain, rest, err := c.getChain(t, args)
	if err != nil {
		return "", err
	}

	pos := 1
	if len(rest) > 0 {
		if n, e := strconv.Atoi(rest[0]); e == nil {
			pos = n
			rest = rest[1:]
		}
	}

	rule, err := parseRuleSpec(rest)
	if err != nil {
		return "", err
	}

	idx := pos - 1
	if idx < 0 {
		idx = 0
	}
	if idx > len(chain.Rules) {
		idx = len(chain.Rules)
	}

	chain.Rules = append(chain.Rules, nil)
	copy(chain.Rules[idx+1:], chain.Rules[idx:])
	chain.Rules[idx] = rule
	renumber(chain)
	return "", nil
}

// doDelete handles -D <chain> (rulenum | rule-spec)
func (c *MockClient) doDelete(t Table, args []string) (string, error) {
	chain, rest, err := c.getChain(t, args)
	if err != nil {
		return "", err
	}

	if len(rest) == 1 {
		if n, e := strconv.Atoi(rest[0]); e == nil {
			idx := n - 1
			if idx < 0 || idx >= len(chain.Rules) {
				return "", fmt.Errorf("규칙 번호 %d 가 범위를 벗어났습니다 (1~%d)", n, len(chain.Rules))
			}
			chain.Rules = append(chain.Rules[:idx], chain.Rules[idx+1:]...)
			renumber(chain)
			return "", nil
		}
	}

	rule, err := parseRuleSpec(rest)
	if err != nil {
		return "", err
	}
	for i, r := range chain.Rules {
		if ruleMatchSpec(r, rule) {
			chain.Rules = append(chain.Rules[:i], chain.Rules[i+1:]...)
			renumber(chain)
			return "", nil
		}
	}
	return "", fmt.Errorf("일치하는 규칙을 찾을 수 없습니다")
}

// doReplace handles -R <chain> <rulenum> <rule-spec>
func (c *MockClient) doReplace(t Table, args []string) (string, error) {
	chain, rest, err := c.getChain(t, args)
	if err != nil {
		return "", err
	}
	if len(rest) < 1 {
		return "", fmt.Errorf("-R 에는 규칙 번호가 필요합니다")
	}
	n, e := strconv.Atoi(rest[0])
	if e != nil {
		return "", fmt.Errorf("규칙 번호가 유효하지 않습니다: %s", rest[0])
	}
	idx := n - 1
	if idx < 0 || idx >= len(chain.Rules) {
		return "", fmt.Errorf("규칙 번호 %d 가 범위를 벗어났습니다", n)
	}
	rule, err := parseRuleSpec(rest[1:])
	if err != nil {
		return "", err
	}
	chain.Rules[idx] = rule
	renumber(chain)
	return "", nil
}

// doFlush handles -F [chain]
func (c *MockClient) doFlush(t Table, args []string) (string, error) {
	ts := c.state.Tables[t]
	if len(args) == 0 {
		for _, ch := range ts.Chains {
			ch.Rules = []*Rule{}
		}
		return "", nil
	}
	chain, ok := ts.Chains[args[0]]
	if !ok {
		return "", fmt.Errorf("체인 없음: %s", args[0])
	}
	chain.Rules = []*Rule{}
	return "", nil
}

// doPolicy handles -P <chain> <target>
func (c *MockClient) doPolicy(t Table, args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("-P 에는 체인 이름과 정책(ACCEPT|DROP)이 필요합니다")
	}
	ts := c.state.Tables[t]
	chain, ok := ts.Chains[args[0]]
	if !ok {
		return "", fmt.Errorf("체인 없음: %s", args[0])
	}
	pol := strings.ToUpper(args[1])
	if pol != "ACCEPT" && pol != "DROP" {
		return "", fmt.Errorf("정책은 ACCEPT 또는 DROP 이어야 합니다")
	}
	// Only built-in chains can have policies
	isBuiltin := false
	for _, name := range DefaultChains[t] {
		if name == args[0] {
			isBuiltin = true
			break
		}
	}
	if !isBuiltin {
		return "", fmt.Errorf("사용자 정의 체인에는 정책을 설정할 수 없습니다")
	}
	chain.Policy = pol
	return "", nil
}

// doList handles -L [chain]
func (c *MockClient) doList(t Table, args []string) (string, error) {
	ts := c.state.Tables[t]
	var sb strings.Builder
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		chainName := args[0]
		chain, ok := ts.Chains[chainName]
		if !ok {
			return "", fmt.Errorf("체인 없음: %s", chainName)
		}
		sb.WriteString(formatChainText(chainName, chain))
	} else {
		for _, name := range getChainOrder(t, ts) {
			chain := ts.Chains[name]
			sb.WriteString(formatChainText(name, chain))
			sb.WriteString("\n")
		}
	}
	return sb.String(), nil
}

// doNewChain handles -N <chain>
func (c *MockClient) doNewChain(t Table, args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("-N 에는 체인 이름이 필요합니다")
	}
	ts := c.state.Tables[t]
	if _, ok := ts.Chains[args[0]]; ok {
		return "", fmt.Errorf("체인 이미 존재: %s", args[0])
	}
	ts.Chains[args[0]] = &Chain{Name: args[0], Policy: "-", Rules: []*Rule{}}
	return "", nil
}

// doDeleteChain handles -X [chain]
func (c *MockClient) doDeleteChain(t Table, args []string) (string, error) {
	ts := c.state.Tables[t]
	builtins := make(map[string]bool)
	for _, name := range DefaultChains[t] {
		builtins[name] = true
	}
	if len(args) == 0 {
		for name, ch := range ts.Chains {
			if !builtins[name] && len(ch.Rules) == 0 {
				delete(ts.Chains, name)
			}
		}
		return "", nil
	}
	name := args[0]
	if builtins[name] {
		return "", fmt.Errorf("기본 체인은 삭제할 수 없습니다: %s", name)
	}
	ch, ok := ts.Chains[name]
	if !ok {
		return "", fmt.Errorf("체인 없음: %s", name)
	}
	if len(ch.Rules) > 0 {
		return "", fmt.Errorf("체인이 비어있지 않습니다 (먼저 -F로 비우세요)")
	}
	delete(ts.Chains, name)
	return "", nil
}

// getChain extracts the chain name from args and returns the chain and remaining args.
func (c *MockClient) getChain(t Table, args []string) (*Chain, []string, error) {
	if len(args) == 0 {
		return nil, nil, fmt.Errorf("체인 이름이 필요합니다")
	}
	ts := c.state.Tables[t]
	chain, ok := ts.Chains[args[0]]
	if !ok {
		return nil, nil, fmt.Errorf("체인 없음: %q (테이블 %q에 없음)\n사용 가능: %s",
			args[0], t, strings.Join(getChainOrder(t, ts), ", "))
	}
	return chain, args[1:], nil
}

// parseRuleSpec parses iptables match/target flags into a Rule.
func parseRuleSpec(args []string) (*Rule, error) {
	r := &Rule{
		Source:  "0.0.0.0/0",
		Dest:    "0.0.0.0/0",
		Proto:   "all",
		Options: make(map[string]string),
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s 뒤에 값이 필요합니다", arg)
			}
			i++
			return args[i], nil
		}

		switch arg {
		case "-j", "--jump":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Target = strings.ToUpper(v)
		case "-p", "--protocol":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Proto = strings.ToLower(v)
		case "-s", "--source":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Source = v
		case "-d", "--destination":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Dest = v
		case "-i", "--in-interface":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.InIface = v
		case "-o", "--out-interface":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.OutIface = v
		case "-m", "--match":
			// Consume module name but don't store separately; its options follow
			if i+1 < len(args) {
				i++ // skip module name, options parsed below
			}
		case "--dport", "--destination-port":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Options["dport"] = v
		case "--sport", "--source-port":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Options["sport"] = v
		case "--dports":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Options["dports"] = v
		case "--sports":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Options["sports"] = v
		case "--state", "--ctstate":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Options["state"] = v
		case "--to-destination":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Options["to-dst"] = v
		case "--to-source":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Options["to-src"] = v
		case "--to-ports":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Options["to-ports"] = v
		case "--icmp-type":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Options["icmp-type"] = v
		case "--log-prefix":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Options["log-prefix"] = v
		case "--log-level":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Options["log-level"] = v
		case "--reject-with":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Options["reject-with"] = v
		case "--limit":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Options["limit"] = v
		case "--limit-burst":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Options["limit-burst"] = v
		case "--comment":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Options["comment"] = v
		case "--mac-source":
			v, err := next()
			if err != nil {
				return nil, err
			}
			r.Options["mac-src"] = v
		case "!":
			// Negation — skip the negated flag for simplicity
		default:
			// Consume unknown --flag value pairs gracefully
			if strings.HasPrefix(arg, "--") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				key := strings.TrimPrefix(arg, "--")
				r.Options[key] = args[i+1]
				i++
			}
		}
	}

	if r.Target == "" {
		return nil, fmt.Errorf("타겟(-j)이 지정되지 않았습니다\n예: -j ACCEPT | DROP | REJECT | LOG | DNAT | SNAT | MASQUERADE")
	}
	return r, nil
}

// ruleMatchSpec returns true if rule r matches the spec s (ignoring Num).
func ruleMatchSpec(r, s *Rule) bool {
	if s.Target != "" && r.Target != s.Target {
		return false
	}
	if s.Proto != "all" && r.Proto != s.Proto {
		return false
	}
	if s.Source != "0.0.0.0/0" && r.Source != s.Source {
		return false
	}
	if s.Dest != "0.0.0.0/0" && r.Dest != s.Dest {
		return false
	}
	if s.InIface != "" && r.InIface != s.InIface {
		return false
	}
	if s.OutIface != "" && r.OutIface != s.OutIface {
		return false
	}
	for k, v := range s.Options {
		if r.Options[k] != v {
			return false
		}
	}
	return true
}

// renumber resets rule Num fields to match their slice index (1-based).
func renumber(chain *Chain) {
	for i, r := range chain.Rules {
		r.Num = i + 1
	}
}

// getChainOrder returns chain names in the canonical default order, followed by user chains.
func getChainOrder(t Table, ts *TableState) []string {
	seen := make(map[string]bool)
	var out []string
	for _, name := range DefaultChains[t] {
		if _, ok := ts.Chains[name]; ok {
			out = append(out, name)
			seen[name] = true
		}
	}
	for name := range ts.Chains {
		if !seen[name] {
			out = append(out, name)
		}
	}
	return out
}

// formatChainText renders a chain as plain text (like iptables -L).
func formatChainText(name string, chain *Chain) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Chain %s (policy %s)\n", name, chain.Policy))
	sb.WriteString(fmt.Sprintf("%-4s %-12s %-6s %-18s %-18s %s\n",
		"num", "target", "prot", "source", "destination", "options"))
	for _, r := range chain.Rules {
		opts := r.ShortString()[len(r.Target)+len(r.Proto)+2:]
		_ = opts
		sb.WriteString(fmt.Sprintf("%-4d %s\n", r.Num, r.ShortString()))
	}
	return sb.String()
}

// splitArgs splits a string into tokens, respecting single and double quotes.
func splitArgs(s string) []string {
	var args []string
	var cur strings.Builder
	inQ := false
	var qChar byte

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQ:
			if c == qChar {
				inQ = false
				args = append(args, cur.String())
				cur.Reset()
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			inQ = true
			qChar = c
		case c == ' ' || c == '\t':
			if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args
}

func (c *MockClient) helpText() string {
	return `사용법: iptables [-t table] action chain [matches] -j target

테이블 (-t):  filter(기본), nat, mangle, raw

액션:
  -A chain      규칙 추가 (append)
  -I chain [n]  규칙 삽입 (insert, 기본 위치 1)
  -D chain [n]  규칙 삭제 (번호 또는 규칙 명세)
  -R chain n    규칙 교체 (replace)
  -F [chain]    체인 비우기 (flush)
  -P chain pol  기본 정책 설정 (ACCEPT|DROP)
  -L [chain]    규칙 목록 출력
  -N chain      사용자 체인 생성
  -X [chain]    사용자 체인 삭제

매치:
  -p proto      프로토콜 (tcp, udp, icmp, all)
  -s source     출발지 IP/마스크
  -d dest       목적지 IP/마스크
  -i iface      입력 인터페이스
  -o iface      출력 인터페이스
  -m module     모듈 로드 (state, conntrack, multiport, limit 등)
  --dport port  목적지 포트 (tcp/udp)
  --sport port  출발지 포트
  --state S     연결 상태 (NEW, ESTABLISHED, RELATED, INVALID)
  --ctstate S   conntrack 상태

타겟 (-j):
  ACCEPT        패킷 허용
  DROP          패킷 조용히 차단
  REJECT        패킷 거부 (오류 응답)
  LOG           로그 기록 후 다음 규칙 계속
  MASQUERADE    NAT (nat/POSTROUTING)
  DNAT          목적지 NAT (nat/PREROUTING)
  SNAT          출발지 NAT (nat/POSTROUTING)`
}
