package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/nangm/iptables-lab/internal/iptables"
	"github.com/nangm/iptables-lab/internal/study"
)

// ─── Content dispatcher ───────────────────────────────────────────────────────

func (m *Model) viewContent() string {
	inner := m.width - 2
	if inner < 20 {
		inner = 20
	}
	switch m.activeTab {
	case tabRules:
		return m.viewRules(inner)
	case tabHistory:
		return m.viewHistory(inner)
	case tabConf:
		return m.viewConf(inner)
	case tabStudy:
		return m.viewStudy(inner)
	}
	return ""
}

// ─── Rules Tab ────────────────────────────────────────────────────────────────

func (m *Model) viewRules(width int) string {
	state := m.client.GetState()
	table := iptables.AllTables[m.tableIdx]
	ts := state.Tables[table]
	chainNames := getChainNames(table, ts)

	// Clamp chainIdx
	if m.chainIdx >= len(chainNames) {
		m.chainIdx = 0
	}

	var lines []string

	// Table selector bar
	var tableTabs []string
	for i, t := range iptables.AllTables {
		s := string(t)
		if i == m.tableIdx {
			tableTabs = append(tableTabs, styleTabActive.Render(s))
		} else {
			tableTabs = append(tableTabs, styleTabInactive.Render(s))
		}
	}
	lines = append(lines, "  "+lipgloss.JoinHorizontal(lipgloss.Left, tableTabs...))
	lines = append(lines, "")

	// Chain selector bar
	var chainTabs []string
	for i, name := range chainNames {
		chain := ts.Chains[name]
		label := fmt.Sprintf("%s(%s)", name, chain.Policy)
		if i == m.chainIdx {
			chainTabs = append(chainTabs, styleChainBadge.Copy().
				Underline(true).Background(lipgloss.Color("#1e293b")).
				Padding(0, 1).Render(label))
		} else {
			chainTabs = append(chainTabs, styleMuted.Copy().Padding(0, 1).Render(label))
		}
	}
	lines = append(lines, "  "+lipgloss.JoinHorizontal(lipgloss.Left, chainTabs...))
	lines = append(lines, "")

	// Rules table for selected chain
	chainName := chainNames[m.chainIdx]
	chain := ts.Chains[chainName]
	lines = append(lines, m.renderRulesTable(chain, width-4)...)

	// Apply scroll
	visible := lines
	if m.scroll < len(lines) {
		visible = lines[m.scroll:]
	}
	return "  " + strings.Join(visible, "\n  ")
}

func (m *Model) renderRulesTable(chain *iptables.Chain, width int) []string {
	var lines []string

	header := styleHeader.Render(fmt.Sprintf(
		"%-4s  %-12s  %-6s  %-18s  %-18s  %s",
		"#", "TARGET", "PROT", "SOURCE", "DEST", "OPTIONS",
	))
	lines = append(lines, header)
	lines = append(lines, styleSeparator.Render(strings.Repeat("─", min(width, 80))))

	if len(chain.Rules) == 0 {
		lines = append(lines, styleMuted.Render("  (규칙 없음)"))
	}

	for _, r := range chain.Rules {
		num := styleRuleNum.Render(fmt.Sprintf("%d", r.Num))
		tgt := colorTarget(r.Target)
		src := r.Source
		if src == "" {
			src = "0.0.0.0/0"
		}
		dst := r.Dest
		if dst == "" {
			dst = "0.0.0.0/0"
		}

		opts := formatOpts(r)

		line := fmt.Sprintf("%s  %-12s  %-6s  %-18s  %-18s  %s",
			num,
			tgt,
			styleMuted.Render(r.Proto),
			styleBase.Render(src),
			styleBase.Render(dst),
			styleMuted.Render(opts),
		)
		lines = append(lines, line)
	}
	return lines
}

func colorTarget(target string) string {
	switch strings.ToUpper(target) {
	case "ACCEPT":
		return styleSuccess.Width(12).Render(target)
	case "DROP", "REJECT":
		return styleError.Width(12).Render(target)
	case "LOG":
		return styleWarning.Width(12).Render(target)
	case "MASQUERADE", "DNAT", "SNAT":
		return stylePolicy.Width(12).Render(target)
	default:
		return stylePrimary.Width(12).Render(target)
	}
}

func formatOpts(r *iptables.Rule) string {
	var parts []string
	if r.InIface != "" {
		parts = append(parts, "in:"+r.InIface)
	}
	if r.OutIface != "" {
		parts = append(parts, "out:"+r.OutIface)
	}
	keys := make([]string, 0, len(r.Options))
	for k := range r.Options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, k+":"+r.Options[k])
	}
	return strings.Join(parts, "  ")
}

// ─── Conf Tab ────────────────────────────────────────────────────────────────

func (m *Model) viewConf(width int) string {
	save := iptables.StateToSave(m.client.GetState())
	raw := strings.Split(save, "\n")

	// Syntax highlight each line
	var lines []string
	lines = append(lines,
		styleHeader.Render("  /etc/sysconfig/iptables"),
		styleMuted.Render("  "+strings.Repeat("─", min(width-2, 50))),
		"",
	)

	for _, line := range raw {
		lines = append(lines, "  "+highlightConfLine(line))
	}

	// Apply scroll
	if m.confScroll >= len(lines) {
		m.confScroll = max(0, len(lines)-1)
	}
	visible := lines
	if m.confScroll < len(lines) {
		visible = lines[m.confScroll:]
	}
	return strings.Join(visible, "\n")
}

// highlightConfLine applies syntax coloring to a single iptables-save line.
func highlightConfLine(line string) string {
	switch {
	case line == "":
		return ""
	case strings.HasPrefix(line, "#"):
		return styleMuted.Render(line)
	case strings.HasPrefix(line, "*"):
		// *filter, *nat, *mangle, *raw
		return stylePrimary.Bold(true).Render(line)
	case strings.HasPrefix(line, ":"):
		// :INPUT ACCEPT [0:0]
		parts := strings.SplitN(line, " ", 3)
		chain := styleChainBadge.Render(parts[0])
		rest := ""
		if len(parts) > 1 {
			policy := parts[1]
			switch policy {
			case "ACCEPT":
				rest = " " + styleSuccess.Render(policy)
			case "DROP":
				rest = " " + styleError.Render(policy)
			default:
				rest = " " + styleMuted.Render(policy)
			}
		}
		if len(parts) > 2 {
			rest += " " + styleMuted.Render(parts[2])
		}
		return chain + rest
	case strings.HasPrefix(line, "-A"):
		// -A CHAIN ... -j TARGET
		return highlightRuleLine(line)
	case line == "COMMIT":
		return styleWarning.Render(line)
	default:
		return styleBase.Render(line)
	}
}

// highlightRuleLine colors a -A rule line token by token.
func highlightRuleLine(line string) string {
	tokens := strings.Fields(line)
	var out []string
	i := 0
	for i < len(tokens) {
		tok := tokens[i]
		switch tok {
		case "-A":
			out = append(out, styleMuted.Render("-A"))
			if i+1 < len(tokens) {
				i++
				out = append(out, styleChainBadge.Render(tokens[i]))
			}
		case "-j":
			out = append(out, styleMuted.Render("-j"))
			if i+1 < len(tokens) {
				i++
				out = append(out, colorTarget(tokens[i]))
			}
		case "-p":
			out = append(out, styleMuted.Render("-p"))
			if i+1 < len(tokens) {
				i++
				out = append(out, styleWarning.Render(tokens[i]))
			}
		case "-s", "-d":
			out = append(out, styleMuted.Render(tok))
			if i+1 < len(tokens) {
				i++
				out = append(out, stylePrimary.Render(tokens[i]))
			}
		case "-i", "-o":
			out = append(out, styleMuted.Render(tok))
			if i+1 < len(tokens) {
				i++
				out = append(out, styleBase.Render(tokens[i]))
			}
		case "--dport", "--sport", "--dports", "--sports", "--state",
			"--to-destination", "--to-source", "--log-prefix",
			"--icmp-type", "--limit", "--reject-with":
			out = append(out, styleMuted.Render(tok))
			if i+1 < len(tokens) {
				i++
				out = append(out, styleSuccess.Render(tokens[i]))
			}
		case "-m":
			out = append(out, styleMuted.Render("-m"))
			if i+1 < len(tokens) {
				i++
				out = append(out, styleMuted.Italic(true).Render(tokens[i]))
			}
		default:
			if strings.HasPrefix(tok, "--") {
				out = append(out, styleMuted.Render(tok))
			} else {
				out = append(out, styleBase.Render(tok))
			}
		}
		i++
	}
	return strings.Join(out, " ")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ─── History Tab ─────────────────────────────────────────────────────────────

func (m *Model) viewHistory(width int) string {
	history := m.client.GetHistory()

	var lines []string

	if len(history) == 0 {
		lines = append(lines,
			styleMuted.Render("  아직 실행된 명령어가 없습니다."),
			"",
			styleMuted.Render("  명령어를 입력하면 변경 이력이 여기에 표시됩니다."),
		)
		return strings.Join(lines, "\n")
	}

	// Clamp histSel
	if m.histSel >= len(history) {
		m.histSel = len(history) - 1
	}

	lines = append(lines,
		styleHeader.Render(fmt.Sprintf("  실행 이력 (%d개)  ↑↓로 선택", len(history))),
		"",
	)

	// Show list of commands (most recent first)
	for i := len(history) - 1; i >= 0; i-- {
		ch := history[i]
		prefix := "  "
		cmdStyle := styleMuted
		if i == m.histSel {
			prefix = styleSuccess.Render("▶ ")
			cmdStyle = styleBase
		}
		status := ""
		if ch.Err != nil {
			status = styleError.Render(" [오류]")
		}
		timeStr := ch.Time.Format("15:04:05")
		lines = append(lines,
			prefix+styleMuted.Render("["+timeStr+"] ")+cmdStyle.Render(ch.Command)+status,
		)
	}

	// Show diff for selected entry
	if m.histSel >= 0 && m.histSel < len(history) {
		sel := history[m.histSel]
		lines = append(lines, "", strings.Repeat("─", min(width, 80)))
		lines = append(lines, m.renderDiff(sel)...)
	}

	// Apply scroll
	visible := lines
	if m.histScroll < len(lines) {
		visible = lines[m.histScroll:]
	}
	return strings.Join(visible, "\n")
}

func (m *Model) renderDiff(ch *iptables.Change) []string {
	var lines []string

	if ch.Err != nil {
		lines = append(lines,
			styleError.Render("  오류: "+ch.Err.Error()),
		)
		return lines
	}

	diffs := iptables.Diff(ch.Before, ch.After)
	if !iptables.HasChanges(diffs) {
		lines = append(lines, styleMuted.Render("  변경 없음"))
		return lines
	}

	lines = append(lines, styleHeader.Render("  변경 내용:"))

	// Group by table/chain
	type key struct{ table iptables.Table; chain string }
	grouped := make(map[key][]iptables.RuleDiff)
	var order []key
	for _, d := range diffs {
		k := key{d.Table, d.ChainName}
		if _, ok := grouped[k]; !ok {
			order = append(order, k)
		}
		grouped[k] = append(grouped[k], d)
	}

	for _, k := range order {
		groupDiffs := grouped[k]
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("  %s/%s",
			stylePrimary.Render(string(k.table)),
			styleChainBadge.Render(k.chain),
		))
		for _, d := range groupDiffs {
			switch d.Kind {
			case iptables.DiffAdded:
				lines = append(lines,
					styleAdded.Render(fmt.Sprintf("    + #%d %s", d.Rule.Num, d.Rule.ShortString())),
				)
			case iptables.DiffRemoved:
				lines = append(lines,
					styleRemoved.Render(fmt.Sprintf("    - #%d %s", d.Rule.Num, d.Rule.ShortString())),
				)
			case iptables.DiffPolicyChanged:
				lines = append(lines,
					stylePolicy.Render(fmt.Sprintf("    ~ policy: %s → %s", d.OldPolicy, d.NewPolicy)),
				)
			}
		}
	}
	return lines
}

// ─── Study Tab ───────────────────────────────────────────────────────────────

func (m *Model) viewStudy(width int) string {
	st := m.st
	lesson := st.lessons[st.lessonIdx]

	var lines []string

	// Lesson header
	progress := fmt.Sprintf("레슨 %d/%d", st.lessonIdx+1, len(st.lessons))
	lines = append(lines,
		"  "+stylePrimary.Render(progress)+"  "+styleTitle.Render(lesson.Title),
		"",
	)

	if st.taskMode {
		lines = append(lines, m.viewTask(lesson, width)...)
	} else {
		lines = append(lines, m.viewLessonContent(lesson, width)...)
	}

	// Apply scroll
	visible := lines
	if st.scroll < len(lines) {
		visible = lines[st.scroll:]
	}
	return strings.Join(visible, "\n")
}

func (m *Model) viewLessonContent(lesson *study.Lesson, width int) []string {
	var lines []string

	// Theory
	lines = append(lines, styleHeader.Render("  ── 이론 ─────────────────────────"))
	for _, line := range strings.Split(lesson.Theory, "\n") {
		lines = append(lines, "  "+styleBase.Render(line))
	}
	lines = append(lines, "")

	// Examples
	if len(lesson.Examples) > 0 {
		lines = append(lines, styleHeader.Render("  ── 예제 ─────────────────────────"))
		for _, ex := range lesson.Examples {
			lines = append(lines,
				"  "+stylePrimary.Render("$ "+ex.Cmd),
				"  "+styleMuted.Render("  → "+ex.Explanation),
				"",
			)
		}
	}

	// Tasks summary
	if len(lesson.Tasks) > 0 {
		lines = append(lines, styleHeader.Render(fmt.Sprintf("  ── 실습 (%d개) ─────────────────", len(lesson.Tasks))))
		for i, task := range lesson.Tasks {
			lines = append(lines, fmt.Sprintf("  %s %s",
				styleMuted.Render(fmt.Sprintf("[%d]", i+1)),
				styleBase.Render(task.Title),
			))
		}
		lines = append(lines, "")
		lines = append(lines, styleHelp.Render("  t 를 눌러 첫 번째 실습을 시작하세요"))
	}

	// Navigation hint
	lines = append(lines, "")
	nav := ""
	st := m.st
	if st.lessonIdx > 0 {
		nav += styleMuted.Render("  p:이전 레슨")
	}
	if st.lessonIdx < len(st.lessons)-1 {
		nav += styleMuted.Render("  n:다음 레슨")
	}
	if nav != "" {
		lines = append(lines, nav)
	}
	return lines
}

func (m *Model) viewTask(lesson *study.Lesson, width int) []string {
	st := m.st
	if st.taskIdx >= len(lesson.Tasks) {
		return []string{styleMuted.Render("  실습 없음")}
	}
	task := lesson.Tasks[st.taskIdx]

	var lines []string

	// Task header
	taskProg := fmt.Sprintf("실습 %d/%d", st.taskIdx+1, len(lesson.Tasks))
	lines = append(lines,
		"  "+styleWarning.Render("[ "+taskProg+" ]")+"  "+styleBase.Render(task.Title),
		"",
	)

	// Description
	for _, line := range strings.Split(task.Description, "\n") {
		lines = append(lines, "  "+styleBase.Render(line))
	}
	lines = append(lines, "")

	// Hint
	if task.Hint != "" {
		lines = append(lines,
			"  "+styleMuted.Render("힌트: "+task.Hint),
			"",
		)
	}

	// Current task state (rules)
	lines = append(lines, styleHeader.Render("  ── 현재 상태 (filter/INPUT) ─────"))
	taskState := st.taskClient.GetState()
	ts := taskState.Tables[iptables.TableFilter]
	if ts != nil {
		input := ts.Chains["INPUT"]
		if input != nil && len(input.Rules) > 0 {
			for _, r := range input.Rules {
				lines = append(lines, "  "+styleMuted.Render(fmt.Sprintf("#%d ", r.Num))+r.ShortString())
			}
		} else {
			lines = append(lines, "  "+styleMuted.Render("(규칙 없음)"))
		}
	}
	lines = append(lines, "")

	// Result
	if st.taskDone {
		lines = append(lines, styleTaskDone.Render("  ✓ "+st.taskMsg))
		lines = append(lines, "")
		// Next task button
		if st.taskIdx+1 < len(lesson.Tasks) {
			lines = append(lines, styleHelp.Render("  t:다음 실습  Esc:레슨으로 돌아가기"))
		} else {
			lines = append(lines, styleHelp.Render("  n:다음 레슨  Esc:레슨으로 돌아가기"))
		}
	} else if st.taskMsg != "" {
		lines = append(lines, styleError.Render("  ✗ "+st.taskMsg))
	}

	// Solution
	if st.showSol && task.Solution != "" {
		lines = append(lines, "")
		lines = append(lines, styleWarning.Render("  ── 정답 ──────────────────────────"))
		for _, line := range strings.Split(task.Solution, "\n") {
			lines = append(lines, "  "+stylePrimary.Render("$ "+line))
		}
	}

	return lines
}

// ─── Help Overlay ─────────────────────────────────────────────────────────────

func (m *Model) viewHelp() string {
	content := `
  tiptables — 도움말

  ── 탭 전환 ──────────────────────────────
  Tab / 1 / 2 / 3    탭 전환 (Rules / History / Study)

  ── 명령어 입력 ──────────────────────────
  Enter              명령어 실행
  Esc                입력 취소 / 실습 모드 나가기
  reset              iptables 상태 초기화

  ── 이동 ─────────────────────────────────
  ↑ / k              위로 스크롤
  ↓ / j              아래로 스크롤
  ← / h              이전 체인/테이블
  → / l              다음 체인/테이블

  ── 학습 모드 (Study 탭) ─────────────────
  p                  이전 레슨
  n                  다음 레슨
  t                  실습 시작
  s                  정답 보기/숨기기

  ── 공통 ─────────────────────────────────
  ?                  이 도움말 열기/닫기
  q / Ctrl+C         종료

  ── iptables 빠른 참고 ───────────────────
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT      SSH 허용
  iptables -A INPUT -s 1.2.3.4 -j DROP               IP 차단
  iptables -P INPUT DROP                             기본 정책 변경
  iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE  NAT
  iptables -F                                        전체 초기화
  iptables -L                                        규칙 목록

  Esc 또는 ? 로 닫기
`
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorPrimary).
		Padding(1, 2).
		Width(m.width - 4)

	return lipgloss.Place(m.width, m.height,
		lipgloss.Center, lipgloss.Center,
		boxStyle.Render(content),
	)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// getChainNames returns chain names in canonical order for the table.
func getChainNames(table iptables.Table, ts *iptables.TableState) []string {
	seen := make(map[string]bool)
	var out []string
	for _, name := range iptables.DefaultChains[table] {
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
