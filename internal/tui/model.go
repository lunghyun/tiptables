package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nangm/iptables-lab/internal/iptables"
	"github.com/nangm/iptables-lab/internal/study"
)

// Tab indices
const (
	tabRules   = 0
	tabHistory = 1
	tabConf    = 2
	tabStudy   = 3
)

var tabNames = []string{"1 Rules", "2 History", "3 Conf", "4 Study"}

// Config holds startup configuration.
type Config struct {
	StudyMode bool
}

// studyState holds the current state of the study tab.
type studyState struct {
	lessons    []*study.Lesson
	lessonIdx  int
	taskIdx    int
	taskMode   bool
	taskClient *iptables.MockClient // isolated state for each task
	taskDone   bool
	taskMsg    string // success/fail feedback
	showSol    bool   // show solution
	scroll     int
}

// Model is the root bubbletea model.
type Model struct {
	width, height int

	// Navigation
	activeTab int

	// Iptables
	client *iptables.MockClient

	// Rules view
	tableIdx int // index into iptables.AllTables
	chainIdx int // index within current table's chains
	scroll   int

	// History view
	histSel    int // selected history entry
	histScroll int

	// Conf view
	confScroll int

	// Study
	st *studyState

	// Input (shared bottom bar)
	input    textinput.Model
	inputMsg string
	inputOK  bool // true = success, false = error

	// Command history (bash-style ↑↓ navigation)
	cmdHistory []string
	historyPos int    // -1 = not navigating
	savedInput string // input saved before navigating history

	// Help overlay
	showHelp bool
}

// New creates a new Model with given config.
func New(cfg Config) *Model {
	ti := textinput.New()
	ti.Placeholder = "iptables ..."
	ti.Focus()
	ti.CharLimit = 300
	ti.Width = 80

	lessons := study.All()
	m := &Model{
		client:     iptables.NewMockClient(),
		input:      ti,
		activeTab:  tabRules,
		historyPos: -1,
		st: &studyState{
			lessons:    lessons,
			lessonIdx:  0,
			taskClient: iptables.NewMockClient(),
		},
	}
	if cfg.StudyMode {
		m.activeTab = tabStudy
	}
	return m
}

// Init implements tea.Model.
func (m *Model) Init() tea.Cmd {
	return textinput.Blink
}

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.input.Width = msg.Width - 6
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Quit
	if msg.String() == "ctrl+c" {
		return m, tea.Quit
	}

	// Help overlay toggle
	if msg.String() == "?" && !m.input.Focused() {
		m.showHelp = !m.showHelp
		return m, nil
	}
	if m.showHelp {
		if msg.String() == "q" || msg.String() == "esc" || msg.String() == "?" {
			m.showHelp = false
		}
		return m, nil
	}

	// Tab switching with number keys or Tab (when input is empty)
	if !m.input.Focused() {
		switch msg.String() {
		case "1":
			m.activeTab = tabRules
			m.input.Focus()
			return m, textinput.Blink
		case "2":
			m.activeTab = tabHistory
			m.input.Focus()
			return m, textinput.Blink
		case "3":
			m.activeTab = tabConf
			m.input.Focus()
			return m, textinput.Blink
		case "4":
			m.activeTab = tabStudy
			m.input.Focus()
			return m, textinput.Blink
		case "q":
			return m, tea.Quit
		}
	}

	// Tab key: cycle tabs when input is empty
	if msg.Type == tea.KeyTab && m.input.Value() == "" {
		m.activeTab = (m.activeTab + 1) % len(tabNames)
		m.inputMsg = ""
		return m, nil
	}

	// Enter: execute command
	if msg.Type == tea.KeyEnter {
		return m.executeCommand()
	}

	// Esc: clear input / cancel task mode
	if msg.Type == tea.KeyEsc {
		if m.input.Value() != "" {
			m.input.SetValue("")
			m.inputMsg = ""
			return m, nil
		}
		if m.activeTab == tabStudy && m.st.taskMode {
			m.exitTaskMode()
			return m, nil
		}
	}

	// ↑↓ 화살표: 입력창에 포커스가 있으면 명령어 히스토리 탐색
	if msg.Type == tea.KeyUp {
		if len(m.cmdHistory) > 0 {
			if m.historyPos == -1 {
				// 탐색 시작: 현재 입력 저장
				m.savedInput = m.input.Value()
				m.historyPos = len(m.cmdHistory) - 1
			} else if m.historyPos > 0 {
				m.historyPos--
			}
			m.input.SetValue(m.cmdHistory[m.historyPos])
			m.input.CursorEnd()
		}
		return m, nil
	}
	if msg.Type == tea.KeyDown {
		if m.historyPos != -1 {
			m.historyPos++
			if m.historyPos >= len(m.cmdHistory) {
				// 끝까지 내려오면 저장해둔 입력 복원
				m.historyPos = -1
				m.input.SetValue(m.savedInput)
				m.input.CursorEnd()
			} else {
				m.input.SetValue(m.cmdHistory[m.historyPos])
				m.input.CursorEnd()
			}
		} else if m.input.Value() == "" {
			// 입력이 비어있고 히스토리 탐색 중이 아닐 때만 스크롤
			m.scrollDown()
		}
		return m, nil
	}

	// 히스토리 탐색 중 다른 키 입력 시 탐색 종료
	if m.historyPos != -1 && msg.Type != tea.KeyUp && msg.Type != tea.KeyDown {
		m.historyPos = -1
		m.savedInput = ""
	}

	// Arrow keys for scrolling (when input empty, not up/down which are handled above)
	if m.input.Value() == "" {
		switch msg.String() {
		case "k":
			m.scrollUp()
			return m, nil
		case "j":
			m.scrollDown()
			return m, nil
		case "left", "h":
			m.prevPane()
			return m, nil
		case "right", "l":
			m.nextPane()
			return m, nil
		}
	}

	// Study-specific keys when input is empty
	if m.activeTab == tabStudy && m.input.Value() == "" {
		switch msg.String() {
		case "n":
			m.nextLesson()
			return m, nil
		case "p":
			m.prevLesson()
			return m, nil
		case "t":
			m.startTask(0)
			return m, nil
		case "s":
			m.st.showSol = !m.st.showSol
			return m, nil
		}
	}

	// History selection
	if m.activeTab == tabHistory && m.input.Value() == "" {
		history := m.client.GetHistory()
		switch msg.String() {
		case "up", "k":
			if m.histSel > 0 {
				m.histSel--
			}
			return m, nil
		case "down", "j":
			if m.histSel < len(history)-1 {
				m.histSel++
			}
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *Model) executeCommand() (tea.Model, tea.Cmd) {
	raw := strings.TrimSpace(m.input.Value())
	if raw == "" {
		return m, nil
	}
	m.input.SetValue("")

	// 히스토리 탐색 상태 초기화
	m.historyPos = -1
	m.savedInput = ""

	// 명령어 히스토리에 저장 (중복 연속 입력 제외)
	if len(m.cmdHistory) == 0 || m.cmdHistory[len(m.cmdHistory)-1] != raw {
		m.cmdHistory = append(m.cmdHistory, raw)
	}

	// Special commands
	switch strings.ToLower(raw) {
	case "reset", "clear":
		m.client.Reset()
		m.inputMsg = "상태가 초기화되었습니다."
		m.inputOK = true
		return m, nil
	case "help", "h", "?":
		m.showHelp = true
		return m, nil
	}

	// Study task mode: execute against isolated client
	if m.activeTab == tabStudy && m.st.taskMode {
		_, err := m.st.taskClient.Execute(raw)
		if err != nil {
			m.inputMsg = "오류: " + err.Error()
			m.inputOK = false
		} else {
			m.inputMsg = ""
			m.inputOK = true
			// Check solution
			lesson := m.st.lessons[m.st.lessonIdx]
			if m.st.taskIdx < len(lesson.Tasks) {
				task := lesson.Tasks[m.st.taskIdx]
				if task.Validate(m.st.taskClient.GetState()) {
					m.st.taskDone = true
					m.st.taskMsg = "정답입니다! 잘 하셨습니다!"
				}
			}
		}
		return m, nil
	}

	// Normal execution against main client
	_, err := m.client.Execute(raw)
	history := m.client.GetHistory()
	if len(history) > 0 {
		m.histSel = len(history) - 1
	}

	if err != nil {
		m.inputMsg = "오류: " + err.Error()
		m.inputOK = false
	} else {
		m.inputMsg = "실행 완료"
		m.inputOK = true
	}
	return m, nil
}

// ─── Study helpers ────────────────────────────────────────────────────────────

func (m *Model) nextLesson() {
	if m.st.lessonIdx < len(m.st.lessons)-1 {
		m.st.lessonIdx++
		m.st.taskMode = false
		m.st.taskDone = false
		m.st.showSol = false
		m.st.scroll = 0
		m.st.taskMsg = ""
	}
}

func (m *Model) prevLesson() {
	if m.st.lessonIdx > 0 {
		m.st.lessonIdx--
		m.st.taskMode = false
		m.st.taskDone = false
		m.st.showSol = false
		m.st.scroll = 0
		m.st.taskMsg = ""
	}
}

func (m *Model) startTask(idx int) {
	lesson := m.st.lessons[m.st.lessonIdx]
	if idx >= len(lesson.Tasks) {
		return
	}
	m.st.taskMode = true
	m.st.taskIdx = idx
	m.st.taskDone = false
	m.st.taskMsg = ""
	m.st.showSol = false
	// Fresh client for the task
	m.st.taskClient = iptables.NewMockClient()
	if lesson.Tasks[idx].Setup != nil {
		lesson.Tasks[idx].Setup(m.st.taskClient)
	}
	m.input.Focus()
}

func (m *Model) exitTaskMode() {
	m.st.taskMode = false
	m.st.taskDone = false
	m.st.taskMsg = ""
	m.st.showSol = false
}

// ─── Scroll / pane helpers ───────────────────────────────────────────────────

func (m *Model) scrollUp() {
	switch m.activeTab {
	case tabRules:
		if m.scroll > 0 {
			m.scroll--
		}
	case tabHistory:
		if m.histScroll > 0 {
			m.histScroll--
		}
	case tabConf:
		if m.confScroll > 0 {
			m.confScroll--
		}
	case tabStudy:
		if m.st.scroll > 0 {
			m.st.scroll--
		}
	}
}

func (m *Model) scrollDown() {
	switch m.activeTab {
	case tabRules:
		m.scroll++
	case tabHistory:
		m.histScroll++
	case tabConf:
		m.confScroll++
	case tabStudy:
		m.st.scroll++
	}
}

func (m *Model) prevPane() {
	switch m.activeTab {
	case tabRules:
		if m.chainIdx > 0 {
			m.chainIdx--
			m.scroll = 0
		} else if m.tableIdx > 0 {
			m.tableIdx--
			m.chainIdx = 0
			m.scroll = 0
		}
	}
}

func (m *Model) nextPane() {
	switch m.activeTab {
	case tabRules:
		table := iptables.AllTables[m.tableIdx]
		ts := m.client.GetState().Tables[table]
		chains := getChainNames(table, ts)
		if m.chainIdx < len(chains)-1 {
			m.chainIdx++
			m.scroll = 0
		} else if m.tableIdx < len(iptables.AllTables)-1 {
			m.tableIdx++
			m.chainIdx = 0
			m.scroll = 0
		}
	}
}

// ─── View ─────────────────────────────────────────────────────────────────────

// View implements tea.Model.
func (m *Model) View() string {
	if m.width == 0 {
		return "로딩 중..."
	}

	if m.showHelp {
		return m.viewHelp()
	}

	header := m.viewHeader()
	content := m.viewContent()
	input := m.viewInputBar()

	// Calculate available height for content
	headerLines := strings.Count(header, "\n") + 1
	inputLines := strings.Count(input, "\n") + 1
	contentHeight := m.height - headerLines - inputLines

	if contentHeight < 3 {
		contentHeight = 3
	}

	// Fit content into available height
	contentLines := strings.Split(content, "\n")
	if len(contentLines) > contentHeight {
		contentLines = contentLines[:contentHeight]
	}
	// Pad to fill height
	for len(contentLines) < contentHeight {
		contentLines = append(contentLines, "")
	}
	content = strings.Join(contentLines, "\n")

	return lipgloss.JoinVertical(lipgloss.Left, header, content, input)
}

func (m *Model) viewHeader() string {
	var tabs []string
	for i, name := range tabNames {
		if i == m.activeTab {
			tabs = append(tabs, styleTabActive.Render(name))
		} else {
			tabs = append(tabs, styleTabInactive.Render(name))
		}
	}

	mode := styleMuted.Render(" [MOCK] ")
	title := styleTitle.Render("iptables-lab")
	tabRow := lipgloss.JoinHorizontal(lipgloss.Left, tabs...)
	help := styleMuted.Render("? help")

	right := lipgloss.JoinHorizontal(lipgloss.Right, mode, help)
	gap := m.width - lipgloss.Width(title) - lipgloss.Width(tabRow) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}

	bar := lipgloss.JoinHorizontal(lipgloss.Left,
		title,
		strings.Repeat(" ", 2),
		tabRow,
		strings.Repeat(" ", gap),
		right,
	)
	return styleTabBar.Width(m.width).Render(bar)
}

func (m *Model) viewInputBar() string {
	var msgLine string
	if m.inputMsg != "" {
		if m.inputOK {
			msgLine = styleSuccess.Render("✓ "+m.inputMsg) + "\n"
		} else {
			msgLine = styleError.Render("✗ "+m.inputMsg) + "\n"
		}
	}

	prompt := stylePrompt.Render("> ")
	inputView := m.input.View()
	var hint string
	switch m.activeTab {
	case tabRules:
		hint = "Tab:탭전환  ←→:체인이동  ↑↓:히스토리/스크롤  Enter:실행  reset:초기화  q:종료"
	case tabHistory:
		hint = "Tab:탭전환  ↑↓:히스토리탐색  Enter:실행  q:종료"
	case tabConf:
		hint = "Tab:탭전환  j/k:스크롤  Enter:실행  q:종료"
	case tabStudy:
		if m.st.taskMode {
			hint = "Enter:실행  ↑↓:히스토리탐색  Esc:나가기  s:정답보기"
		} else {
			hint = "Tab:탭전환  p/n:이전/다음레슨  t:실습시작  q:종료"
		}
	}

	bar := msgLine + prompt + inputView + "\n" + styleHelp.Render(hint)
	return styleInputBar.Width(m.width - 2).Render(bar)
}
