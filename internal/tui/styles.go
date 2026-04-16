package tui

import "github.com/charmbracelet/lipgloss"

var (
	colorBase    = lipgloss.Color("#e2e8f0")
	colorMuted   = lipgloss.Color("#64748b")
	colorPrimary = lipgloss.Color("#60a5fa")
	colorSuccess = lipgloss.Color("#4ade80")
	colorError   = lipgloss.Color("#f87171")
	colorWarning = lipgloss.Color("#fbbf24")
	colorAdded   = lipgloss.Color("#4ade80")
	colorRemoved = lipgloss.Color("#f87171")
	colorPolicy  = lipgloss.Color("#a78bfa")
	colorBorder  = lipgloss.Color("#334155")
	colorHeader  = lipgloss.Color("#94a3b8")

	styleBase = lipgloss.NewStyle().Foreground(colorBase)

	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorPrimary).
			MarginBottom(0)

	styleTabActive = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorPrimary).
			Background(lipgloss.Color("#1e293b")).
			Padding(0, 2)

	styleTabInactive = lipgloss.NewStyle().
				Foreground(colorMuted).
				Padding(0, 2)

	styleTabBar = lipgloss.NewStyle().
			Background(lipgloss.Color("#0f172a")).
			Width(0) // set dynamically

	styleBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder)

	styleHeader = lipgloss.NewStyle().
			Foreground(colorHeader).
			Bold(true)

	styleSuccess = lipgloss.NewStyle().Foreground(colorSuccess)
	styleError   = lipgloss.NewStyle().Foreground(colorError)
	styleWarning = lipgloss.NewStyle().Foreground(colorWarning)
	styleMuted   = lipgloss.NewStyle().Foreground(colorMuted)
	stylePrimary = lipgloss.NewStyle().Foreground(colorPrimary)

	styleAdded   = lipgloss.NewStyle().Foreground(colorAdded)
	styleRemoved = lipgloss.NewStyle().Foreground(colorRemoved)
	stylePolicy  = lipgloss.NewStyle().Foreground(colorPolicy)

	stylePrompt = lipgloss.NewStyle().
			Foreground(colorPrimary).
			Bold(true)

	styleInputBar = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), true, false, false, false).
			BorderForeground(colorBorder).
			Padding(0, 1)

	styleHelp = lipgloss.NewStyle().
			Foreground(colorMuted).
			Italic(true)

	styleChainBadge = lipgloss.NewStyle().
			Foreground(colorPrimary).
			Bold(true)

	styleRuleNum = lipgloss.NewStyle().
			Foreground(colorMuted).
			Width(4)

	styleSeparator = lipgloss.NewStyle().Foreground(colorBorder)

	styleTaskDone    = lipgloss.NewStyle().Foreground(colorSuccess).Bold(true)
	styleTaskPending = lipgloss.NewStyle().Foreground(colorWarning)
)
