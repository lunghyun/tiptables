package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nangm/iptables-lab/internal/tui"
)

const version = "0.1.0"

func main() {
	var (
		studyMode = flag.Bool("study", false, "학습 모드로 바로 시작")
		showVer   = flag.Bool("version", false, "버전 출력")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `iptables-lab v%s — iptables 학습 시뮬레이터

사용법:
  iptables-lab [옵션]

옵션:
  -study     학습 모드로 바로 시작
  -version   버전 출력
  -help      도움말

탭:
  1 Rules    현재 iptables 규칙 조회
  2 History  변경 이력 및 diff 시각화
  3 Study    학습 레슨 & 실습

명령어 입력 예시:
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  iptables -P INPUT DROP
`, version)
	}
	flag.Parse()

	if *showVer {
		fmt.Printf("iptables-lab v%s\n", version)
		return
	}

	cfg := tui.Config{StudyMode: *studyMode}
	m := tui.New(cfg)
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "오류: %v\n", err)
		os.Exit(1)
	}
}
