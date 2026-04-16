// Package study provides structured iptables learning content with lessons and tasks.
package study

import (
	"strings"

	"github.com/nangm/iptables-lab/internal/iptables"
)

// Task is a hands-on exercise the user must solve by entering iptables commands.
type Task struct {
	Title       string
	Description string
	Hint        string
	Setup       func(c *iptables.MockClient) // optional: pre-populate state
	Validate    func(s *iptables.State) bool  // returns true when task is solved
	Solution    string                         // shown after solving or on request
}

// Example is a command with an explanation, used in lesson theory sections.
type Example struct {
	Cmd         string
	Explanation string
}

// Lesson is one unit of study content.
type Lesson struct {
	ID       int
	Title    string
	Theory   string
	Examples []Example
	Tasks    []*Task
}

// All returns all lessons in order.
func All() []*Lesson {
	return []*Lesson{
		lesson1(),
		lesson2(),
		lesson3(),
		lesson4(),
		lesson5(),
		lesson6(),
		lesson7(),
	}
}

// ─── Lesson 1 ────────────────────────────────────────────────────────────────

func lesson1() *Lesson {
	return &Lesson{
		ID:    1,
		Title: "iptables 소개: 패킷 여정",
		Theory: strings.TrimSpace(`
iptables는 Linux 커널의 netfilter 프레임워크를 제어하는 도구입니다.
네트워크 패킷이 시스템을 통과할 때 각 체크포인트에서 규칙을 적용합니다.

┌─ 패킷 흐름 ──────────────────────────────────────────────────┐
│                                                               │
│  [네트워크]──→ PREROUTING ──→ (라우팅 결정)                  │
│                                │                              │
│                    ┌───────────┴───────────┐                  │
│                    ↓                       ↓                  │
│                 INPUT                   FORWARD               │
│                    ↓                       ↓                  │
│              [로컬 프로세스]          [다른 인터페이스]        │
│                    ↓                                          │
│                 OUTPUT                                        │
│                    ↓                                          │
│               POSTROUTING ──→ [네트워크]                      │
│                                                               │
└───────────────────────────────────────────────────────────────┘

핵심 개념:
  테이블(Table)  - 기능별 규칙 그룹 (filter, nat, mangle, raw)
  체인(Chain)    - 패킷이 통과하는 검사 지점의 규칙 목록
  규칙(Rule)     - 패킷 조건(match) + 처리 방법(target)
  타겟(Target)   - 규칙에 일치하면 수행할 동작

패킷은 체인의 규칙을 위에서 아래로 순서대로 비교합니다.
일치하는 규칙이 없으면 체인의 기본 정책(policy)이 적용됩니다.
`),
		Examples: []Example{
			{
				Cmd:         "iptables -L",
				Explanation: "filter 테이블의 모든 체인과 규칙 출력",
			},
			{
				Cmd:         "iptables -t nat -L",
				Explanation: "nat 테이블의 모든 체인과 규칙 출력",
			},
		},
		Tasks: []*Task{
			{
				Title:       "현재 규칙 목록 확인",
				Description: "filter 테이블의 INPUT 체인 규칙을 조회하세요.",
				Hint:        "iptables -L INPUT 또는 iptables -L 사용",
				Validate: func(s *iptables.State) bool {
					return true // always pass — just need to run -L
				},
				Solution: "iptables -L INPUT",
			},
		},
	}
}

// ─── Lesson 2 ────────────────────────────────────────────────────────────────

func lesson2() *Lesson {
	return &Lesson{
		ID:    2,
		Title: "테이블과 체인",
		Theory: strings.TrimSpace(`
iptables에는 4개의 테이블이 있으며 각각 목적이 다릅니다.

┌──────────┬─────────────────────────────────────────────────────┐
│ 테이블   │ 역할 / 체인                                          │
├──────────┼─────────────────────────────────────────────────────┤
│ filter   │ 패킷 허용/차단 (기본 테이블)                         │
│          │ INPUT · FORWARD · OUTPUT                             │
├──────────┼─────────────────────────────────────────────────────┤
│ nat      │ 주소/포트 변환 (NAT)                                 │
│          │ PREROUTING · INPUT · OUTPUT · POSTROUTING           │
├──────────┼─────────────────────────────────────────────────────┤
│ mangle   │ 패킷 헤더 수정 (TOS, TTL, MARK 등)                  │
│          │ PREROUTING · INPUT · FORWARD · OUTPUT · POSTROUTING │
├──────────┼─────────────────────────────────────────────────────┤
│ raw      │ 연결 추적(conntrack) 제어                            │
│          │ PREROUTING · OUTPUT                                  │
└──────────┴─────────────────────────────────────────────────────┘

체인 기본 정책 (policy):
  - ACCEPT: 일치하는 규칙 없으면 허용 (기본값)
  - DROP:   일치하는 규칙 없으면 차단

사용자 정의 체인을 만들어 규칙을 논리적으로 분리할 수도 있습니다.
`),
		Examples: []Example{
			{
				Cmd:         "iptables -t filter -L",
				Explanation: "filter 테이블 전체 출력 (-t filter 생략 가능)",
			},
			{
				Cmd:         "iptables -t nat -L PREROUTING",
				Explanation: "nat 테이블의 PREROUTING 체인만 출력",
			},
			{
				Cmd:         "iptables -N MY_CHAIN",
				Explanation: "filter 테이블에 MY_CHAIN 이라는 사용자 체인 생성",
			},
		},
		Tasks: []*Task{
			{
				Title:       "사용자 체인 생성 및 삭제",
				Description: "filter 테이블에 'TEST_CHAIN' 이라는 사용자 체인을 만들고, 다시 삭제하세요.",
				Hint:        "생성: -N TEST_CHAIN  삭제: -X TEST_CHAIN",
				Validate: func(s *iptables.State) bool {
					ts := s.Tables[iptables.TableFilter]
					_, exists := ts.Chains["TEST_CHAIN"]
					return !exists // Pass when chain is deleted
				},
				Solution: "iptables -N TEST_CHAIN\niptables -X TEST_CHAIN",
			},
			{
				Title:       "nat 테이블 조회",
				Description: "nat 테이블의 POSTROUTING 체인을 조회하세요.",
				Hint:        "iptables -t nat -L POSTROUTING",
				Validate:    func(s *iptables.State) bool { return true },
				Solution:    "iptables -t nat -L POSTROUTING",
			},
		},
	}
}

// ─── Lesson 3 ────────────────────────────────────────────────────────────────

func lesson3() *Lesson {
	return &Lesson{
		ID:    3,
		Title: "규칙 기본 문법",
		Theory: strings.TrimSpace(`
iptables 규칙의 기본 형식:

  iptables [-t 테이블] 액션 체인 [매치 조건...] -j 타겟

액션:
  -A chain   체인 끝에 규칙 추가 (Append)
  -I chain n 체인 n번째에 규칙 삽입 (Insert, 기본: 1번)
  -D chain n 체인 n번째 규칙 삭제 (Delete)
  -R chain n 체인 n번째 규칙 교체 (Replace)
  -F [chain] 체인의 모든 규칙 삭제 (Flush)
  -P chain T 체인 기본 정책 설정 (Policy)

자주 쓰는 매치 조건:
  -p tcp|udp|icmp|all   프로토콜
  -s 1.2.3.4[/mask]     출발지 IP (source)
  -d 1.2.3.4[/mask]     목적지 IP (destination)
  -i eth0               입력 인터페이스
  -o eth0               출력 인터페이스
  --dport 80            목적지 포트 (-p tcp/udp와 함께)
  --sport 1024:65535    출발지 포트 범위

타겟 (-j):
  ACCEPT     허용
  DROP       차단 (응답 없음)
  REJECT     거부 (TCP RST / ICMP 오류 반환)
  LOG        로그 기록 (매칭 계속)
  RETURN     현재 체인에서 복귀
`),
		Examples: []Example{
			{
				Cmd:         "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
				Explanation: "SSH(22번 포트) 인바운드 허용",
			},
			{
				Cmd:         "iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT",
				Explanation: "192.168.1.0/24 네트워크에서 오는 패킷 허용",
			},
			{
				Cmd:         "iptables -I INPUT 1 -p icmp -j DROP",
				Explanation: "ICMP(ping) 차단 규칙을 INPUT 체인 맨 앞에 삽입",
			},
			{
				Cmd:         "iptables -D INPUT 1",
				Explanation: "INPUT 체인의 1번 규칙 삭제",
			},
		},
		Tasks: []*Task{
			{
				Title:       "SSH 허용",
				Description: "INPUT 체인에 TCP 22번 포트(SSH) 인바운드 트래픽을 허용하는 규칙을 추가하세요.",
				Hint:        "iptables -A INPUT -p tcp --dport <포트> -j <타겟>",
				Validate: func(s *iptables.State) bool {
					return hasRule(s, iptables.TableFilter, "INPUT", func(r *iptables.Rule) bool {
						return r.Target == "ACCEPT" && r.Proto == "tcp" && r.Options["dport"] == "22"
					})
				},
				Solution: "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
			},
			{
				Title:       "특정 IP 차단",
				Description: "출발지 IP 10.0.0.99 로부터 오는 모든 패킷을 차단하세요.",
				Hint:        "출발지 IP는 -s 옵션으로 지정합니다",
				Validate: func(s *iptables.State) bool {
					return hasRule(s, iptables.TableFilter, "INPUT", func(r *iptables.Rule) bool {
						return r.Target == "DROP" && r.Source == "10.0.0.99"
					})
				},
				Solution: "iptables -A INPUT -s 10.0.0.99 -j DROP",
			},
			{
				Title:       "HTTP 아웃바운드 허용",
				Description: "OUTPUT 체인에서 TCP 80번 포트(HTTP)로 나가는 트래픽을 허용하세요.",
				Hint:        "OUTPUT 체인에 -p tcp --dport 80 -j ACCEPT 추가",
				Validate: func(s *iptables.State) bool {
					return hasRule(s, iptables.TableFilter, "OUTPUT", func(r *iptables.Rule) bool {
						return r.Target == "ACCEPT" && r.Proto == "tcp" && r.Options["dport"] == "80"
					})
				},
				Solution: "iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT",
			},
		},
	}
}

// ─── Lesson 4 ────────────────────────────────────────────────────────────────

func lesson4() *Lesson {
	return &Lesson{
		ID:    4,
		Title: "상태 기반 필터링 (Stateful Firewall)",
		Theory: strings.TrimSpace(`
conntrack(연결 추적) 모듈을 사용하면 연결 상태에 따라 패킷을 필터링할 수 있습니다.

연결 상태:
  NEW          새로운 연결의 첫 패킷
  ESTABLISHED  이미 연결된 세션의 패킷 (양방향)
  RELATED      기존 연결과 연관된 새 연결 (FTP 데이터 등)
  INVALID      어느 연결에도 속하지 않는 패킷

실전 방화벽 패턴 (DEFAULT DROP 정책):
  1. ESTABLISHED,RELATED 허용  →  응답 패킷이 돌아올 수 있게
  2. 필요한 인바운드 포트만 허용
  3. INPUT 정책을 DROP으로 설정

  # 이 순서가 중요합니다!
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  iptables -P INPUT DROP

경고: -P INPUT DROP을 먼저 설정하면 기존 SSH 세션이 끊길 수 있습니다.
      항상 ESTABLISHED,RELATED 허용 규칙을 먼저 추가하세요.
`),
		Examples: []Example{
			{
				Cmd:         "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
				Explanation: "이미 수립된 연결과 관련 연결의 응답 패킷 허용",
			},
			{
				Cmd:         "iptables -A INPUT -m state --state INVALID -j DROP",
				Explanation: "유효하지 않은 상태의 패킷 차단",
			},
			{
				Cmd:         "iptables -P INPUT DROP",
				Explanation: "INPUT 체인 기본 정책을 DROP으로 변경",
			},
		},
		Tasks: []*Task{
			{
				Title: "상태 기반 방화벽 구성",
				Description: `다음 순서로 상태 기반 방화벽을 구성하세요:
1. ESTABLISHED,RELATED 상태의 패킷 허용
2. 루프백(lo) 인터페이스 허용 (-i lo -j ACCEPT)
3. SSH(22) 허용
4. INPUT 정책을 DROP으로 변경`,
				Hint: "-m state --state ESTABLISHED,RELATED -j ACCEPT 를 먼저 추가하세요",
				Validate: func(s *iptables.State) bool {
					filter := s.Tables[iptables.TableFilter]
					input := filter.Chains["INPUT"]
					if input == nil || input.Policy != "DROP" {
						return false
					}
					hasEstab := hasRule(s, iptables.TableFilter, "INPUT", func(r *iptables.Rule) bool {
						st := r.Options["state"]
						return r.Target == "ACCEPT" && (st == "ESTABLISHED,RELATED" || st == "RELATED,ESTABLISHED")
					})
					hasSsh := hasRule(s, iptables.TableFilter, "INPUT", func(r *iptables.Rule) bool {
						return r.Target == "ACCEPT" && r.Proto == "tcp" && r.Options["dport"] == "22"
					})
					return hasEstab && hasSsh
				},
				Solution: `iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -P INPUT DROP`,
			},
		},
	}
}

// ─── Lesson 5 ────────────────────────────────────────────────────────────────

func lesson5() *Lesson {
	return &Lesson{
		ID:    5,
		Title: "NAT: 주소 변환",
		Theory: strings.TrimSpace(`
NAT(Network Address Translation)은 패킷의 출발지/목적지 IP·포트를 변환합니다.
nat 테이블에서 처리됩니다.

종류:
  MASQUERADE   아웃바운드 NAT — 동적 IP 환경에서 사용
               출발지 IP를 출력 인터페이스 IP로 자동 변경
               (가정용 인터넷 공유, Docker 등)

  SNAT         아웃바운드 NAT — 고정 IP 환경에서 사용
               출발지 IP를 지정한 IP로 고정
               --to-source 로 지정

  DNAT         인바운드 포트 포워딩
               목적지 IP·포트를 내부 서버로 변경
               PREROUTING 체인에서 사용
               --to-destination 으로 지정

IP 포워딩 활성화 (실제 환경):
  echo 1 > /proc/sys/net/ipv4/ip_forward

참고: 이 시뮬레이터에서 IP 포워딩은 자동 활성화 상태로 간주합니다.
`),
		Examples: []Example{
			{
				Cmd:         "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
				Explanation: "eth0으로 나가는 모든 패킷의 출발지 IP를 eth0 IP로 변환 (인터넷 공유)",
			},
			{
				Cmd:         "iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.10:8080",
				Explanation: "외부 80포트로 오는 TCP를 내부 192.168.1.10:8080으로 포워딩",
			},
			{
				Cmd:         "iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -j SNAT --to-source 203.0.113.1",
				Explanation: "내부망에서 나가는 패킷의 출발지를 공인 IP로 고정",
			},
		},
		Tasks: []*Task{
			{
				Title:       "인터넷 공유 설정 (MASQUERADE)",
				Description: "eth0 인터페이스로 나가는 패킷에 MASQUERADE NAT를 설정하세요.",
				Hint:        "nat 테이블의 POSTROUTING 체인에 추가합니다",
				Validate: func(s *iptables.State) bool {
					return hasRule(s, iptables.TableNAT, "POSTROUTING", func(r *iptables.Rule) bool {
						return r.Target == "MASQUERADE" && r.OutIface == "eth0"
					})
				},
				Solution: "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
			},
			{
				Title:       "포트 포워딩 (DNAT)",
				Description: "외부에서 TCP 8080번 포트로 오는 연결을 내부 서버 192.168.1.50:80으로 포워딩하세요.",
				Hint:        "nat 테이블의 PREROUTING 체인에 DNAT 규칙 추가",
				Validate: func(s *iptables.State) bool {
					return hasRule(s, iptables.TableNAT, "PREROUTING", func(r *iptables.Rule) bool {
						return r.Target == "DNAT" && r.Proto == "tcp" &&
							r.Options["dport"] == "8080" && r.Options["to-dst"] == "192.168.1.50:80"
					})
				},
				Solution: "iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.50:80",
			},
		},
	}
}

// ─── Lesson 6 ────────────────────────────────────────────────────────────────

func lesson6() *Lesson {
	return &Lesson{
		ID:    6,
		Title: "로깅과 속도 제한",
		Theory: strings.TrimSpace(`
LOG 타겟
  LOG는 패킷 정보를 커널 로그(/var/log/kern.log, dmesg)에 기록하고
  체인 처리를 계속합니다. (패킷을 허용하거나 차단하지 않음)

  --log-prefix "TAG: "  로그 메시지 앞에 태그 추가
  --log-level  4        로그 레벨 (4=warning, 7=debug)

  패턴: LOG 규칙 → DROP 규칙 순서로 배치

limit 모듈 (속도 제한)
  초당/분당 일치 횟수를 제한합니다.
  DDoS 방어, 로그 폭증 방지에 사용.

  --limit 5/min          분당 5번만 매치 허용
  --limit-burst 10       초기 버스트 허용 횟수

실용 예: SSH 무차별 대입 방어
  iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
    -m limit --limit 3/min --limit-burst 5 -j ACCEPT
  iptables -A INPUT -p tcp --dport 22 -j DROP
`),
		Examples: []Example{
			{
				Cmd:         "iptables -A INPUT -j LOG --log-prefix \"[DROP]: \" --log-level 4",
				Explanation: "INPUT 체인에 도달한 패킷을 로그로 기록 (처리는 계속)",
			},
			{
				Cmd:         "iptables -A INPUT -p tcp --dport 22 -m limit --limit 5/min -j LOG --log-prefix \"SSH: \"",
				Explanation: "분당 5번까지만 SSH 접속 시도를 로그에 기록",
			},
		},
		Tasks: []*Task{
			{
				Title: "DROP 전 로그 기록",
				Description: `INPUT 체인에 다음 두 규칙을 추가하세요:
1. 출발지 192.168.99.99 패킷을 "[BLOCKED]: " 접두사로 로그
2. 동일 출발지 패킷을 DROP`,
				Hint: "LOG 규칙을 DROP 규칙보다 먼저 추가해야 합니다",
				Validate: func(s *iptables.State) bool {
					ts := s.Tables[iptables.TableFilter]
					input := ts.Chains["INPUT"]
					if input == nil {
						return false
					}
					var logIdx, dropIdx = -1, -1
					for _, r := range input.Rules {
						if r.Source == "192.168.99.99" {
							if r.Target == "LOG" && logIdx == -1 {
								logIdx = r.Num
							}
							if r.Target == "DROP" && dropIdx == -1 {
								dropIdx = r.Num
							}
						}
					}
					return logIdx > 0 && dropIdx > 0 && logIdx < dropIdx
				},
				Solution: `iptables -A INPUT -s 192.168.99.99 -j LOG --log-prefix "[BLOCKED]: "
iptables -A INPUT -s 192.168.99.99 -j DROP`,
			},
		},
	}
}

// ─── Lesson 7 ────────────────────────────────────────────────────────────────

func lesson7() *Lesson {
	return &Lesson{
		ID:    7,
		Title: "실전: 서버 방화벽 구성",
		Theory: strings.TrimSpace(`
웹 서버 방화벽 완성 예시 (권장 패턴):

  # 1. 기존 규칙 모두 제거
  iptables -F
  iptables -t nat -F

  # 2. 루프백 및 기존 연결 허용
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  # 3. 필요한 서비스 허용
  iptables -A INPUT -p tcp --dport 22  -j ACCEPT  # SSH
  iptables -A INPUT -p tcp --dport 80  -j ACCEPT  # HTTP
  iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # HTTPS
  iptables -A INPUT -p icmp -j ACCEPT             # Ping

  # 4. 나머지 차단 (기본 정책)
  iptables -P INPUT DROP
  iptables -P FORWARD DROP

규칙 순서가 중요합니다!
  - ESTABLISHED,RELATED 허용을 DROP 정책보다 먼저
  - 더 구체적인 규칙을 더 일반적인 규칙보다 먼저
  - LOG 규칙을 DROP 규칙보다 먼저

규칙 영구 저장 (실제 환경):
  iptables-save > /etc/iptables/rules.v4
  iptables-restore < /etc/iptables/rules.v4
`),
		Examples: []Example{
			{
				Cmd:         "iptables -F && iptables -t nat -F",
				Explanation: "모든 규칙 초기화 (주의: 실제 서버에서는 SSH 연결이 끊길 수 있음)",
			},
			{
				Cmd:         "iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT",
				Explanation: "multiport 모듈로 HTTP/HTTPS를 한 번에 허용",
			},
		},
		Tasks: []*Task{
			{
				Title: "웹 서버 방화벽 완성",
				Description: `다음 조건을 모두 만족하는 방화벽을 구성하세요:
  ✓ ESTABLISHED,RELATED 상태 허용
  ✓ SSH (22) 허용
  ✓ HTTP (80) 허용
  ✓ HTTPS (443) 허용
  ✓ ICMP (ping) 허용
  ✓ INPUT 기본 정책: DROP
  ✓ FORWARD 기본 정책: DROP`,
				Hint: "순서: ESTABLISHED → 포트 허용 → 정책 DROP",
				Setup: func(c *iptables.MockClient) {
					c.Reset() // Start fresh
				},
				Validate: func(s *iptables.State) bool {
					filter := s.Tables[iptables.TableFilter]
					input := filter.Chains["INPUT"]
					forward := filter.Chains["FORWARD"]
					if input == nil || forward == nil {
						return false
					}
					if input.Policy != "DROP" || forward.Policy != "DROP" {
						return false
					}
					checks := []func(*iptables.Rule) bool{
						func(r *iptables.Rule) bool {
							st := r.Options["state"]
							return r.Target == "ACCEPT" && (st == "ESTABLISHED,RELATED" || st == "RELATED,ESTABLISHED")
						},
						func(r *iptables.Rule) bool {
							return r.Target == "ACCEPT" && r.Proto == "tcp" && r.Options["dport"] == "22"
						},
						func(r *iptables.Rule) bool {
							return r.Target == "ACCEPT" && r.Proto == "tcp" && r.Options["dport"] == "80"
						},
						func(r *iptables.Rule) bool {
							return r.Target == "ACCEPT" && r.Proto == "tcp" && r.Options["dport"] == "443"
						},
						func(r *iptables.Rule) bool {
							return r.Target == "ACCEPT" && r.Proto == "icmp"
						},
					}
					for _, check := range checks {
						if !hasRule(s, iptables.TableFilter, "INPUT", check) {
							return false
						}
					}
					return true
				},
				Solution: `iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -P INPUT DROP
iptables -P FORWARD DROP`,
			},
		},
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// hasRule returns true if any rule in the given table/chain matches the predicate.
func hasRule(s *iptables.State, table iptables.Table, chain string, pred func(*iptables.Rule) bool) bool {
	ts, ok := s.Tables[table]
	if !ok {
		return false
	}
	ch, ok := ts.Chains[chain]
	if !ok {
		return false
	}
	for _, r := range ch.Rules {
		if pred(r) {
			return true
		}
	}
	return false
}
