# tiptables

iptables를 루트 권한 없이 배울 수 있는 인터랙티브 터미널 학습 도구입니다.  
메모리 시뮬레이터 위에서 실제 `iptables` 명령어를 실행하고, 변경 내용을 실시간으로 시각화합니다.

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)
![License](https://img.shields.io/badge/license-MIT-blue)

## 기능

| 탭 | 설명 |
|---|---|
| **Rules** | 4개 테이블(filter/nat/mangle/raw) × 체인별 규칙 컬러 시각화 |
| **History** | 실행 이력 + before/after diff (`+`추가/`-`삭제/`~`정책변경) |
| **Study** | 7개 레슨 · 이론 · 예제 · 실습 과제 (정답 자동 검증) |

학습 내용:
1. iptables 소개 & 패킷 흐름
2. 테이블과 체인
3. 규칙 기본 문법 (-A / -I / -D / -P)
4. 상태 기반 필터링 (conntrack)
5. NAT (MASQUERADE / DNAT / SNAT)
6. 로깅과 속도 제한
7. 실전 서버 방화벽 구성

## 설치

### 바이너리 직접 다운로드 (권장)

[Releases](../../releases) 페이지에서 OS에 맞는 파일을 다운로드하세요.

```bash
# Linux (amd64)
curl -L https://github.com/lunghyun/tiptables/releases/download/v0.0.1/tiptables_linux_amd64 -o tiptables
chmod +x tiptables
./tiptables
```

```bash
# macOS (Apple Silicon)
curl -L https://github.com/lunghyun/tiptables/releases/download/v0.0.1/tiptables_darwin_arm64 -o tiptables
chmod +x tiptables
./tiptables
```

### Go로 빌드

```bash
git clone https://github.com/lunghyun/tiptables.git
cd tiptables
go build -o tiptables .
./tiptables
```

## 사용법

```bash
./tiptables           # 시작 (Rules 탭)
./tiptables -study    # 학습 모드로 바로 시작
./tiptables -help     # 도움말
```

### 키보드 단축키

| 키 | 동작 |
|---|---|
| `Tab` / `1` `2` `3` | 탭 전환 |
| `Enter` | 명령어 실행 |
| `Esc` | 입력 취소 / 실습 나가기 |
| `↑↓` / `j k` | 스크롤 |
| `← →` / `h l` | 체인·테이블 전환 (Rules) |
| `p` / `n` | 이전/다음 레슨 (Study) |
| `t` | 실습 시작 (Study) |
| `s` | 정답 보기/숨기기 (실습 중) |
| `?` | 도움말 오버레이 |
| `reset` | 상태 초기화 |
| `q` / `Ctrl+C` | 종료 |

### 명령어 예시

```bash
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -s 1.2.3.4 -j DROP
iptables -P INPUT DROP
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.10:80
iptables -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -F
iptables -L
```

## 프로젝트 구조

```
tiptables/
├── main.go
├── internal/
│   ├── iptables/
│   │   ├── types.go       # Rule, Chain, State 타입
│   │   ├── mock.go        # 명령어 파서 + 메모리 시뮬레이터
│   │   ├── diff.go        # before/after diff 계산
│   │   └── mock_test.go   # 단위 테스트
│   ├── study/
│   │   └── lessons.go     # 7개 레슨 + 실습 과제
│   └── tui/
│       ├── model.go       # bubbletea 모델 & 키 처리
│       ├── styles.go      # lipgloss 스타일
│       └── views.go       # 탭별 렌더링
```

## 라이선스

MIT
