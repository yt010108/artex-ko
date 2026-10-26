package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/norma/harness"
)

// runTrace retains the latest tool call so an interrupted run can identify the
// operation that was still in flight.
type runTrace struct {
	startedAt time.Time
	id        string
	name      string
	input     string
	at        time.Time
	pending   bool
}

func (t *runTrace) start(id, name, input string) {
	t.id, t.name, t.input, t.at, t.pending = id, name, input, time.Now(), true
}

func (t *runTrace) done(id string) {
	if id == t.id {
		t.pending = false
	}
}

var reasonHint = map[harness.TerminalReason]string{
	harness.ReasonCompleted:         "모델이 이번 회차를 정상 종료했지만 요약을 남기지 않았습니다. 사실과 자산은 도구 호출 기록을 확인하세요",
	harness.ReasonMaxTurns:          "단계 상한(MaxTurns)에 도달했습니다. SDK가 마무리하며 사실과 자산을 기록했고, 의도는 실패 대신 exhausted로 표시됩니다",
	harness.ReasonTimeout:           "단일 실행 시간(MaxDuration)이 끝났습니다. 실행 중인 도구를 중단하고 확인된 사실과 자산을 기록한 뒤 의도를 exhausted로 표시합니다",
	harness.ReasonModelError:        "모델 또는 API 호출에 실패했습니다(네트워크, 인증, 요청 제한, 제공자 오류 등). 재시도 후에도 실패해 의도가 blocked로 표시되었습니다. 실행 기록(get_worker_trace)을 확인한 뒤 재시도 여부를 결정하세요",
	harness.ReasonBlockingLimit:     "컨텍스트 길이가 상한에 도달해 요청을 보내기 전에 차단되었습니다. 의도를 좁히거나 도구 출력을 줄이세요",
	harness.ReasonPromptTooLong:     "프롬프트가 너무 길고 컨텍스트 압축 재시도도 모두 실패해 계속할 수 없습니다",
	harness.ReasonImageError:        "현재 모델이 이번 실행의 이미지 입력을 지원하지 않습니다. 시각 기능을 지원하는 모델로 바꾸거나 도구가 이미지를 반환하지 않도록 하세요",
	harness.ReasonStopHookPrevented: "Stop 훅이 종료를 막았으나 이후에도 계속하지 못했습니다. 작업 Guard 규칙을 확인하세요",
	harness.ReasonHookStopped:       "도구 또는 훅이 실행을 중단했습니다. 범위 밖 대상이나 금지된 명령이 원인일 수 있으니 마지막 tool_result의 차단 설명을 확인하세요",
	harness.ReasonAbortedStreaming:  "모델 응답을 생성하는 중 실행이 취소되었습니다",
	harness.ReasonAbortedTools:      "도구를 실행하는 중 취소되었습니다",
}

// terminalText renders a terminal event with no final text into a compact summary
// and a Markdown detail block.
func terminalText(ctx context.Context, term *harness.Terminal, tr *runTrace) (string, string) {
	reason := term.Reason
	aborted := reason == harness.ReasonAbortedStreaming || reason == harness.ReasonAbortedTools
	// Prompt may return ctx.Err directly without a terminal event. Preserve the
	// cancellation cause instead of falling back to an empty/unknown terminal reason.
	if reason == "" && ctx.Err() != nil {
		aborted = true
	}

	var sum string
	if aborted {
		_, short, _, ok := AbortReason(ctx)
		if !ok {
			short = "취소 사유를 확인할 수 없습니다"
		}
		stage := "실행 중"
		switch reason {
		case harness.ReasonAbortedStreaming:
			stage = "모델 응답 생성 중"
		case harness.ReasonAbortedTools:
			stage = "도구 실행 중"
		}
		sum = "(실행 중단: " + short + "; " + stage + progressSuffix(term, tr) + ", 미완료)"
	} else if reason == harness.ReasonMaxTurns || reason == harness.ReasonTimeout {
		sum = "(실행 예산 상한(" + string(reason) + ")에 도달해 사실을 기록하고 마무리했습니다" + progressSuffix(term, tr) + "; 이번 실행의 요약 없음)"
	} else {
		hint := terminalReasonHint(reason)
		sum = "(요약 없음, 종료 상태 " + terminalReasonLabel(reason) + ": " + firstLine(hint, 80) + ")"
	}

	var b strings.Builder
	b.WriteString(sum)
	b.WriteString("\n\n")
	displayReason := terminalReasonLabel(reason)
	fmt.Fprintf(&b, "- **종료 상태**: `%s` - %s\n", displayReason, terminalReasonHint(reason))
	if aborted {
		code, _, why, ok := AbortReason(ctx)
		if ok {
			fmt.Fprintf(&b, "- **중단 사유** (`%s`): %s\n", code, why)
		} else {
			b.WriteString("- **중단 사유**: 확인할 수 없습니다. 취소 측에서 context.WithCancelCause로 사유를 남기지 않았을 수 있습니다\n")
		}
	}
	if term.Err != nil {
		fmt.Fprintf(&b, "- **원인 오류**: `%v`\n", term.Err)
	}
	if aborted && strings.TrimSpace(term.Text) != "" {
		b.WriteString("- **취소 전 생성된 일부 출력**:\n\n")
		b.WriteString(term.Text)
		b.WriteString("\n\n")
	}
	if term.Turns > 0 {
		fmt.Fprintf(&b, "- **실행된 모델 회차**: %d회\n", term.Turns)
	}
	if !tr.startedAt.IsZero() {
		fmt.Fprintf(&b, "- **이번 실행 시간**: %s\n", roundDur(time.Since(tr.startedAt)))
	}
	if u := term.Usage; u.InputTokens+u.OutputTokens+u.CacheReadTokens+u.CacheWriteTokens > 0 {
		fmt.Fprintf(&b, "- **누적 토큰**: 입력 %d / 출력 %d / 캐시 읽기 %d / 캐시 쓰기 %d\n",
			u.InputTokens, u.OutputTokens, u.CacheReadTokens, u.CacheWriteTokens)
	}
	if tr.name == "" {
		b.WriteString("- **도구 호출**: 이번 실행은 도구를 호출하기 전에 끝났습니다\n")
	} else if tr.pending {
		fmt.Fprintf(&b, "- **중단 시 실행 중인 도구**: `%s` (실행 시간 %s, **결과를 반환하지 않음**)\n\n  ```json\n  %s\n  ```\n",
			tr.name, roundDur(time.Since(tr.at)), firstLine(tr.input, 300))
	} else {
		fmt.Fprintf(&b, "- **중단 전 마지막 도구**: `%s` (정상적으로 결과 반환)\n", tr.name)
	}
	return sum, b.String()
}

func terminalReasonLabel(reason harness.TerminalReason) string {
	if reason == "" {
		return "context_canceled"
	}
	return string(reason)
}

func terminalReasonHint(reason harness.TerminalReason) string {
	if hint := reasonHint[reason]; hint != "" {
		return hint
	}
	if reason == "" {
		return "실행 context가 취소되었지만 Terminal 이벤트가 생성되지 않았습니다"
	}
	return "알 수 없는 종료 상태입니다. harness에 새 TerminalReason이 추가되었다면 reasonHint를 갱신하세요"
}

func progressSuffix(term *harness.Terminal, tr *runTrace) string {
	var parts []string
	if term.Turns > 0 {
		parts = append(parts, fmt.Sprintf("%d회", term.Turns))
	}
	if !tr.startedAt.IsZero() {
		parts = append(parts, roundDur(time.Since(tr.startedAt)))
	}
	if len(parts) == 0 {
		return ""
	}
	return ", 실행 " + strings.Join(parts, " / ")
}

func roundDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(100 * time.Millisecond).String()
	case d < time.Hour:
		return d.Round(time.Second).String()
	default:
		return d.Round(time.Minute).String()
	}
}
