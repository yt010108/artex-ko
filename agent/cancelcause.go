package agent

import (
	"context"
	"errors"
	"fmt"
)

// AbortCause names why an agent run's context was cancelled. Every cancellation
// site should attach one so the activity trace can report the real initiator.
type AbortCause struct {
	Code  string
	Short string
	Text  string
}

func (c *AbortCause) Error() string { return c.Text }

func cause(code, short, text string) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: text}
}

// Causef builds a cause that includes runtime-specific detail.
func Causef(code, short, format string, args ...any) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: fmt.Sprintf(format, args...)}
}

var (
	// Task-level execution context.
	AbortPausedByUser = cause("paused_by_user", "사용자가 작업을 일시정지했습니다",
		"사용자가 작업 제어 API(POST /api/tasks/{id}/control, action=pause)로 작업을 일시정지했습니다. 실행 중이던 Planner/Worker가 취소되고 의도는 frontier(open)로 돌아갑니다. 작업을 재개하면 처음부터 다시 실행합니다")
	AbortPausedByOrchestrator = cause("paused_by_orchestrator", "운영 에이전트가 작업을 일시정지했습니다",
		"운영 에이전트가 pause_task 도구로 작업을 일시정지했습니다. 실행 중이던 Planner/Worker가 취소되고 의도는 frontier(open)로 돌아갑니다. 재개하면 다시 실행합니다")
	AbortTaskDeleted = cause("task_deleted", "작업이 삭제되었습니다",
		"작업 삭제(DELETE /api/tasks/{id})가 진행되어 실행 중인 Planner, Worker, 메인 에이전트가 취소되었습니다. 이번 실행 결과는 사용하지 않습니다")
	AbortPausedOnReload = cause("paused_on_reload", "서버가 작업의 일시정지 상태를 복원했습니다",
		"서버 시작 시 데이터베이스에 저장된 일시정지 상태를 복원하면서 이번 실행이 취소되었습니다. 정상적인 복원 중에는 실행 중인 에이전트가 없습니다")
	AbortGoalMet = cause("goal_met", "플래너가 작업 목표 달성을 확인했습니다",
		"플래너가 목표 달성을 확인하고 작업을 done으로 변경하여 실행 중인 Worker를 취소했습니다. 해당 의도는 실패가 아니라 stopped로 표시됩니다")
	AbortSettleDrainTimeout = cause("settle_drain_timeout", "작업 시간 초과 후 정리 대기가 끝났습니다",
		"작업이 timeout에 도달한 뒤 실행 중인 Worker의 마무리를 90초 동안 기다렸지만 완료되지 않아 강제 취소했습니다. 의도는 exhausted로 표시되고, 마무리 중 기록한 사실과 자산은 유지됩니다")

	// Per-work context.
	AbortKilledByPlanner = cause("killed_by_planner", "플래너가 의도를 종료했습니다",
		"플래너가 kill_work로 의도를 종료했습니다. 탐색 방향이 벗어났거나 계속할 가치가 없을 때 사용합니다. 의도는 stopped로 표시되며 자동으로 다시 할당되지 않습니다")
	AbortWorkPausedByUser = cause("work_paused_by_user", "사용자가 Worker 의도를 일시정지했습니다",
		"사용자가 실행 중인 Worker를 일시정지해 이번 호출이 취소되고 의도는 paused가 되었습니다. 기록된 의도, 사실, 취약점, 활동은 유지되며 재개하면 처음부터 다시 실행합니다")
	AbortWorkCancelledByUser = cause("work_cancelled_by_user", "사용자가 Worker 의도를 삭제했습니다",
		"사용자가 실행 중인 Worker를 삭제해 이번 호출이 취소되었습니다. Worker가 기록 작업을 마치면 선택한 삭제 방식에 따라 의도를 처리합니다. 소프트 삭제는 결과를 보존하고, 영구 삭제는 의도와 해당 의도에만 의존하는 하위 노드를 함께 제거합니다")
	AbortWorkFinished = cause("work_finished", "Worker가 정상 종료되어 context를 해제했습니다",
		"Worker가 정상 종료되어 엔진이 detachWork에서 context를 해제했습니다. 실행 중단이 아닙니다. 중단 메시지에 표시된다면 취소와 종료가 동시에 일어난 것입니다")
	AbortPausedRaceGuard = cause("paused_race_guard", "일시정지 중 새 실행을 막았습니다",
		"일시정지 중에는 엔진이 새 실행 context를 만들지 않습니다. 의도 할당과 일시정지가 겹쳐 Worker가 시작되는 상황을 막으며, 이미 할당된 의도는 frontier로 돌아갑니다")

	// Main Agent and standalone conversation contexts.
	AbortChatStoppedByUser = cause("chat_stopped_by_user", "사용자가 이번 대화를 중지했습니다",
		"사용자가 중지를 눌러 이번 메인 에이전트 또는 대화 에이전트 실행을 종료했습니다. 기존 활동 기록은 유지되며 다음 메시지를 보낼 수 있습니다")
	AbortChatPausedWithTask = cause("chat_paused_with_task", "작업 일시정지로 메인 에이전트 대화가 중단되었습니다",
		"사용자가 작업을 일시정지하면서 실행 중인 메인 에이전트 대화도 취소되었습니다. 기존 활동 기록은 유지되며, 작업을 재개해도 이번 메시지는 자동 재실행되지 않습니다")
	AbortChatTurnFinished = cause("chat_turn_finished", "이번 대화가 정상 종료되어 context를 해제했습니다",
		"이번 대화가 정상 종료되어 서버가 context를 해제하고 있습니다. 실행 중단이 아닙니다. 중단 메시지에 표시된다면 취소와 종료가 동시에 일어난 것입니다")

	// Process-level and per-run hard backstop.
	AbortShutdown = cause("shutdown", "서버 프로세스가 종료 중입니다",
		"서버가 SIGINT 또는 SIGTERM을 받아 재시작, 업데이트 또는 종료 중입니다. 실행 중인 에이전트가 취소되며, 재시작 뒤 남은 running 의도는 open으로 초기화되어 다시 실행됩니다")
	AbortRunHardTimeout = cause("run_hard_timeout", "단일 실행의 강제 시간 제한에 도달했습니다",
		"단일 실행이 시간 예산과 추가 유예를 넘었습니다. 모델 요청이나 도구가 오래 응답하지 않아 정상적인 마무리를 할 수 없습니다. 중단 직전 마지막으로 결과를 반환하지 않은 도구 호출을 확인하세요")
)

// AbortReason resolves the named cause attached to a cancelled run context.
func AbortReason(ctx context.Context) (code, short, text string, ok bool) {
	c := context.Cause(ctx)
	if c == nil {
		return "", "", "", false
	}
	var ac *AbortCause
	if errors.As(c, &ac) {
		return ac.Code, ac.Short, ac.Text, true
	}
	switch {
	case errors.Is(c, context.DeadlineExceeded):
		return "deadline_exceeded", "상위 context가 시간 제한에 도달했습니다",
			"상위 context가 시간 제한에 도달했지만 설정 측에서 WithTimeoutCause로 사유를 남기지 않았습니다: " + c.Error(), true
	case errors.Is(c, context.Canceled):
		return "canceled_no_cause", "취소 사유가 기록되지 않았습니다",
			"상위 context가 취소되었지만 context.WithCancelCause로 사유를 남기지 않았습니다. agent/cancelcause.go에 사유를 등록하고 해당 취소 지점에 연결하세요", true
	default:
		return "other", firstLine(c.Error(), 80), c.Error(), true
	}
}
