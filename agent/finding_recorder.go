package agent

import (
	"context"

	"github.com/Autumn-27/artex/db"
)

// FindingRecorder is injected by the host; agents never synthesize or copy
// evidence bodies themselves. Its implementation owns the atomic write.
type FindingRecorder interface {
	Record(context.Context, db.RecordFindingInput, []db.TrafficRef) (*db.RecordedFinding, error)
}

// Tool-use guidance is appended without replacing the user's editable prompt.
// It does not require capture or claim that unavailable traffic tools exist.
const findingTrafficGuidance = "\n\n**취약점 트래픽 증거(선택 사항)**: report_finding을 호출할 때 결론을 뒷받침하는 실제 HTTP 요청·응답을 확인했다면 traffic_refs에 재현 순서대로 연결하세요. 도메인이나 시각은 후보를 찾는 데만 쓰고, 그것만으로 관련성을 단정하지 마세요. TCP 등 비 HTTP 취약점이나 정확한 트래픽 기록이 없다면 traffic_refs를 생략하거나 []로 전달해도 됩니다. evidence에는 명령 출력·로그 등 다른 검증 가능한 근거를 남기고, 트래픽을 연결하지 못한 이유도 적으세요. ID를 추측하거나 트래픽을 채우려고 불필요하게 다시 테스트하지 마세요."

func (t *ToolSet) SetFindingRecorder(r FindingRecorder)   { t.findingRecorder = r }
func (w *Worker) SetFindingRecorder(r FindingRecorder)    { w.findingRecorder = r }
func (p *Planner) SetFindingRecorder(r FindingRecorder)   { p.findingRecorder = r }
func (m *MainAgent) SetFindingRecorder(r FindingRecorder) { m.findingRecorder = r }
