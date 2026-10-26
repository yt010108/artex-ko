package agent

import (
	"encoding/json"
	"fmt"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const findingIDGuidance = "\n\n**취약점 ID 구분**: finding_id는 독립된 취약점 기록 ID이고 finding_node_id는 탐색 그래프 노드 ID입니다. list_findings/list_task_findings/node_detail/get_task_node_detail의 id는 탐색 노드 ID이므로 별도의 finding_id 필드를 읽으세요. get_finding_traffic와 bind_finding_traffic에는 독립된 finding_id를, update_finding_report의 finding_id에는 탐색 노드 ID를 전달합니다. report_finding 첫 줄의 숫자를 트래픽 증거 도구에 전달하거나 오류가 났다고 다른 ID를 추측하지 마세요."

// The server supplies the persisted setting. A missing setting/host is off.
// Consulted at assembly and again on writes so an already-running session
// cannot keep binding after the user switches the feature off.
var FindingTrafficBindingEnabled func() bool

func findingTrafficBindingEnabled() bool {
	return FindingTrafficBindingEnabled != nil && FindingTrafficBindingEnabled()
}

// Applied after ToolResolve: user descriptions and prompts remain intact, while
// all actual reporters (including Planner and custom chat agents) see the same
// API contract. Disabled/unbound tools are never reintroduced here.
func findingWorkflowTools(agentKey string, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	if !findingTrafficBindingEnabled() {
		out := make([]actool.CoreTool, 0, len(tools))
		for _, tool := range tools {
			if tool.Name() == "bind_finding_traffic" {
				continue
			}
			if agentKey == "reporter" && (tool.Name() == "traffic_search" || tool.Name() == "traffic_get" || tool.Name() == "traffic_blob") {
				continue
			}
			switch tool.Name() {
			case "report_finding", "add_hint", "add_task_hint":
				// Work on a copy: toggling back on must restore the original schema.
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				if json.Unmarshal(raw, &schema) == nil {
					stripTrafficParameters(schema)
					tool = DecorateTool(tool, tool.Description(), schema)
				}
			}
			out = append(out, tool)
		}
		return out, ""
	}
	out := append([]actool.CoreTool(nil), tools...)
	has := map[string]bool{}
	for i, tool := range out {
		has[tool.Name()] = true
		note := ""
		switch tool.Name() {
		case "report_finding":
			note = "\n취약점은 먼저 등록하고, 보고서 에이전트가 작성 전에 트래픽을 확인해 연결합니다. evidence에 검증 명령·핵심 출력·이미 확인한 트래픽 ID와 용도를 남기세요. 트래픽 연결만을 위해 다시 테스트하지 마세요. 확인된 참조는 traffic_refs로 직접 전달하거나 현재 작업의 힌트를 가리키는 evidence_hint_id로 전달할 수 있습니다. 잘못된 참조가 있으면 등록이 실패합니다. TCP 등 트래픽 기록이 없는 취약점에서는 이 선택 매개변수를 생략할 수 있습니다. 반환되는 finding_id와 finding_node_id는 서로 다른 ID입니다."
		case "add_hint", "add_task_hint":
			note = "\n확인된 취약점을 작업 에이전트에게 넘길 때는 text에 구체적인 취약점을 적고 traffic_refs에 확인된 트래픽 ID·용도·설명·순서를 유지하세요. 단일 힌트는 최상위 필드에, 일괄 입력은 해당 hints 항목에 넣습니다. 텍스트만 전달하면서 기존 트래픽 참조를 버리거나 검증되지 않은 후보를 증거로 전달하지 마세요."
		case "get_finding_traffic", "bind_finding_traffic", "list_findings", "list_task_findings", "node_detail", "get_task_node_detail", "update_finding_report":
			note = findingIDGuidance
		}
		if note != "" {
			out[i] = DecorateTool(tool, tool.Description()+note, tool.InputSchema())
		}
	}
	guidance := ""
	if has["report_finding"] || has["add_task_hint"] || has["add_hint"] {
		guidance = "\n\n**트래픽 증거 인계(선택)**: 취약점을 등록하면 보고서 에이전트가 작성 전에 확인된 트래픽을 연결합니다. evidence에는 검증 명령·핵심 출력·기존 트래픽 ID와 용도를 남기고, 작업 안에서는 intent_id도 전달하세요. Auto나 Planner가 대신 등록할 때 기존 증거를 버리지 마세요. add_hint/add_task_hint의 traffic_refs로 넘기거나 report_finding의 traffic_refs/evidence_hint_id로 직접 연결할 수 있습니다. TCP 등 기록이 없으면 트래픽 없이 등록해도 됩니다. ID를 추측하거나 증거를 채우려고 불필요하게 다시 테스트하지 마세요."
		if has["add_task_hint"] && !has["add_hint"] {
			guidance += "\n플랫폼 대화에 작업 컨텍스트가 없다면 report_finding을 직접 호출하지 마세요. add_task_hint로 해당 작업에 전달하고 작업 에이전트가 등록한 뒤 list_task_findings로 확인하세요."
		}
		if has["prove_goal"] || has["goal_met"] {
			guidance += "\n목표 달성을 판정하기 전에 이미 확보한 증거의 등록·인계를 마치세요. 취약점 텍스트만 등록하고 증거 인계 전에 작업을 끝내거나 Worker를 중단하지 마세요. 트래픽 기록이 없다면 기다리거나 추가 캡처를 강요하지 마세요."
		}
	}
	if has["update_finding_report"] && has["bind_finding_traffic"] && has["get_finding_traffic"] {
		guidance += "\n\n**보고 전 트래픽 자동 연결(활성화)**: 이번 취약점을 뒷받침하는 트래픽을 확인하고 연결한 뒤 보고서를 작성하세요. report_finding의 JSON 또는 get_task_node_detail/list_task_findings에서 finding_id와 finding_node_id를 구분해 읽으세요. 취약점 내용·실행 기록·기존 증거를 확인하고, 등록자가 전달한 실제 트래픽 ID를 우선 검토하세요. HTTP 트래픽 도구가 있으면 traffic_search로 후보를 찾고 traffic_get으로 요청·응답을 각각 확인하세요. 도메인과 시각만으로 관련성을 단정하지 마세요. 검증된 참조만 재현 순서대로 bind_finding_traffic(finding_id, traffic_refs)에 전달하고 baseline/proof/verification/supporting 용도를 설명하세요. 취약점을 다시 등록하거나 증거를 채우려고 대상을 다시 테스트하지 마세요. 연결 후 get_finding_traffic로 최신 version과 필요한 본문을 읽고, update_finding_report의 evidence_version에 실제 읽은 version을 전달하세요. 이때 update_finding_report의 finding_id에는 finding_node_id를 사용합니다. 이미 연결된 증거는 중복 추가하지 마세요. TCP 등 정확한 트래픽이 없으면 텍스트·명령 증거로 보고서를 작성하고 이유를 밝히세요. 연결이 실패했다면 성공했다고 쓰지 마세요."
	}
	if guidance != "" || has["get_finding_traffic"] || has["update_finding_report"] {
		guidance += findingIDGuidance
	}
	return out, guidance
}

func stripTrafficParameters(schema map[string]any) {
	props, _ := schema["properties"].(map[string]any)
	delete(props, "traffic_refs")
	delete(props, "evidence_hint_id")
	if required, ok := schema["required"].([]any); ok {
		kept := required[:0]
		for _, key := range required {
			if key != "traffic_refs" && key != "evidence_hint_id" {
				kept = append(kept, key)
			}
		}
		schema["required"] = kept
	}
	if hints, ok := props["hints"].(map[string]any); ok {
		if items, ok := hints["items"].(map[string]any); ok {
			stripTrafficParameters(items)
		}
	}
}

// HintTrafficSchema is shared by the task-local and cross-task hint tools.
func HintTrafficSchema() map[string]any {
	return map[string]any{"type": "array", "description": "선택 사항. 이 힌트의 취약점을 실제로 뒷받침하는 확인된 트래픽 참조를 순서대로 넣으세요. 이후 report_finding에 evidence_hint_id를 전달하면 이 참조를 인계할 수 있습니다.", "items": obj(map[string]any{"traffic_id": str("확인된 실제 트래픽 ID"), "role": str("baseline / proof / verification / supporting"), "note": str("이 트래픽이 뒷받침하는 결론")}, "traffic_id")}
}

func (t *ToolSet) findingRefsFromHint(hintID int64, explicit []db.TrafficRef) ([]db.TrafficRef, error) {
	if hintID <= 0 {
		return db.NormalizeTrafficRefs(explicit)
	}
	n, err := t.ts.GetNode(hintID) // local store only: inherited hints cannot supply evidence
	if err != nil {
		return nil, err
	}
	if n == nil || n.Kind != db.KindHint {
		return nil, fmt.Errorf("evidence_hint_id=%d은 현재 작업의 힌트 노드여야 합니다(상속된 힌트는 직접 연결할 수 없습니다).", hintID)
	}
	var payload struct {
		Refs []db.TrafficRef `json:"traffic_refs"`
	}
	if err := json.Unmarshal(n.Payload, &payload); err != nil {
		return nil, err
	}
	return db.NormalizeTrafficRefs(append(append([]db.TrafficRef{}, explicit...), payload.Refs...))
}
