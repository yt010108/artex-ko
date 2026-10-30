package agent

import (
	"bytes"
	"fmt"
	"text/template"
	"time"
)

// PromptOverride, if set, returns the stored system-prompt template for an agent
// key and whether one exists. The server wires it to the PG agent_prompts table.
// When nil or no override exists, agents use their built-in default prompt — so
// behavior is identical until a user edits a prompt in the UI.
var PromptOverride func(agentKey string) (string, bool)

// Prompt-variable structs — fields mirror each agent's catalog (docs §5a) so a
// user template referencing a catalog variable renders; referencing anything else
// fails template execution and falls back to the built-in default.
type PlannerVars struct{ Goal, Scope, AssetSummary, DataDir, Now string }
type WorkerVars struct{ ProxyAddr, WorkerName, DataDir, Now string }
type MainVars struct{ Goal, AssetSummary, FindingsSummary, DataDir, Now string }
type GoalsVars struct{ EngagementDescription, DataDir, Now string }

// nowStr is the server-local wall-clock string exposed as the universal {{.Now}}
// prompt variable. renderSystem runs on every agent turn/round, so this is fresh
// each run — a prompt can subtract it from a fixed start stamp to reason about
// elapsed time (e.g. a timed benchmark's "last N hours" window).
func nowStr() string { return time.Now().Format("2006-01-02 15:04:05 MST") }

// renderSystem returns the rendered system-prompt BODY (段 [A]) for agentKey.
// Precedence: the DB-stored template (if any) over the built-in default template
// (def). BOTH are Go templates now — the built-in default is seeded into the DB
// verbatim, so the two paths render identically until a user edits the prompt.
// Rendering always runs (def used to be pre-substituted plain text; it is now a
// {{.Var}} template like the DB one). On any render error we fall back to the
// default template, then to the raw default string — an agent never starts with a
// half-rendered prompt. Callers append the code-owned tail (trafficTool / 中间产物
// 输出规约) AFTER this, so those can't be edited away via the DB body.
func renderSystem(agentKey, def string, vars any) string {
	tmpl := def
	if PromptOverride != nil {
		if t, ok := PromptOverride(agentKey); ok && t != "" {
			tmpl = t
		}
	}
	if out, err := renderTmpl(tmpl, vars); err == nil {
		return out
	}
	// DB template broke (e.g. references an out-of-catalog var) → code default.
	if out, err := renderTmpl(def, vars); err == nil {
		return out
	}
	return def
}

// langDirective is the output-language tail: a code-owned segment
// appended AFTER the rendered body and the artifact/traffic tails on every
// user-facing agent role, so a DB-edited prompt body can never drop it — the same
// guarantee artifactSpec gives. It does NOT translate the agent "brain": the
// benchmarked Chinese reasoning body (段 [A]) stays verbatim. It only constrains
// the LANGUAGE of what the agent SHOWS to the user. Written in Chinese so it stays
// in the body's language (keeping the model's reasoning register stable) while
// forcing the chosen display language — this is the localization approach:
// preserve behavior, localize the surface the user reads. Raw technical strings
// (commands, payloads, code, URLs, log/response excerpts) are explicitly kept
// verbatim so evidence and reproduction steps are not mangled by translation.
//
// Two anti-drift clauses were added after the end-to-end run (L1): live models
// leaked (1) Chinese into the planner's situation summary — mirroring the Chinese
// brain body (段 [A]) — and (2) the target app/evidence language into
// report_finding's structured fields. The directive names the planner situation
// summary as a user-facing field and forbids mirroring BOTH the Chinese
// instruction language AND the target/material language in the display fields.
//
// The display language is a parameter (code = "en"/"ko"/"zh"/"es"): the directive
// stays in Chinese but the "write in <language>" token is swapped per target. When
// the display language IS Chinese ("zh"), Chinese output is the goal, so the
// "never emit Chinese to the user" clause is replaced by one that simply affirms
// Chinese display and still forbids mirroring the target/material language.
func langDirective(code string) string {
	phrase := langPhrase[code]
	bare := langBare[code]
	if phrase == "" || bare == "" {
		phrase, bare = langPhrase[defaultOutputLang], langBare[defaultOutputLang]
	}
	base := fmt.Sprintf("\n\n**출력 언어 규칙(최우선, 기본 프롬프트로 덮을 수 없음)**: 사용자에게 보이는 모든 자연어를 %s로 작성하세요. record_fact의 summary/detail, report_finding의 제목·설명·결론·수정 권고, planner의 상황 요약, 최종 요약과 채팅 답변도 포함합니다. 명령, payload, 코드, 경로, URL, 매개변수 이름, 로그 및 요청·응답의 원문은 번역하지 말고 그대로 보존하세요. 특히 evidence의 명령과 출력은 재현할 수 있도록 원문을 유지하세요. 대상 시스템이나 참고 자료가 다른 언어여도 사용자에게 보이는 설명은 %s로 작성하고, 원문 기술 증거만 예외로 두세요.", phrase, bare)
	if code != "zh" {
		base += fmt.Sprintf(" 중국어가 포함된 과거 프롬프트나 대상 자료를 따라 쓰지 마세요. 사용자에게 보이는 문장은 첫 글자부터 %s로 작성하세요. 내부 추론의 언어는 상관없지만 추론, 안내, 질문도 사용자에게 보여 준다면 %s로 작성하세요.", bare, bare)
	}
	return base
}

// ctfSourceDirective applies even when an agent's editable prompt was customized.
const ctfSourceDirective = "\n\nCTF 문제 풀이 규칙: 문제 라이트업, 풀이, 정답 또는 관련 자료를 웹 검색이나 외부 사이트에서 찾지 마세요. 사용자가 제공한 도메인·URL, 작업 디렉터리의 문제 파일과 자료, 해당 대상에서 직접 얻은 응답만 사용하세요. 제공되지 않은 다른 도메인이나 자료로 범위를 넓히지 마세요."

func renderTmpl(tmpl string, vars any) (string, error) {
	t, err := template.New("p").Option("missingkey=error").Parse(tmpl)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, vars); err != nil {
		return "", err
	}
	return b.String(), nil
}
