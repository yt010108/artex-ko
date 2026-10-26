package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// 平台操作工具(给内置 Auto agent 用):建/改 skill、自定义工具、MCP。都是 host 工具,
// seed 进 tools 表、默认绑定 auto,经 hostTools 注入。复用现有 db/文件系统逻辑。

func (s *Server) platformTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolCreateSkill(),
		s.toolUpdateSkillFile(),
		s.toolCreateCustomTool(),
		s.toolUpdateCustomTool(),
		s.toolCreateMCP(),
		s.toolUpdateMCP(),
		s.toolDeleteAssetsByHost(),
	}
}

// platformToolKeys are the tool keys the Auto agent gets bound by default.
var platformToolKeys = []string{
	"create_skill", "update_skill_file",
	"create_custom_tool", "update_custom_tool",
	"create_mcp", "update_mcp",
	"delete_assets_by_host",
}

// ---- assets ----

// toolDeleteAssetsByHost hard-deletes every asset tied to one host (exact match).
// Platform-level (not a per-task tool): operates on the global, cross-task asset库.
func (s *Server) toolDeleteAssetsByHost() actool.CoreTool {
	return wrTool("delete_assets_by_host",
		"host와 정확히 일치하는 자산을 전역 목록에서 삭제합니다. 해당 호스트 아래의 서비스(service)와 엔드포인트(endpoint)도 삭제됩니다.\n"+
			"대소문자로 정규화하고 공백을 제거해 정확히 비교하며 퍼지·와일드카드 검색은 하지 않습니다. 루트 도메인(example.com)을 지정하면 하위 도메인과 그 서비스·엔드포인트까지 삭제합니다. 하위 도메인(a.example.com)이나 IP를 지정하면 해당 호스트와 그 아래 항목만 삭제합니다.\n"+
			"삭제는 모든 작업이 공유하는 자산 목록에 적용되며 되돌릴 수 없습니다.",
		objSchema(map[string]any{
			"host": strParam("host 삭제 대상 : 도메인명/하위도메인명/IP. 정확히 일치(예: example.com, a.example.com 또는 1.2.3.4)"),
		}, "host"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			as := s.assetStore()
			if as == nil {
				return actool.Errorf("자산 라이브러리가 초기화되지 않았습니다."), nil
			}
			var a struct {
				Host string `json:"host"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Host) == "" {
				return actool.Errorf("host는 비워둘 수 없습니다."), nil
			}
			counts, err := as.DeleteByHost(a.Host)
			if err != nil {
				return actool.Errorf("삭제 실패:" + err.Error()), nil
			}
			var total int64
			for _, n := range counts {
				total += n
			}
			return jsonResult(map[string]any{
				"host":            a.Host,
				"deleted":         total,
				"deleted_by_type": counts,
			})
		})
}

// ---- skills ----

func (s *Server) toolCreateSkill() actool.CoreTool {
	return wrTool("create_skill",
		"새 스킬을 만들고 agentskills.io 형식의 SKILL.md를 작성합니다. name에는 소문자·숫자·하이픈을 사용하세요.",
		objSchema(map[string]any{
			"name":         strParam("skill 이름(소문자로 시작, 문자/숫자/하이픈)"),
			"description":  strParam("skill 설명(필수, 기능/사용 시기 설명)"),
			"instructions": strParam("Markdown 텍스트 설명(선택사항)"),
		}, "name", "description"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Name, Description, Instructions string }
			_ = json.Unmarshal(in, &a)
			if !validSkillName(a.Name) {
				return actool.Errorf("잘못된 스킬 이름입니다(소문자로 시작, 소문자·숫자·하이픈만 사용, 최대 64자)"), nil
			}
			if strings.TrimSpace(a.Description) == "" {
				return actool.Errorf("description 필수"), nil
			}
			path := filepath.Join(s.skillDir, a.Name)
			if _, err := os.Stat(path); err == nil {
				return actool.Errorf("스킬이 이미 존재합니다: " + a.Name), nil
			}
			if err := os.MkdirAll(path, 0o755); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var b strings.Builder
			b.WriteString("---\n")
			fmt.Fprintf(&b, "name: %s\n", a.Name)
			fmt.Fprintf(&b, "description: %s\n", a.Description)
			b.WriteString("---\n")
			if strings.TrimSpace(a.Instructions) != "" {
				b.WriteString(a.Instructions)
			} else {
				fmt.Fprintf(&b, "## %s\n\n1. \n2. \n3. \n", a.Name)
			}
			if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte(b.String()), 0o644); err != nil {
				_ = os.RemoveAll(path)
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("skill created: " + a.Name), nil
		})
}

func (s *Server) toolUpdateSkillFile() actool.CoreTool {
	return wrTool("update_skill_file",
		"특정 skill(기본값 SKILL.md) 내의 파일을 쓰거나 덮어씁니다. 스킬 콘텐츠를 수정하거나 스크립트/참조를 추가하는 데 사용됩니다.",
		objSchema(map[string]any{
			"name":    strParam("skill 이름"),
			"file":    strParam("상대 경로(선택 사항, 기본값 SKILL.md, 예: scripts/run.py)"),
			"content": strParam("파일의 전체 내용"),
		}, "name", "content"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Name, File, Content string }
			_ = json.Unmarshal(in, &a)
			if !validSkillName(a.Name) {
				return actool.Errorf("skill 이름이 불법입니다"), nil
			}
			skillPath := filepath.Join(s.skillDir, a.Name)
			if _, err := os.Stat(skillPath); os.IsNotExist(err) {
				return actool.Errorf("skill이 존재하지 않습니다:" + a.Name), nil
			}
			rel := strings.TrimSpace(a.File)
			if rel == "" {
				rel = "SKILL.md"
			}
			clean, msg := skillRelPath(rel)
			if msg != "" {
				return actool.Errorf("잘못된 경로:" + msg), nil
			}
			full := filepath.Join(skillPath, clean)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if err := os.WriteFile(full, []byte(a.Content), 0o644); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("skill file written: " + a.Name + "/" + clean), nil
		})
}

// ---- custom tools ----

type customToolToolInput struct {
	Key         string          `json:"key"`
	Description string          `json:"description"`
	Kind        string          `json:"kind"`
	Exec        json.RawMessage `json:"exec"`
	Schema      json.RawMessage `json:"schema"`
	Agents      []string        `json:"agents"`
	Deferred    bool            `json:"deferred"`
	Enabled     *bool           `json:"enabled"`
}

func customToolSchema(keyDesc string) map[string]any {
	return objSchema(map[string]any{
		"key":         strParam(keyDesc),
		"description": strParam("모델에게 전송된 설명"),
		"kind":        strParam("shell | command | script(Python 전용) | http. shell=bash 환경 설명(도구가 bash에서 직접 호출될 수 있다는 점만 모델에 알리고 exec/schema은 필요하지 않음) 나머지 3개는 exec를 제공해야 합니다."),
		"exec":        map[string]any{"type": "object", "description": "실행 사양(shell 유형에는 필요하지 않음): command→{command}; script→{code}; http→{method,url,headers,body,proxy,use_recording_proxy}"},
		"schema":      map[string]any{"type": "object", "description": "매개변수 JSON-Schema(shell/command/script는 비워둘 수 있습니다. http는 필수이며 properties를 포함해야 합니다.)"},
		"agents":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "도구를 사용할 에이전트 key 목록(선택 사항)"},
		"deferred":    map[string]any{"type": "boolean", "description": "도구를 지연 로드할지 여부. shell에는 사용할 수 없고 command/script/http 도구에만 적용됩니다."},
		"enabled":     map[string]any{"type": "boolean", "description": "활성화 여부(기본값 true)"},
	}, "key", "kind")
}

func toDBTool(a customToolToolInput) *db.Tool {
	enabled := true
	if a.Enabled != nil {
		enabled = *a.Enabled
	}
	return &db.Tool{
		Key: a.Key, Description: a.Description, Schema: a.Schema, Agents: a.Agents,
		Enabled: enabled, Kind: a.Kind, Exec: a.Exec, Deferred: a.Deferred,
	}
}

func (s *Server) toolCreateCustomTool() actool.CoreTool {
	return wrTool("create_custom_tool", "사용자 지정 도구(shell/command/script/http)를 플랫폼에 등록합니다. 외부 도구를 설치했다면 이 도구로 등록해야 에이전트가 호출할 수 있습니다. shell은 bash 환경을 설명하는 유형으로 key, description, agents만 필요하며 exec/schema는 사용하지 않습니다.",
		customToolSchema("도구 key(소문자, 문자/숫자/밑줄로 시작)"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a customToolToolInput
			_ = json.Unmarshal(in, &a)
			a.Key = strings.TrimSpace(a.Key)
			if !reToolKey.MatchString(a.Key) {
				return actool.Errorf("key 소문자로 시작해야 하며 소문자/숫자/밑줄만 포함할 수 있습니다."), nil
			}
			if a.Kind != "shell" && a.Kind != "command" && a.Kind != "script" && a.Kind != "http" {
				return actool.Errorf("kind는 shell / command / script / http이어야 합니다."), nil
			}
			if a.Kind == "http" && !hasSchemaProps(a.Schema) {
				return actool.Errorf("http 도구는 매개변수 JSON Schema를 제공해야 합니다(비워둘 수 없음)."), nil
			}
			if exist, _ := s.m.pg.GetTool(a.Key); exist != nil {
				return actool.Errorf("key는 이미 존재합니다:" + a.Key), nil
			}
			if err := s.m.pg.CreateCustomTool(toDBTool(a)); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("custom tool created: " + a.Key), nil
		})
}

func (s *Server) toolUpdateCustomTool() actool.CoreTool {
	return wrTool("update_custom_tool", "key로 기존 사용자 지정 도구를 찾아 수정합니다.",
		customToolSchema("수정될 맞춤 도구 key"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a customToolToolInput
			_ = json.Unmarshal(in, &a)
			existing, _ := s.m.pg.GetTool(a.Key)
			if existing == nil || existing.System {
				return actool.Errorf("사용자 정의 도구만 수정할 수 있습니다." + a.Key), nil
			}
			if a.Kind != "shell" && a.Kind != "command" && a.Kind != "script" && a.Kind != "http" {
				return actool.Errorf("kind는 shell / command / script / http이어야 합니다."), nil
			}
			if a.Kind == "http" && !hasSchemaProps(a.Schema) {
				return actool.Errorf("http 도구는 매개변수 JSON Schema를 제공해야 합니다(비워둘 수 없음)."), nil
			}
			if err := s.m.pg.UpdateCustomTool(toDBTool(a)); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("custom tool updated: " + a.Key), nil
		})
}

// ---- MCP ----

type mcpToolInput struct {
	ID        int64           `json:"id"`
	Name      string          `json:"name"`
	Transport string          `json:"transport"`
	Command   string          `json:"command"`
	Args      json.RawMessage `json:"args"`
	Env       json.RawMessage `json:"env"`
	URL       string          `json:"url"`
	Enabled   *bool           `json:"enabled"`
	Insecure  *bool           `json:"insecure"`
}

func mcpSchema(withID bool) map[string]any {
	props := map[string]any{
		"name":      strParam("MCP 서버 이름"),
		"transport": strParam("stdio | http / sse"),
		"command":   strParam("stdio 시작 명령(예: npx)"),
		"args":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "명령 매개변수 배열"},
		"env":       map[string]any{"type": "object", "description": "환경 변수 {KEY:VALUE}"},
		"url":       strParam("http/sse/URL"),
		"enabled":   map[string]any{"type": "boolean", "description": "활성화 여부(기본값 true)"},
		"insecure":  map[string]any{"type": "boolean", "description": "http: TLS 인증서 확인 건너뛰기(자체 서명된 인증서의 경우 true로 설정, 기본값은 false)"},
	}
	required := []string{"name", "transport"}
	if withID {
		props["id"] = map[string]any{"type": "integer", "description": "수정할 MCP 서버 id"}
		required = []string{"id", "name", "transport"}
	}
	return objSchema(props, required...)
}

func (a mcpToolInput) toDB() *db.MCPServer {
	enabled := true
	if a.Enabled != nil {
		enabled = *a.Enabled
	}
	insecure := false
	if a.Insecure != nil {
		insecure = *a.Insecure
	}
	return &db.MCPServer{
		ID: a.ID, Name: a.Name, Transport: a.Transport, Command: a.Command,
		Args: a.Args, Env: a.Env, URL: a.URL, Enabled: enabled, Insecure: insecure,
	}
}

func (s *Server) toolCreateMCP() actool.CoreTool {
	return wrTool("create_mcp", "MCP 서버(stdio/http/sse)를 등록합니다. 생성 후 에이전트 가시성 설정에서 사용할 도구를 허용하세요.",
		mcpSchema(false),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a mcpToolInput
			_ = json.Unmarshal(in, &a)
			a.ID = 0
			if strings.TrimSpace(a.Name) == "" || strings.TrimSpace(a.Transport) == "" {
				return actool.Errorf("name / transport 필수"), nil
			}
			id, err := s.m.pg.SaveMCP(a.toDB())
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("mcp created: id=%d name=%s", id, a.Name)), nil
		})
}

func (s *Server) toolUpdateMCP() actool.CoreTool {
	return wrTool("update_mcp", "기존 MCP 서버를 수정합니다(id 누르기).",
		mcpSchema(true),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a mcpToolInput
			_ = json.Unmarshal(in, &a)
			if a.ID == 0 {
				return actool.Errorf("id 필수"), nil
			}
			if _, err := s.m.pg.SaveMCP(a.toDB()); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("mcp updated: id=%d", a.ID)), nil
		})
}
