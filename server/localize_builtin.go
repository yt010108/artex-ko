package server

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"log"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/Autumn-27/artex/agent"
)

//go:embed tool_default_zh_ko.json
var toolDefaultTranslationsJSON []byte

// localizeBuiltins upgrades known shipped strings in stored defaults while keeping
// user-authored prompts, unrelated tool text, bindings, and enabled flags.
func (s *Server) localizeBuiltins() {
	pg := s.m.pg
	if _, err := pg.Exec(`UPDATE agents
		SET name='취약점 재검증', description=CASE WHEN description='从漏洞详情手动启动，读取原证据并保存独立复测结论。'
			THEN '취약점 상세 화면에서 시작하여 기존 증거를 읽고 별도의 재검증 결과를 저장합니다.' ELSE description END
		WHERE key='retester' AND name='漏洞复测'`); err != nil {
		log.Printf("[localize] 재검증 에이전트 이름 갱신 실패: %v", err)
	}
	if _, err := pg.Exec(`UPDATE agent_prompts SET note=CASE note
		WHEN '内置默认' THEN '기본 프롬프트'
		WHEN '恢复为内置默认' THEN '기본 프롬프트로 복원'
		ELSE note END
		WHERE updated_by='system' AND note IN ('内置默认','恢复为内置默认')`); err != nil {
		log.Printf("[localize] 프롬프트 이력 메모 갱신 실패: %v", err)
	}

	prompts := agent.BuiltinPromptSeeds()
	prompts["reporter"] = agent.ReporterDefaultPrompt
	prompts["retester"] = agent.RetesterDefaultPrompt
	for key, tmpl := range prompts {
		var id int64
		var current, by string
		err := pg.QueryRow(`SELECT a.id,p.template_text,COALESCE(p.updated_by,'')
			FROM agents a JOIN agent_prompts p ON p.id=a.current_prompt_id WHERE a.key=$1`, key).Scan(&id, &current, &by)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			log.Printf("[localize] %s 프롬프트 조회 실패: %v", key, err)
			continue
		}
		if by != "system" || !hasHan(current) || current == tmpl {
			continue
		}
		if _, err := pg.ResetPromptToDefault(id, tmpl); err != nil {
			log.Printf("[localize] %s 기본 프롬프트 갱신 실패: %v", key, err)
		}
	}

	translations := map[string]string{}
	if err := json.Unmarshal(toolDefaultTranslationsJSON, &translations); err != nil {
		log.Printf("[localize] 도구 번역표 읽기 실패: %v", err)
		return
	}
	keys := make([]string, 0, len(translations))
	for key := range translations {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	rows, err := pg.ListTools()
	if err != nil {
		log.Printf("[localize] 도구 목록 조회 실패: %v", err)
		return
	}
	for _, row := range rows {
		if !row.System {
			continue
		}
		desc := translateOldDefault(row.Description, translations, keys)
		var schema, oldSchema any
		if err := json.Unmarshal(row.Schema, &schema); err != nil {
			log.Printf("[localize] %s 도구 스키마 읽기 실패: %v", row.Key, err)
			continue
		}
		if err := json.Unmarshal(row.Schema, &oldSchema); err != nil {
			continue
		}
		schema = localizeSchemaStrings(schema, translations, keys)
		encoded, err := json.Marshal(schema)
		if err != nil {
			continue
		}
		if desc == row.Description && reflect.DeepEqual(schema, oldSchema) {
			continue
		}
		_, err = pg.Exec(`UPDATE tools SET description=$2,schema=$3
			WHERE key=$1 AND system AND description=$4 AND schema=$5`,
			row.Key, desc, json.RawMessage(encoded), row.Description, row.Schema)
		if err != nil {
			log.Printf("[localize] %s 도구 기본 문구 갱신 실패: %v", row.Key, err)
		}
	}
}

func hasHan(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool { return unicode.Is(unicode.Han, r) }) >= 0
}

func translateOldDefault(value string, translations map[string]string, keys []string) string {
	if translated, ok := translations[value]; ok {
		return translated
	}
	if !hasHan(value) {
		return value
	}
	for _, key := range keys {
		translated := translations[key]
		if strings.Count(key, "%d") == 1 && strings.Count(translated, "%d") == 1 {
			parts := strings.SplitN(key, "%d", 2)
			if strings.HasPrefix(value, parts[0]) && strings.HasSuffix(value, parts[1]) {
				number := strings.TrimSuffix(strings.TrimPrefix(value, parts[0]), parts[1])
				if _, err := strconv.Atoi(number); err == nil {
					return strings.Replace(translated, "%d", number, 1)
				}
			}
		}
		if strings.Contains(value, key) {
			value = strings.ReplaceAll(value, key, translated)
		}
	}
	return value
}

func localizeSchemaStrings(value any, translations map[string]string, keys []string) any {
	switch current := value.(type) {
	case []any:
		for i := range current {
			current[i] = localizeSchemaStrings(current[i], translations, keys)
		}
	case map[string]any:
		for key, item := range current {
			if (key == "description" || key == "title") && item != nil {
				if label, ok := item.(string); ok {
					current[key] = translateOldDefault(label, translations, keys)
					continue
				}
			}
			current[key] = localizeSchemaStrings(item, translations, keys)
		}
	}
	return value
}
