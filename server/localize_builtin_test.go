package server

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestLocalizeBuiltinToolTextKeepsSchemaStructure(t *testing.T) {
	translations := map[string]string{}
	if err := json.Unmarshal(toolDefaultTranslationsJSON, &translations); err != nil {
		t.Fatal(err)
	}
	const old = "返回条数，默认 20，上限 100"
	if translations[old] == "" || hasHan(translations[old]) {
		t.Fatalf("missing Korean default for %q", old)
	}
	keys := []string{old}
	original := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"limit": map[string]any{"type": "integer", "description": old, "default": float64(20)},
			"q":     map[string]any{"type": "string", "description": "사용자가 작성한 설명"},
			"mode":  map[string]any{"type": "string", "enum": []any{old}, "default": old},
		},
	}
	copyJSON, _ := json.Marshal(original)
	var copied any
	if err := json.Unmarshal(copyJSON, &copied); err != nil {
		t.Fatal(err)
	}
	localized := localizeSchemaStrings(copied, translations, keys).(map[string]any)
	properties := localized["properties"].(map[string]any)
	if got := properties["limit"].(map[string]any)["description"]; got != translations[old] {
		t.Fatalf("default description = %q", got)
	}
	if got := properties["limit"].(map[string]any)["default"]; got != float64(20) {
		t.Fatalf("default value = %v", got)
	}
	if !reflect.DeepEqual(properties["mode"], original["properties"].(map[string]any)["mode"]) {
		t.Fatal("input enum or default changed")
	}
	if !reflect.DeepEqual(properties["q"], original["properties"].(map[string]any)["q"]) {
		t.Fatal("user description changed")
	}
	const oldTemplate = "可选：只读继承的来源任务 id 列表(最多 %d 个)。子任务可只读引用这些任务已探明的资产/结论作为起点；与 parent_ref 的纯父子指针不同，这是内容继承。"
	oldDescription := strings.Replace(oldTemplate, "%d", "5", 1)
	got := translateOldDefault(oldDescription, translations, []string{oldTemplate})
	if hasHan(got) || !strings.Contains(got, "5개") {
		t.Fatalf("formatted default description not localized: %q", got)
	}
}
