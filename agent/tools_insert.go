package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// assetInterceptCandidates 提取一条待插入资产输入项的 域名/IP/URL 候选串，用于资产拦截匹配。
// URL 的 host 会拆出归类，使「只带 URL」的服务/端点资产也能被 域名/IP 规则命中。
func assetInterceptCandidates(item assetInputItem) (domains, ips, urls []string) {
	add := func(dst *[]string, s string) {
		if s = strings.TrimSpace(s); s != "" {
			*dst = append(*dst, s)
		}
	}
	add(&domains, item.Domain)
	for _, d := range item.BoundDomains {
		add(&domains, d)
	}
	add(&ips, item.IP)
	add(&ips, item.ServiceIP)
	add(&urls, item.URL)
	if item.URL != "" {
		if u, err := url.Parse(item.URL); err == nil {
			if h := u.Hostname(); h != "" {
				if net.ParseIP(h) != nil {
					add(&ips, h)
				} else {
					add(&domains, h)
				}
			}
		}
	}
	return domains, ips, urls
}

// assetInputLabel 返回一条待插入资产的简短标识，用于拦截说明消息。
func assetInputLabel(item assetInputItem) string {
	typ := strings.TrimSpace(item.Type)
	var target string
	switch {
	case strings.TrimSpace(item.Domain) != "":
		target = strings.TrimSpace(item.Domain)
	case strings.TrimSpace(item.URL) != "":
		target = strings.TrimSpace(item.URL)
	case strings.TrimSpace(item.IP) != "":
		target = strings.TrimSpace(item.IP)
	case strings.TrimSpace(item.ServiceIP) != "":
		target = strings.TrimSpace(item.ServiceIP)
	default:
		target = "(알려지지 않은)"
	}
	if typ != "" {
		return fmt.Sprintf("[%s] %s", typ, target)
	}
	return target
}

// =====================================================================
// Unified asset insertion tools
// =====================================================================

// SetAssetStore wires the asset store and company store onto this ToolSet
// so the insert_assets, add_company_scope, and list_assets tools are active.
func (t *ToolSet) SetAssetStore(as *db.AssetStore, cs *db.CompanyStore) {
	t.as = as
	t.cs = cs
}

// assetInputItem is one element of the insert_assets "assets" array.
type assetInputItem struct {
	Type string `json:"type"` // root_domain|ip|subdomain|app|service|endpoint

	// ---- root_domain / subdomain ----
	Domain      string   `json:"domain"`
	ICP         string   `json:"icp"`
	RecordType  string   `json:"record_type"`
	RecordValue []string `json:"record_value"`

	// ---- ip ----
	IP           string           `json:"ip"`
	BoundDomains []string         `json:"bound_domains"`
	OpenPorts    []db.PortService `json:"open_ports"`

	// ---- app ----
	AppName     string `json:"app_name"`
	BundleID    string `json:"bundle_id"`
	Category    string `json:"category"`
	Description string `json:"description"`
	AppICP      string `json:"app_icp"`
	CompanyID   *int64 `json:"company_id"` // explicit company link (app only; others auto-attribute via scope)

	// ---- service (http) ----
	URL           string           `json:"url"`
	Technologies  []string         `json:"technologies"`
	StatusCode    *int             `json:"status_code"`
	ContentLength *int64           `json:"content_length"`
	PageTitle     string           `json:"page_title"`
	FaviconMMH3   string           `json:"favicon_mmh3"`
	Auth          []map[string]any `json:"auth"`
	ServiceName   string           `json:"service_name"`
	ServiceIP     string           `json:"service_ip"` // optional enrichment IP

	// ---- service (other) ----
	Port  int    `json:"port"`
	Proto string `json:"proto"`

	// ---- endpoint ----
	Method string           `json:"method"`
	Params []map[string]any `json:"params"`
}

// insertAssets is the unified insert_assets agent tool.
func (t *ToolSet) insertAssets() actool.CoreTool {
	return writeTool(
		"insert_assets",
		"새로 발견한 자산을 일괄 등록합니다. 서로 다른 type을 한 번에 넣을 수 있습니다.\n"+
			"유형별 필수 필드: root_domain→domain, ip→ip(IPv4/IPv6 주소, 호스트 이름 제외), subdomain→domain, app→app_name, service(HTTP)→url, service(기타)→service_name+port(ip/domain 중 하나 필요), endpoint→url+method. 나머지 필드는 각 설명을 참고하세요.\n"+
			"auth/technologies/params는 추가 병합(append)이며 원래 값을 덮어쓰지 않습니다. \n"+
			"반환: {results:[{index,id,type}], errors:[{index,error}]}",
		obj(map[string]any{
			// task_id 不暴露给模型：worker 归属哪个 task 由程序经 SetTaskID 权威赋值(见 handler)。
			"assets": map[string]any{
				"type":        "array",
				"description": "자산 배열, 각 요소는 자산 기록에 해당합니다.",
				"items": obj(map[string]any{
					"type": map[string]any{
						"type":        "string",
						"enum":        []string{"root_domain", "ip", "subdomain", "app", "service", "endpoint"},
						"description": "자산 유형",
					},
					// root_domain / subdomain
					"domain":      str("루트 도메인 이름 또는 하위 도메인 이름(root_domain/subdomain 필수)"),
					"icp":         str("ICP 등록번호(선택)"),
					"record_type": str("DNS 레코드 유형: A/AAAA/CNAME/MX 등(subdomain에서 선택 사항)"),
					"record_value": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "DNS 레코드 값 목록(subdomain에서 선택 사항, 예: [\"1.2.3.4\",\"2.3.4.5\"])",
					},
					// ip
					"ip": str("IP 주소는 IPv4/IPv6 주소여야 하며 호스트 이름은 입력할 수 없습니다(호스트 이름은 type=subdomain의 domain 필드를 사용하세요). ip 유형이 필요합니다. service/endpoint 유형은 채울 수 있으며 IP와 연결하는 데 사용됩니다."),
					"bound_domains": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "이 IP에 바인딩된 도메인 이름 목록(ip 유형은 선택 사항)",
					},
					"open_ports": map[string]any{
						"type":        "array",
						"description": "열린 포트 목록(ip에서 선택 사항)",
						"items": obj(map[string]any{
							"port":    intp("포트 번호"),
							"service": str("http/ssh/mysql 등의 서비스 이름(선택 사항)"),
						}, "port"),
					},
					// app
					"app_name":    str("애플리케이션 이름(app 유형 필수)"),
					"bundle_id":   str("Bundle ID (app 유형은 선택사항)"),
					"category":    str("애플리케이션 분류(선택)"),
					"description": str("애플리케이션 설명(선택사항)"),
					"app_icp":     str("앱의 ICP 등록번호(선택 사항)"),
					"company_id":  intp("소속 회사 id(app에서 선택 사항). app은 scope를 통한 자동 소속 판정에 의존할 수 없으므로 필요하면 명시하세요. add_company_scope가 반환한 id를 사용합니다."),
					// service (http)
					"url":         str("프로토콜 및 포트를 포함한 완전한 URL(HTTP 서비스 필요, service_type는 자동으로 http로 설정됨)"),
					"status_code": intp("HTTP 200/301/403/404 등의 응답 상태 코드(선택 사항)"),
					"content_length": map[string]any{
						"type":        "integer",
						"description": "HTTP 응답 본문 바이트 수(선택 사항)",
					},
					"page_title":   str("페이지 <title> 콘텐츠(선택사항)"),
					"favicon_mmh3": str("favicon MMH3 해시(선택 사항)"),
					"technologies": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "[\"Nginx\", \"Vue\", \"Bootstrap\"] 등의 지문/기술 스택 목록(선택 사항)",
					},
					"auth": map[string]any{
						"type":        "array",
						"description": "발견한 인증 정보 목록. 각 항목에 type, username, password 등의 필드를 넣을 수 있습니다(선택 사항, 기존 항목에 추가).",
						"items":       map[string]any{"type": "object"},
					},
					// service (other，非 HTTP)
					"service_name": str("ssh/mysql/redis 등의 서비스 이름(service이 HTTP이 아닌 경우 필수)"),
					"port":         intp("포트 번호(service가 HTTP가 아닌 경우 필수)"),
					// endpoint
					"method": str("HTTP 메서드: GET/POST/PUT/PATCH/DELETE 등(endpoint에서 필수)"),
					"params": map[string]any{
						"type":        "array",
						"description": "요청 매개변수 목록, 각각 location(query/body/header/path)/name/value/type 포함(선택사항, 추가하면 덮어쓰지 않음)",
						"items":       map[string]any{"type": "object"},
					},
				}, "type"),
			},
		}, "assets"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("insert_assets 활성화되지 않음: AssetStore 초기화되지 않음"), nil
			}
			var a struct {
				Assets []assetInputItem `json:"assets"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			// task_id 由程序权威赋值(worker: SetTaskID)，不接受模型传入——避免模型漏传/错传
			// 导致资产未归任务或归错任务。无任务上下文的调用方(auto/pentest/chat)其 t.taskID=0。
			taskID := t.taskID

			type result struct {
				Index int    `json:"index"`
				ID    int64  `json:"id"`
				Type  string `json:"type"`
			}
			type errEntry struct {
				Index int    `json:"index"`
				Error string `json:"error"`
			}

			var results []result
			var errs []errEntry

			// 资产闸门规则一次性载入；读取失败则跳过判定（不阻断插入）。
			// 拦截规则 = 全局 ∪ 任务级 block；允许规则 = 任务级 allow。
			blockRules, _ := t.as.ListAssetInterceptRules()
			var allowRules []db.AssetInterceptRule
			if t.taskID > 0 {
				if tb, ta, err := t.as.TaskInterceptRulesSplit(t.taskID); err == nil {
					blockRules = append(blockRules, tb...)
					allowRules = ta
				}
			}

			for i, item := range a.Assets {
				// 资产闸门：先拦截后允许，被拒的资产禁止插入（跳过 Upsert 及后续副作用）。
				domains, ips, urls := assetInterceptCandidates(item)
				if d := db.EvaluateAssetGate(blockRules, allowRules, domains, ips, urls); !d.Allowed {
					errs = append(errs, errEntry{
						Index: i,
						Error: fmt.Sprintf("자산 %s %s, 삽입 비활성화됨", assetInputLabel(item), d.Reason),
					})
					continue
				}

				typ := strings.TrimSpace(item.Type)
				var id int64
				var err error

				switch typ {
				case "root_domain":
					id, err = t.as.UpsertRootDomain(db.UpsertRootDomainReq{
						Domain: item.Domain,
						ICP:    item.ICP,
						TaskID: taskID,
					})

				case "ip":
					id, err = t.as.UpsertIP(db.UpsertIPReq{
						IP:           item.IP,
						BoundDomains: item.BoundDomains,
						OpenPorts:    item.OpenPorts,
						TaskID:       taskID,
					})

				case "subdomain":
					id, err = t.as.UpsertSubdomain(db.UpsertSubdomainReq{
						Domain:      item.Domain,
						RecordType:  item.RecordType,
						RecordValue: item.RecordValue,
						ICP:         item.ICP,
						TaskID:      taskID,
					})

				case "app":
					id, err = t.as.UpsertApp(db.UpsertAppReq{
						Name:        item.AppName,
						BundleID:    item.BundleID,
						Category:    item.Category,
						Description: item.Description,
						ICP:         item.AppICP,
						CompanyID:   item.CompanyID,
						TaskID:      taskID,
					})

				case "service":
					// distinguish HTTP vs other by presence of url
					if item.URL != "" {
						// agent may send "ip" or "service_ip" for the enrichment IP; accept both
						svcIP := item.ServiceIP
						if svcIP == "" {
							svcIP = item.IP
						}
						id, err = t.as.UpsertHTTPService(db.UpsertHTTPServiceReq{
							URL:           item.URL,
							Technologies:  item.Technologies,
							StatusCode:    item.StatusCode,
							ContentLength: item.ContentLength,
							PageTitle:     item.PageTitle,
							FaviconMMH3:   item.FaviconMMH3,
							Auth:          item.Auth,
							IP:            svcIP,
							TaskID:        taskID,
						})
					} else {
						id, err = t.as.UpsertOtherService(db.UpsertOtherServiceReq{
							Domain:      item.Domain,
							IP:          item.IP,
							Port:        item.Port,
							ServiceName: item.ServiceName,
							Auth:        item.Auth,
							TaskID:      taskID,
						})
					}

				case "endpoint":
					id, err = t.as.UpsertEndpoint(db.UpsertEndpointReq{
						URL:    item.URL,
						Method: item.Method,
						Params: item.Params,
						IP:     item.ServiceIP,
						TaskID: taskID,
					})

				default:
					errs = append(errs, errEntry{Index: i, Error: "unknown type: " + typ})
					continue
				}

				if err != nil {
					errs = append(errs, errEntry{Index: i, Error: err.Error()})
					continue
				}
				results = append(results, result{Index: i, ID: id, Type: typ})
				t.writes.Assets++
				t.anchorOwner(id)
				if taskID > 0 {
					var sourceNodeID *int64
					if t.ownerNode > 0 {
						nodeID := t.ownerNode
						sourceNodeID = &nodeID
					}
					summary := "에이전트가 insert_assets로 등록함"
					if t.ownerNode > 0 {
						summary = fmt.Sprintf("Worker 의도 #%d에서 insert_assets로 등록함", t.ownerNode)
					}
					_ = t.as.SetTaskAssetSource(taskID, id, "agent", summary, sourceNodeID)
				}
				// 自动入测试范围(source='auto')：只对 worker 顶层显式插入的这一项，按其
				// 类型加保守范围；side-effect 派生的资产不经此处，故范围不盲目扩大。taskID=0 时无操作。
				// 与覆盖度开关无关：task_scope 是任务的范围边界(list/查询的过滤基准)，
				// 覆盖度开关只决定要不要把它当分母去算指标，不决定要不要累积范围本身。
				{
					svcIP := item.ServiceIP
					if svcIP == "" {
						svcIP = item.IP
					}
					_ = t.as.AddAutoScope(taskID, typ, item.Domain, item.URL, svcIP)
				}
			}

			return jsonResult(map[string]any{
				"results": results,
				"errors":  errs,
			})
		},
	)
}

// addCompanyScope writes to company_scope table and triggers asset attribution.
func (t *ToolSet) addCompanyScope() actool.CoreTool {
	return writeTool(
		"add_company_scope",
		"회사 자산 범위에 도메인, IP, CIDR, ICP 등록번호, 회사 키워드를 추가합니다. 도메인·네트워크·ICP는 일치하는 자산을 자동으로 회사에 귀속시키며, 키워드는 에이전트에게 범위 힌트로 제공합니다.\n"+
			"회사 이름은 고유합니다. 없으면 만들고 있으면 기존 회사를 사용하며 범위만 합칩니다. scope에는 루트 도메인, URL, 단일 IP, CIDR, ICP 등록번호, 회사 키워드를 한 줄씩 넣으세요.\n"+
			"reason에 whois, 인증서, ASN 등 귀속 근거를 적으세요. 허용되지 않은 TLD나 너무 넓은 네트워크(IPv4는 /16~32, IPv6는 /32~128)를 거부하고 잘못된 항목은 errors에 반환합니다.",
		obj(map[string]any{
			"company": str("회사명(없으면 생성, 있으면 재사용, 이름은 고유함)"),
			"scope":   str("자산 범위, 한 줄에 한 줄: 도메인 이름 / URL / IP / CIDR / ICP등록 / 기업 키워드"),
			"reason":  str("귀속근거(증거/출처)를 반드시 기재해야 합니다."),
			"logo":    str("회사 아이콘 URL(선택, 새 회사를 만들 때만 유효)"),
		}, "company", "scope"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.cs == nil {
				return actool.Errorf("add_company_scope 활성화되지 않음: CompanyStore 초기화되지 않음"), nil
			}
			var a struct {
				Company string `json:"company"`
				Scope   string `json:"scope"`
				Reason  string `json:"reason"`
				Logo    string `json:"logo"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if strings.TrimSpace(a.Company) == "" {
				return actool.Errorf("company는 비워둘 수 없습니다."), nil
			}
			companyID, _, err := t.cs.UpsertCompany(a.Company, a.Logo)
			if err != nil {
				return actool.Errorf("회사를 생성/가져오지 못했습니다:" + err.Error()), nil
			}
			lines := splitLines(a.Scope)
			added, skipped, invalid, errMsgs := t.cs.AddScope(companyID, lines, a.Reason)
			out := map[string]any{
				"company_id": companyID,
				"added":      added,
				"skipped":    skipped,
				"invalid":    invalid,
			}
			if len(errMsgs) > 0 {
				out["errors"] = errMsgs
			}
			return jsonResult(out)
		},
	)
}

// addTaskScope lets the plan agent add test scope to THE CURRENT TASK — the coverage
// denominator and the task's authorization edge. Worker discoveries are auto-scoped
// (precise host) by insertAssets; this tool is for DELIBERATELY WIDENING: pull a whole
// root domain or whole company into scope, or add a specific subdomain / ip.
func (t *ToolSet) addTaskScope() actool.CoreTool {
	return writeTool(
		"add_task_scope",
		"현재 작업에 허가된 테스트 범위를 추가합니다. 이 범위는 작업의 테스트 경계이자 자산 커버리지의 기준입니다.\n"+
			"kind는 다음을 지원합니다: company(회사 전체 자산) / root_domain(모든 하위 도메인을 포함한 전체 루트 도메인) / subdomain(정확한 단일 하위 도메인) / ip / cidr / icp / keyword. \n"+
			"Worker가 발견한 개별 호스트는 시스템이 정확한 호스트 범위로 자동 추가합니다. 이 도구는 루트 도메인·회사 전체로 넓히거나 특정 하위 도메인·IP를 추가할 때 사용하세요.\n"+
			"value에는 kind에 맞는 값(기존 회사 이름 또는 id, 도메인, IP, CIDR, ICP 등록번호, 키워드)을 넣으세요. reason에 검증 가능한 근거를 남기고 여러 항목은 entries 배열로 제출하세요.",
		obj(map[string]any{
			"entries": map[string]any{"type": "array", "description": "일괄 입력: [{kind, value}]. kind는 company/root_domain/subdomain/ip/cidr/icp/keyword 중 하나입니다.", "items": map[string]any{"type": "object"}},
			"kind":    str("[싱글] company / root_domain / subdomain / ip / cidr / icp / keyword"),
			"value":   str("[단일입력] 회사명 또는 id / 도메인명 / IP / CIDR / ICP / 키워드"),
			"reason":  str("범위에 포함할 근거(감사용, 필수)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("add_task_scope 활성화되지 않음: AssetStore 초기화되지 않음"), nil
			}
			if t.taskID <= 0 {
				return actool.Errorf("add_task_scope에는 작업 컨텍스트가 필요합니다(현재는 task가 아님)"), nil
			}
			type scopeEntry struct {
				Kind  string `json:"kind"`
				Value string `json:"value"`
			}
			var a struct {
				Entries    []scopeEntry `json:"entries"`
				scopeEntry              // 单条模式
				Reason     string       `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			items := a.Entries
			if len(items) == 0 {
				items = []scopeEntry{a.scopeEntry}
			}
			var added []map[string]any
			errs := map[string]string{}
			for i, e := range items {
				ts, err := t.as.AddAgentScope(t.taskID, strings.TrimSpace(e.Kind), e.Value, a.Reason, "agent")
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				added = append(added, map[string]any{"kind": ts.Kind, "domain": ts.Domain, "net": ts.Net, "value": ts.Value, "company_id": ts.CompanyID})
			}
			out := map[string]any{"added": added}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		},
	)
}

// listUntestedAssets lets the plan agent pull the current + directly inherited
// scope's not-yet-tested assets on demand (filter by type, paginated).
func (t *ToolSet) listUntestedAssets() actool.CoreTool {
	return readTool(
		"list_untested_assets",
		"팩트 앵커에 포함되지 않은 [이 작업 및 직접 관련된 작업] 범위 내의 자산을 쿼리합니다(관련 범위는 읽기 전용이므로 보충 테스트 여부를 판단할 수 있으며 사용자를 대신하여 결정을 내리지 않습니다). \n"+
			"자산 유형별 선택적 필터링: root_domain/subdomain/service/app/endpoint/ip. \n"+
			"페이지 매기기: page는 1부터 시작하고, page_size의 기본값은 10입니다. {assets:[{id,type,label}], total, page, page_size}를 반환합니다. 작업 컨텍스트만 사용할 수 있습니다.",
		obj(map[string]any{
			"type":      str("자산 유형 필터(선택사항): root_domain/subdomain/service/app/endpoint/ip"),
			"page":      intp("1부터 시작하는 페이지 번호(기본값 1)"),
			"page_size": intp("페이지당 수(기본값 10)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("list_untested_assets 활성화되지 않음: AssetStore 초기화되지 않음"), nil
			}
			if t.taskID <= 0 || t.ts == nil {
				return actool.Errorf("list_untested_assets 작업 컨텍스트가 필요합니다."), nil
			}
			var a struct {
				Type     string `json:"type"`
				Page     int    `json:"page"`
				PageSize int    `json:"page_size"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Page <= 0 {
				a.Page = 1
			}
			if a.PageSize <= 0 {
				a.PageSize = 10
			}
			offset := (a.Page - 1) * a.PageSize
			assets, total, err := t.as.ListUntestedAssetsWithSources(t.taskID, strings.TrimSpace(a.Type), a.PageSize, offset)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"assets": assets, "total": total, "page": a.Page, "page_size": a.PageSize,
			})
		},
	)
}

// listAssets lets an agent query the asset table.
func (t *ToolSet) listAssets() actool.CoreTool {
	return readTool(
		"list_assets",
		"자산 목록을 DSL 검색식 또는 id/ids로 조회합니다. 페이징을 지원하며 현재 작업과 직접 연결된 작업의 테스트 범위에 있는 자산만 반환합니다.\n"+
			"DSL: field=value 부분 일치(ILIKE) | field==value 정확히 일치 | field!=value 제외 | 숫자 필드는 > >= < <= 지원 | 단독 단어는 전체 텍스트 부분 일치. AND/OR 조합(AND 우선), 괄호로 그룹 지정 가능. 자산 유형은 DSL 대신 별도 type 매개변수를 사용하세요.\n"+
			"id/ids가 전달되지 않으면 dsl는 비어 있지 않아야 합니다(무조건 전체 쿼리는 허용되지 않음). \n"+
			"사용 가능한 필드: domain(루트/하위/서비스 도메인 이름), root_domain, ip, url, page_title, icp, service_name, app_name, method(예: GET/POST), service_type(http|other), record_type (예: A/CNAME), technology (배열, = 퍼지 == 정확), port/status_code/company_id (정수). \n"+
			"예: status_code>=400 AND technology=shiro ; (port==80 OR port==443) AND technology=nginx",
		obj(map[string]any{
			"dsl":    str(`DSL 검색식(문법과 필드는 도구 설명 참고). id/ids를 전달하지 않으면 필수입니다.`),
			"type":   str("자산 유형 필터링: root_domain|ip|subdomain|app|service|endpoint(독립 필드, dsl와 겹쳐질 수 있음; type만으로는 쿼리하기에 충분하지 않으며 dsl가 여전히 필요함)"),
			"id":     intp("직접 조회할 단일 자산 id(선택 사항, dsl/type와 함께 사용 불가)"),
			"ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "직접 조회할 여러 자산 id(선택 사항, dsl/type와 함께 사용 불가)"},
			"limit":  intp("반환할 최대 개수(기본값 10)"),
			"offset": intp("페이징 오프셋, 기본값 0(선택 사항)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("list_assets 활성화되지 않음: AssetStore 초기화되지 않음"), nil
			}
			var a struct {
				DSL    string  `json:"dsl"`
				Type   string  `json:"type"`
				ID     int64   `json:"id"`
				IDs    []int64 `json:"ids"`
				Limit  int     `json:"limit"`
				Offset int     `json:"offset"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Limit <= 0 {
				a.Limit = 10
			}

			var assets []*db.Asset
			var err error
			switch {
			case a.ID > 0:
				assets, err = t.as.GetByIDsInScope(t.taskID, []int64{a.ID})
			case len(a.IDs) > 0:
				assets, err = t.as.GetByIDsInScope(t.taskID, a.IDs)
			case a.DSL != "":
				assets, err = t.as.QueryDSLInScope(a.DSL, a.Type, t.taskID, a.Limit, a.Offset)
			default:
				return actool.Errorf("id/ids가 전송되지 않는 경우 dsl는 비워둘 수 없습니다. 모든 자산에 대한 무조건 쿼리는 허용되지 않습니다. 쿼리 조건을 제공하십시오."), nil
			}
			if err != nil {
				return actool.Errorf("DSL 오류:" + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"count":  len(assets),
				"assets": assets,
			})
		},
	)
}

// listCompanies lets an agent enumerate companies (企业) with their scope + asset count.
func (t *ToolSet) listCompanies() actool.CoreTool {
	return readTool(
		"list_companies",
		"자산 목록의 회사와 각 회사의 범위(scope), 귀속 자산 수를 나열합니다. 반환되는 company_id는 insert_assets에서 앱을 회사에 연결하거나 list_assets에서 회사를 기준으로 검색할 때 사용합니다. search를 주면 회사 이름에 포함된 문자열로 대소문자 구분 없이 필터링합니다. 비워 두면 모두 반환합니다.",
		obj(map[string]any{
			"search": str("회사 이름에 포함된 문자열(선택 사항, 대소문자 구분 안 함). 비워 두면 모두 반환합니다."),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.cs == nil {
				return actool.Errorf("list_companies 활성화되지 않음: CompanyStore 초기화되지 않음"), nil
			}
			var a struct {
				Search string `json:"search"`
			}
			_ = json.Unmarshal(in, &a)
			cos, err := t.cs.ListCompanies()
			if err != nil {
				return actool.Errorf("회사를 쿼리하지 못했습니다:" + err.Error()), nil
			}
			q := strings.ToLower(strings.TrimSpace(a.Search))
			type companyOut struct {
				ID         int64    `json:"id"`
				Name       string   `json:"name"`
				AssetCount int      `json:"asset_count"`
				Scope      []string `json:"scope"`
			}
			out := make([]companyOut, 0, len(cos))
			for _, c := range cos {
				if q != "" && !strings.Contains(strings.ToLower(c.Name), q) {
					continue
				}
				scope := make([]string, 0, len(c.Scope))
				for _, r := range c.Scope {
					scope = append(scope, r.Raw)
				}
				out = append(out, companyOut{ID: c.ID, Name: c.Name, AssetCount: c.AssetCount, Scope: scope})
			}
			return jsonResult(map[string]any{"count": len(out), "companies": out})
		},
	)
}

// splitLines splits a multi-line string into non-empty trimmed lines.
func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// WorkerTools returns the tool set for a work agent.
func (t *ToolSet) WorkerTools() []actool.CoreTool {
	return []actool.CoreTool{
		// list_findings 保留：报漏洞前先查本任务已确认漏洞，避免重复上报同一漏洞。
		t.listFindings(),
		t.addFinding(), t.recordFact(),
		// asset management (handlers guard nil store internally)。
		// add_company_scope 不给 worker：定义企业资产范围属规划/主控/Auto 的职责，worker 只执行探索。
		t.insertAssets(), t.listAssets(),
		// 跨 work 回看：worker 也可复用其他 work 的观察，避免重复劳动。
		// search_all_worker_traces：不必先知道 intent_id，按关键字全局捞命中步骤；
		// get_worker_trace：锁定某条 work 后列步骤/就地搜/取完整内容。
		t.searchAllWorkerTraces(), t.getWorkerTrace(),
		// node_detail：worker 拿到 intent_id/节点 id 后可查该节点完整详情（配合上面的回看）。
		t.nodeDetail(),
		// 以下工具仍【不给】worker，只留给 planner/main（读上下文、跨 work 复盘是规划职责，
		// worker 只做单条意图的执行与写回）：list_facts / list_companies / list_worker_traces。
	}
}

// MainAgentTools returns the human-interface tool set.
func (t *ToolSet) MainAgentTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.graphOverview(), t.listFindings(), t.listFacts(), t.nodeDetail(),
		t.expandDigest(), // cold-digest §6.1
		t.getWorkerOutput(), t.getWorkerTrace(), t.searchAllWorkerTraces(), t.addHint(), t.addIntent(),
		// steer_work：人可对某条正在运行的意图(work)实时注入纠偏指令（不打断、不丢进展）。
		t.steerWorkTool(),
		// set_goals：人可在运行时给本任务补一个新的最终目标（规划者据此重判是否达成）。
		t.setGoals(),
		// set_constraints：人可在运行时给本任务补/改操作约束（allow/deny），约束 planner/worker 的探索边界。
		t.setConstraints(),
		// asset management (handlers guard nil store internally)
		t.insertAssets(), t.addCompanyScope(), t.listAssets(),
		t.addFinding(), t.recordFact(),
		t.addTaskScope(),
		// list_untested_assets：按需查本任务范围内未测资产(类型+分页)，自行决定补测。
		t.listUntestedAssets(),
	}
}

// AllDomainTools returns the union of all domain tools across all agent types,
// deduped by name (mainagent order wins). Used by the server to build a registry
// for injecting domain tools into agents (Auto, custom) that don't own a per-task
// ToolSet. The caller provides real stores; tools are callable at taskID=0 scope.
func (t *ToolSet) AllDomainTools() []actool.CoreTool {
	seen := map[string]bool{}
	var out []actool.CoreTool
	all := append(append(t.MainAgentTools(), t.PlannerTools()...), t.WorkerTools()...)
	for _, tool := range all {
		if !seen[tool.Name()] {
			seen[tool.Name()] = true
			out = append(out, tool)
		}
	}
	return out
}
