package db

// localizeBuiltinRuleLabels updates only shipped labels from older databases.
// User changes to rule messages, enabled state, patterns and priorities are kept.
func (d *DB) localizeBuiltinRuleLabels() error {
	if v, _, _ := d.GetSetting("builtin_korean_labels_v1"); v == "done" {
		return nil
	}
	rules := [][4]string{
		{"[内置] 递归强制删除 rm -rf", "[기본] 재귀 강제 삭제 rm -rf", "禁止执行递归强制删除（rm -rf / rm --recursive），可能永久损坏系统或靶机环境", "재귀 강제 삭제(rm -rf / rm --recursive)는 시스템이나 대상 환경을 영구 손상할 수 있어 차단합니다"},
		{"[内置] 删除系统关键目录", "[기본] 시스템 주요 경로 삭제", "禁止删除系统关键路径", "시스템 주요 경로 삭제를 차단합니다"},
		{"[内置] 磁盘格式化 mkfs", "[기본] 디스크 포맷 mkfs", "禁止格式化磁盘（mkfs）", "디스크 포맷(mkfs)을 차단합니다"},
		{"[内置] 覆写磁盘设备 dd", "[기본] 디스크 장치 덮어쓰기 dd", "禁止使用 dd 覆写磁盘设备", "dd로 디스크 장치를 덮어쓰는 작업을 차단합니다"},
		{"[内置] Fork 炸弹", "[기본] 포크 폭탄", "禁止执行 Fork 炸弹", "포크 폭탄 실행을 차단합니다"},
		{"[内置] 关机 / 重启", "[기본] 시스템 종료 및 재시작", "禁止执行关机或重启命令", "시스템 종료 또는 재시작 명령을 차단합니다"},
		{"[内置] 杀死全部进程", "[기본] 모든 프로세스 종료", "禁止 kill -9 -1 或 killall -9（杀死所有进程）", "모든 프로세스를 종료하는 kill -9 -1 또는 killall -9를 차단합니다"},
		{"[内置] 磁盘擦除 shred / wipe", "[기본] 디스크 삭제 shred / wipe", "禁止对磁盘设备执行 shred/wipe 擦除", "디스크 장치에 대한 shred/wipe 삭제를 차단합니다"},
		{"[内置] 清空防火墙规则", "[기본] 방화벽 규칙 초기화", "禁止清空防火墙规则（iptables -F / nft flush）", "방화벽 규칙 초기화(iptables -F / nft flush)를 차단합니다"},
		{"[内置] SQL DROP DATABASE / TABLE / SCHEMA", "[기본] SQL DROP DATABASE / TABLE / SCHEMA", "禁止执行 DROP 操作，可能不可逆地销毁数据库对象", "데이터베이스 객체를 되돌릴 수 없이 삭제할 수 있는 DROP 작업을 차단합니다"},
		{"[内置] SQL TRUNCATE", "[기본] SQL TRUNCATE", "禁止执行 TRUNCATE，可能清空数据表所有数据", "테이블의 모든 데이터를 지울 수 있는 TRUNCATE 작업을 차단합니다"},
		{"[内置] MongoDB drop / dropDatabase", "[기본] MongoDB drop / dropDatabase", "禁止执行 MongoDB drop 操作", "MongoDB drop 작업을 차단합니다"},
		{"[内置] Redis FLUSHALL / FLUSHDB", "[기본] Redis FLUSHALL / FLUSHDB", "禁止执行 Redis FLUSHALL / FLUSHDB，可能清空全部缓存数据", "캐시 데이터를 모두 지울 수 있는 Redis FLUSHALL / FLUSHDB를 차단합니다"},
		{"[内置] curl / wget 发送 DELETE 请求", "[기본] curl / wget DELETE 요청", "禁止通过 curl/wget 发送 HTTP DELETE 请求，可能删除目标系统数据", "대상 시스템 데이터를 삭제할 수 있는 curl/wget HTTP DELETE 요청을 차단합니다"},
		{"[内置] Python HTTP 客户端 DELETE（requests/httpx/aiohttp）", "[기본] Python HTTP 클라이언트 DELETE (requests/httpx/aiohttp)", "禁止使用 Python HTTP 客户端发送 DELETE 请求", "Python HTTP 클라이언트의 DELETE 요청을 차단합니다"},
		{"[内置] 脚本中声明 HTTP DELETE 方法（JS/通用）", "[기본] 스크립트의 HTTP DELETE 메서드", "禁止在脚本中声明并发送 HTTP DELETE 请求", "스크립트에서 HTTP DELETE 요청을 보내는 작업을 차단합니다"},
		{"[内置] 批量清空 / 清除接口路径", "[기본] 대량 삭제 API 경로", "禁止调用批量清空或销毁类接口（/clear /wipe /flush /purge 等）", "대량 삭제 API(/clear /wipe /flush /purge 등) 호출을 차단합니다"},
		{"[内置] 破坏性系统命令", "[기본] 파괴적인 시스템 명령", "破坏性命令被拒绝（rm -rf / / mkfs / dd / fork bomb / 关机重启 / 覆写磁盘设备）", "파괴적인 명령(rm -rf /, mkfs, dd, 포크 폭탄, 종료·재시작, 디스크 덮어쓰기)을 차단합니다"},
		{"[内置] 数据外泄管道", "[기본] 데이터 외부 전송 파이프", "疑似数据外泄管道被拒绝（命令输出经 curl/wget/nc 外传）", "명령 출력을 curl/wget/nc로 외부 전송할 수 있는 파이프를 차단합니다"},
		{"[内置] 删除类接口路径", "[기본] 삭제 API 경로", "禁止调用删除类接口（/delete /remove /unlink /erase 等），不论使用哪种 HTTP 方法——多数应用的删除接口用 GET/POST 就能触发，同样会真实删除目标数据", "HTTP 메서드와 관계없이 삭제 API(/delete /remove /unlink /erase 등) 호출을 차단합니다. GET/POST로도 대상 데이터를 삭제할 수 있습니다"},
	}
	for _, r := range rules {
		if _, err := d.Exec(`UPDATE intercept_rules SET name=$2, message=CASE WHEN message=$3 THEN $4 ELSE message END WHERE name=$1`, r[0], r[1], r[2], r[3]); err != nil {
			return err
		}
	}
	assets := [][3]string{
		{".gov", "[内置] 政府网站 (.gov)", "[기본] 정부 사이트 (.gov)"},
		{".gov.cn", "[内置] 政府网站 (.gov.cn)", "[기본] 정부 사이트 (.gov.cn)"},
		{".edu", "[内置] 教育网站 (.edu)", "[기본] 교육 기관 사이트 (.edu)"},
		{".edu.cn", "[内置] 教育网站 (.edu.cn)", "[기본] 교육 기관 사이트 (.edu.cn)"},
	}
	for _, r := range assets {
		if _, err := d.Exec(`UPDATE asset_intercept_rules SET note=$3 WHERE builtin=true AND kind='fuzzy_domain' AND pattern=$1 AND note=$2`, r[0], r[1], r[2]); err != nil {
			return err
		}
	}
	return d.SetSetting("builtin_korean_labels_v1", "done")
}
