export const mentionKinds = [
  { kind: "finding", label: "취약점", alias: "finding" },
  { kind: "asset", label: "자산", alias: "asset" },
  { kind: "company", label: "기업", alias: "company" },
  { kind: "endpoint", label: "엔드포인트", alias: "api" },
  { kind: "ip", label: "IP", alias: "ip" },
  { kind: "app", label: "앱", alias: "app" },
  { kind: "root_domain", label: "도메인", alias: "domain" },
  { kind: "subdomain", label: "서브도메인", alias: "subdomain" },
  { kind: "service", label: "서비스", alias: "service" },
] as const;

export type MentionKind = (typeof mentionKinds)[number]["kind"];

const legacyMentionLabels: Record<string, MentionKind> = {
  漏洞: "finding", 资产: "asset", 企业: "company", 接口: "endpoint",
  应用: "app", 域名: "root_domain", 子域名: "subdomain", 服务: "service",
};
export interface ChatMention {
  kind: MentionKind;
  id: number;
  label: string;
  description: string;
}

export function activeMention(value: string, caret: number) {
  const before = value.slice(0, caret);
  const start = before.lastIndexOf("@");
  if (start < 0 || (start > 0 && /[\w.+/-]/.test(before[start - 1]))) return null;
  const query = before.slice(start + 1);
  if (/[[\]\r\n@]/.test(query) || query.length > 220) return null;
  return { start, end: caret, query };
}

export function mentionSearch(query: string) {
  const text = query.trimStart().toLowerCase();
  for (const item of mentionKinds) {
    const legacy = Object.keys(legacyMentionLabels).find((label) => legacyMentionLabels[label] === item.kind);
    for (const alias of [item.label.toLowerCase(), item.alias, legacy].filter((value): value is string => Boolean(value))) {
      if (text === alias || text.startsWith(`${alias} `) || (/[^a-z]/.test(alias) && text.startsWith(alias))) {
        return { kind: item.kind, query: query.trimStart().slice(alias.length).trim(), categories: [] };
      }
    }
  }
  const categories = mentionKinds.filter(
    (item) =>
      item.label.toLowerCase().startsWith(text) ||
      item.alias.startsWith(text) ||
      Object.entries(legacyMentionLabels).some(([label, kind]) => kind === item.kind && label.startsWith(text)),
  );
  return { kind: "" as const, query: query.trim(), categories };
}

export function mentionToken(item: ChatMention) {
  const kind = mentionKinds.find((entry) => entry.kind === item.kind)?.label ?? "자산";
  const label = item.label
    .replace(/[[\]]/g, (char) => (char === "[" ? "（" : "）"))
    .replace(/\s+/g, " ")
    .slice(0, 100);
  return `@[${kind}#${item.id} ${label}]`;
}

export interface SelectedMention {
  token: string;
  kind: MentionKind;
  id: string;
  text: string;
  start: number;
}

// 새 인용은 한국어 라벨을 쓰고, 기존 대화에 저장된 중국어 라벨도 계속 읽는다.
export function selectedMentions(value: string): SelectedMention[] {
  return [...value.matchAll(/@\[(취약점|자산|기업|엔드포인트|IP|앱|도메인|서브도메인|서비스|漏洞|资产|企业|接口|应用|域名|子域名|服务)#([0-9]+)(?: ([^\]\r\n]*))?\]/g)].map(
    (match) => ({
      token: match[0],
      kind: mentionKinds.find((entry) => entry.label === match[1])?.kind ?? legacyMentionLabels[match[1]] ?? "asset",
      id: match[2],
      text: match[3] ?? "",
      start: match.index,
    }),
  );
}
