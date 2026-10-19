/**
 * 编码方式 → 通道能力。
 *
 * 与后端 `src-tauri/src/protocol/php.rs` 的 `session_mode_for` 保持同义：
 * 前端生成 stub 与登记 Shell 必须用**同一套规则**，否则会出现
 * 「生成器能勾 session、登记表单没这个字段」这类不一致（历史上确实如此）。
 */

/** NATIVE 系列：stub 自带内置功能分发，无 eval 注入通道。 */
export function isNativeEncoder(encoderId: string): boolean {
  return encoderId.startsWith("native");
}

/** 该编码方式是否支持「分阶段载荷（session 模式）」。 */
export function supportsSessionMode(encoderId: string): boolean {
  // xor_session 编码器本身即分阶段载荷
  if (encoderId === "xor_session") return true;
  // NATIVE 自带内置分发，session 开关会被忽略
  if (isNativeEncoder(encoderId)) return false;
  // php_stream 用 include 流执行请求体，没有可注入处理器的 eval 通道
  if (encoderId === "php_stream") return false;
  return true;
}

/** 该编码方式是否只能以 session 通道工作（无需显式开关）。 */
export function forcesSessionMode(encoderId: string): boolean {
  return encoderId === "xor_session";
}

/**
 * 传输形态（W2，存在 protocol_params.transport）。
 *
 * `param` / `header` 必须与生成 stub 时的配置一致（只有 NATIVE 系列把它们烘焙进
 * stub）；其余字段只改变客户端请求形态。
 */
export type TransportProfile = {
  param?: string;
  header?: string;
  pathSuffix?: string;
  padding?: number;
  extraHeaders?: Record<string, string>;
};

/** 解析已保存的协议参数（容错：非法 JSON 视为空）。 */
export function parseProtocolParams(raw: string | null | undefined): {
  encoder?: string;
  salt?: string;
  session?: boolean;
  transport?: TransportProfile;
} {
  if (!raw) return {};
  try {
    const value = JSON.parse(raw) as Record<string, unknown>;
    if (typeof value !== "object" || value === null) return {};
    const rawTransport = value.transport;
    const transport: TransportProfile | undefined =
      typeof rawTransport === "object" && rawTransport !== null
        ? {
            param:
              typeof (rawTransport as Record<string, unknown>).param === "string"
                ? ((rawTransport as Record<string, unknown>).param as string)
                : undefined,
            header:
              typeof (rawTransport as Record<string, unknown>).header === "string"
                ? ((rawTransport as Record<string, unknown>).header as string)
                : undefined,
            pathSuffix:
              typeof (rawTransport as Record<string, unknown>).pathSuffix === "string"
                ? ((rawTransport as Record<string, unknown>).pathSuffix as string)
                : undefined,
            padding:
              typeof (rawTransport as Record<string, unknown>).padding === "number"
                ? ((rawTransport as Record<string, unknown>).padding as number)
                : undefined,
            extraHeaders:
              typeof (rawTransport as Record<string, unknown>).extraHeaders === "object" &&
              (rawTransport as Record<string, unknown>).extraHeaders !== null
                ? ((rawTransport as Record<string, unknown>).extraHeaders as Record<
                    string,
                    string
                  >)
                : undefined,
          }
        : undefined;
    return {
      encoder: typeof value.encoder === "string" ? value.encoder : undefined,
      salt: typeof value.salt === "string" ? value.salt : undefined,
      session: value.session === true,
      transport,
    };
  } catch {
    return {};
  }
}

/** 由编码方式 / 盐 / session 开关 / 传输形态生成 `protocol_params` JSON。 */
export function buildProtocolParams(
  encoderId: string,
  salt: string,
  session: boolean,
  transport?: TransportProfile,
): string {
  const params: Record<string, unknown> = { encoder: encoderId };
  if (salt.trim()) params.salt = salt.trim();
  if (session && supportsSessionMode(encoderId)) params.session = true;

  const profile: TransportProfile = {};
  // 参数名 / 头名只对 NATIVE 系列生效；与默认值相同时不写入（保持配置干净）
  if (isNativeEncoder(encoderId)) {
    const param = transport?.param?.trim();
    if (param && param !== "formData") profile.param = param;
    const header = transport?.header?.trim();
    if (header && header !== "X-Debug-Key") profile.header = header;
  }
  const suffix = transport?.pathSuffix?.trim();
  if (suffix) profile.pathSuffix = suffix;
  if (transport?.padding && transport.padding > 0) profile.padding = transport.padding;
  const headers = Object.fromEntries(
    Object.entries(transport?.extraHeaders ?? {})
      .map(([name, value]) => [name.trim(), value] as const)
      .filter(([name, value]) => name && value),
  );
  if (Object.keys(headers).length > 0) profile.extraHeaders = headers;
  if (Object.keys(profile).length > 0) params.transport = profile;

  return JSON.stringify(params);
}

/** 额外请求头文本 ↔ 对象（每行 `Name: Value`）。 */
export function parseHeaderLines(text: string): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const index = trimmed.indexOf(":");
    if (index <= 0) continue;
    const name = trimmed.slice(0, index).trim();
    const value = trimmed.slice(index + 1).trim();
    if (name) headers[name] = value;
  }
  return headers;
}

export function headerLines(headers?: Record<string, string>): string {
  return Object.entries(headers ?? {})
    .map(([name, value]) => `${name}: ${value}`)
    .join("\n");
}
