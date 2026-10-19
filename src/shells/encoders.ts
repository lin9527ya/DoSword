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

/** 解析已保存的协议参数（容错：非法 JSON 视为空）。 */
export function parseProtocolParams(raw: string | null | undefined): {
  encoder?: string;
  salt?: string;
  session?: boolean;
} {
  if (!raw) return {};
  try {
    const value = JSON.parse(raw) as Record<string, unknown>;
    if (typeof value !== "object" || value === null) return {};
    return {
      encoder: typeof value.encoder === "string" ? value.encoder : undefined,
      salt: typeof value.salt === "string" ? value.salt : undefined,
      session: value.session === true,
    };
  } catch {
    return {};
  }
}

/** 由编码方式 / 盐 / session 开关生成 `protocol_params` JSON。 */
export function buildProtocolParams(
  encoderId: string,
  salt: string,
  session: boolean,
): string {
  const params: Record<string, unknown> = { encoder: encoderId };
  if (salt.trim()) params.salt = salt.trim();
  if (session && supportsSessionMode(encoderId)) params.session = true;
  return JSON.stringify(params);
}
