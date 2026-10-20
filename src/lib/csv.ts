/**
 * CSV 生成（审计导出、数据库查询结果导出共用）。
 *
 * 此前两处各写一份 `csvCell`，且行为不一致（一处无条件加引号、一处按需加），
 * 导出结果随调用点变化 —— 收敛到一处。
 */

/**
 * 单元格转义：含引号 / 逗号 / 换行的值加引号并双写内部引号；
 * `null` / `undefined` 视为空串（数据库查询结果里很常见）。
 */
export function csvCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  const text = String(value);
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/**
 * 生成 CSV 文本。开头带 UTF-8 BOM：Excel 打开中文不乱码（不带 BOM 会显示成乱码）。
 * 行分隔用 CRLF（Excel / Windows 工具链的默认预期）。
 */
export function buildCsv(rows: readonly (readonly unknown[])[]): string {
  const body = rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
  return `\uFEFF${body}`;
}
