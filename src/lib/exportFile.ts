import { save } from "@tauri-apps/plugin-dialog";

import { api, b64 } from "../api";

/**
 * 弹保存对话框并写入文本文件；返回 `false` 表示用户取消。
 *
 * 审计导出与查询结果导出此前各写一遍「对话框 → TextEncoder → base64 → 写盘」，
 * 收敛到一处（也便于日后换成分块写大文件）。
 */
export async function saveTextFile(options: {
  defaultPath: string;
  filters: { name: string; extensions: string[] }[];
  text: string;
}): Promise<boolean> {
  const localPath = await save({
    defaultPath: options.defaultPath,
    filters: options.filters,
  });
  if (!localPath) return false;
  await api.writeLocalFile(
    localPath,
    b64.encodeBytes(new TextEncoder().encode(options.text)),
  );
  return true;
}
