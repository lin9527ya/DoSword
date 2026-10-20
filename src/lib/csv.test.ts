import { describe, expect, it } from "vitest";
import { buildCsv, csvCell } from "./csv";

describe("csvCell", () => {
  it("普通值不加引号", () => {
    expect(csvCell("abc")).toBe("abc");
    expect(csvCell(42)).toBe("42");
    expect(csvCell(true)).toBe("true");
  });

  it("含引号 / 逗号 / 换行的值加引号并双写内部引号", () => {
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell("a,b")).toBe('"a,b"');
    expect(csvCell("line1\nline2")).toBe('"line1\nline2"');
    expect(csvCell("cr\rlf")).toBe('"cr\rlf"');
  });

  it("null / undefined 视为空串（数据库结果里很常见）", () => {
    expect(csvCell(null)).toBe("");
    expect(csvCell(undefined)).toBe("");
  });
});

describe("buildCsv", () => {
  it("带 UTF-8 BOM、CRLF 行分隔（Excel 打开中文不乱码）", () => {
    const csv = buildCsv([
      ["时间", "操作"],
      ["2026-10-20", "shell.connect"],
    ]);
    expect(csv.startsWith("\uFEFF")).toBe(true);
    expect(csv).toBe("\uFEFF时间,操作\r\n2026-10-20,shell.connect");
  });

  it("单元格里的逗号不会串列", () => {
    const csv = buildCsv([["a,b", "c"]]);
    expect(csv.slice(1)).toBe('"a,b",c');
  });

  it("空表只输出 BOM", () => {
    expect(buildCsv([])).toBe("\uFEFF");
  });
});
