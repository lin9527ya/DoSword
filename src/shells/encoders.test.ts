import { describe, expect, it } from "vitest";
import {
  buildProtocolParams,
  forcesSessionMode,
  headerLines,
  isNativeEncoder,
  parseHeaderLines,
  parseProtocolParams,
  supportsSessionMode,
} from "./encoders";

// 这套规则与后端 `protocol::php::session_mode_for` 同义。前端生成 stub 与登记 Shell
// 必须一致，否则会出现「生成器能勾 session、登记表单没这个字段」这类历史缺陷 ——
// 所以这里把分类边界钉死。

describe("编码方式分类", () => {
  it("NATIVE 系列按 id 前缀识别", () => {
    for (const id of ["native", "native_aead", "native_aes_cbc", "native_chacha20"]) {
      expect(isNativeEncoder(id)).toBe(true);
    }
    for (const id of ["xor_session", "base64", "php_stream"]) {
      expect(isNativeEncoder(id)).toBe(false);
    }
  });

  it("NATIVE 自带内置分发 → session 开关会被忽略", () => {
    expect(supportsSessionMode("native")).toBe(false);
    expect(supportsSessionMode("native_aead")).toBe(false);
  });

  it("xor_session 本身即分阶段载荷：支持且强制", () => {
    expect(supportsSessionMode("xor_session")).toBe(true);
    expect(forcesSessionMode("xor_session")).toBe(true);
  });

  it("php_stream 走 include 流执行，没有可注入处理器的 eval 通道", () => {
    expect(supportsSessionMode("php_stream")).toBe(false);
    expect(forcesSessionMode("php_stream")).toBe(false);
  });

  it("其余编码器支持 session", () => {
    for (const id of ["base64", "xor_base64", "des", "char", "php_obfuscate", "xor_body"]) {
      expect(supportsSessionMode(id)).toBe(true);
    }
  });
});

describe("parseProtocolParams（容错解析）", () => {
  it("空值 / 非法 JSON / 非对象 → 空结果，不抛异常", () => {
    expect(parseProtocolParams(null)).toEqual({});
    expect(parseProtocolParams(undefined)).toEqual({});
    expect(parseProtocolParams("")).toEqual({});
    expect(parseProtocolParams("{不是 JSON")).toEqual({});
    expect(parseProtocolParams("123")).toEqual({});
    expect(parseProtocolParams("null")).toEqual({});
  });

  it("解析 encoder / salt / session", () => {
    expect(parseProtocolParams('{"encoder":"native","salt":"abc","session":true}')).toEqual({
      encoder: "native",
      salt: "abc",
      session: true,
    });
  });

  it("session 只认布尔真值，字符串 \"true\" 不算", () => {
    expect(parseProtocolParams('{"session":"true"}').session).toBe(false);
    expect(parseProtocolParams("{}").session).toBe(false);
  });

  it("transport 逐字段校验类型，类型不符的字段被丢弃", () => {
    const parsed = parseProtocolParams(
      JSON.stringify({
        encoder: "native",
        transport: {
          param: "sess",
          header: 42,
          pathSuffix: "?v=1",
          padding: "8",
          extraHeaders: { "X-A": "1" },
        },
      }),
    );
    expect(parsed.transport).toEqual({
      param: "sess",
      pathSuffix: "?v=1",
      extraHeaders: { "X-A": "1" },
    });
  });

  it("transport 非对象时视为未配置", () => {
    expect(parseProtocolParams('{"encoder":"native","transport":"x"}').transport).toBeUndefined();
  });
});

describe("buildProtocolParams（生成）", () => {
  it("默认值不写入，保持配置干净", () => {
    expect(
      buildProtocolParams("native", "", false, { param: "formData", header: "X-Debug-Key" }),
    ).toBe('{"encoder":"native"}');
  });

  it("盐去空白后写入；session 只在支持时写入", () => {
    expect(JSON.parse(buildProtocolParams("native", "  s1  ", false))).toEqual({
      encoder: "native",
      salt: "s1",
    });
    // NATIVE 不支持 session，勾了也不写
    expect(JSON.parse(buildProtocolParams("native", "", true))).toEqual({ encoder: "native" });
    // xor_session 支持
    expect(JSON.parse(buildProtocolParams("xor_session", "", true))).toEqual({
      encoder: "xor_session",
      session: true,
    });
  });

  it("参数名 / 头名只对 NATIVE 生效（只有 NATIVE 把它们烘焙进 stub）", () => {
    const native = JSON.parse(
      buildProtocolParams("native", "", false, { param: "sess", header: "X-Token" }),
    );
    expect(native.transport).toEqual({ param: "sess", header: "X-Token" });

    const legacy = JSON.parse(
      buildProtocolParams("base64", "", false, { param: "sess", header: "X-Token" }),
    );
    expect(legacy.transport).toBeUndefined();
  });

  it("查询串 / 填充对所有编码器生效", () => {
    const raw = buildProtocolParams("base64", "", false, { pathSuffix: "?v=2", padding: 16 });
    expect(JSON.parse(raw).transport).toEqual({ pathSuffix: "?v=2", padding: 16 });
  });

  it("额外请求头去空白、丢空名空值", () => {
    const raw = buildProtocolParams("native", "", false, {
      extraHeaders: { " X-A ": " 1 ", "": "x", "X-B": "" },
    });
    expect(JSON.parse(raw).transport.extraHeaders).toEqual({ "X-A": " 1 " });
  });

  it("往返：build → parse 保真", () => {
    const raw = buildProtocolParams("native", "salt", false, {
      param: "sess",
      pathSuffix: "?v=1",
      padding: 8,
      extraHeaders: { "X-A": "1" },
    });
    const parsed = parseProtocolParams(raw);
    expect(parsed.encoder).toBe("native");
    expect(parsed.salt).toBe("salt");
    expect(parsed.transport).toEqual({
      param: "sess",
      pathSuffix: "?v=1",
      padding: 8,
      extraHeaders: { "X-A": "1" },
    });
  });
});

describe("额外请求头文本 ↔ 对象", () => {
  it("每行 `Name: Value`，忽略空行与无冒号行", () => {
    expect(parseHeaderLines("X-A: 1\n\n坏行\nX-B:2")).toEqual({ "X-A": "1", "X-B": "2" });
  });

  it("值里含冒号时只按第一个冒号切分", () => {
    expect(parseHeaderLines("X-A: a:b:c")).toEqual({ "X-A": "a:b:c" });
  });

  it("CRLF 输入不会留下带 \\r 的名字或值", () => {
    const parsed = parseHeaderLines("X-A: 1\r\nX-B: 2\r\n");
    expect(parsed).toEqual({ "X-A": "1", "X-B": "2" });
    expect(Object.keys(parsed).some((name) => name.includes("\r"))).toBe(false);
  });

  it("冒号开头（空名字）被忽略", () => {
    expect(parseHeaderLines(": value")).toEqual({});
  });

  it("往返：headerLines → parseHeaderLines", () => {
    const headers = { "X-A": "1", "X-B": "2" };
    expect(parseHeaderLines(headerLines(headers))).toEqual(headers);
  });

  it("headerLines 对未配置返回空串", () => {
    expect(headerLines(undefined)).toBe("");
  });
});
