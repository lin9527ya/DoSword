import { beforeEach, describe, expect, it } from "vitest";
import { THEME_KEY, applyTheme, currentTheme } from "./theme";

describe("主题应用", () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
  });

  it("无存储时回落为明亮", () => {
    applyTheme();
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(currentTheme()).toBe("light");
  });

  it("读取 localStorage 中的 dark", () => {
    localStorage.setItem(THEME_KEY, "dark");
    applyTheme();
    expect(currentTheme()).toBe("dark");
  });

  it("非法取值回落为明亮（而不是原样写进 data-theme）", () => {
    localStorage.setItem(THEME_KEY, "紫色");
    applyTheme();
    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it("currentTheme 只认 html 上的 data-theme，不读存储", () => {
    localStorage.setItem(THEME_KEY, "dark");
    document.documentElement.dataset.theme = "light";
    expect(currentTheme()).toBe("light");
    document.documentElement.dataset.theme = "dark";
    expect(currentTheme()).toBe("dark");
  });
});
