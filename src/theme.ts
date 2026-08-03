export const THEME_KEY = "dosword:theme";

/** 应用主题：读取 localStorage（缺省明亮），写入 <html data-theme>。 */
export function applyTheme() {
  let theme: string;
  try {
    theme = localStorage.getItem(THEME_KEY) ?? "light";
  } catch {
    theme = "light";
  }
  if (theme !== "dark" && theme !== "light") theme = "light";
  document.documentElement.dataset.theme = theme;
}

export function currentTheme(): "light" | "dark" {
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}
