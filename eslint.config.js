// ESLint 扁平配置：目标是**接住 react-hooks 类缺陷**，而不是重排风格。
//
// 背景：仓库此前没有任何 lint（`package.json` 仅 tsc/vite），源码里 4 处
// `// eslint-disable-next-line react-hooks/exhaustive-deps` 是死注释，
// hook 依赖/闭包缺陷（终端轮询竞态、重复拉取等）从未被任何环节拦截。
//
// 规则强度：
//   - react-hooks/rules-of-hooks      → error（真正的 hook 用法错误，阻塞）
//   - react-hooks/exhaustive-deps     → warn（历史代码较多，先可见、不阻塞）
//   - @typescript-eslint/no-explicit-any / no-unused-vars → warn
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";

export default tseslint.config(
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      "target/**",
      "src-tauri/**",
      "src/generated/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      globals: { ...globals.browser },
    },
    plugins: { "react-hooks": reactHooks },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      // 允许 `catch {}` 形式的显式忽略（项目里大量使用）
      "no-empty": ["error", { allowEmptyCatch: true }],
    },
  },
  {
    files: ["scripts/**/*.mjs", "*.config.{js,ts}"],
    languageOptions: { globals: { ...globals.node } },
  },
);
