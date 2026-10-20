import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// 前端单测配置。与 `vite.config.ts` **分开**：jsdom 环境与测试专用设置不该进生产构建。
//
// - environment: jsdom —— 组件与 theme 都依赖 DOM（document / localStorage）
// - setupFiles   —— 只做一件事：每个用例后清理已渲染的 DOM。@testing-library 的自动
//   清理依赖全局 afterEach，而这里没开 `globals`（保持「显式 import」的风格）
// - include      —— 测试与源码同目录（`src/**/*.test.ts(x)`），随功能一起演进
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["./src/test-setup.ts"],
    restoreMocks: true,
  },
});
