import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// 每个用例后卸载已渲染的组件：未开 `globals` 时 @testing-library 不会自动注册清理，
// 否则上一个用例的 DOM 会残留、`getByText` 可能命中两个节点。
afterEach(cleanup);
