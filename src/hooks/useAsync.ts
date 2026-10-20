import { useCallback, useEffect, useRef, useState } from "react";

import { errorText } from "../api";

/**
 * 数据加载 hook：`loading` / `error` / **请求序号** 三件事交给它，组件只留业务状态。
 *
 * 适用判据（不满足就别硬套）：加载器是「取一份数据 → 设**一个**主状态」。
 * 同时设置多个派生状态、或该状态还会在别处被改（例如会话列表还会被心跳刷新）的
 * 加载器，保持各自的本地写法更清楚。
 *
 * 请求序号解决的是**乱序响应**：先发的慢请求后到时，不得覆盖后发的快请求结果
 * （此前每个视图各写一遍 try/catch，都没有这一层）。
 *
 * `onError` 用于弹 toast 之类的副作用；`error` 供页面内联展示。
 */
export function useAsync<T>(
  load: () => Promise<T>,
  options: { onError?: (message: string) => void } = {},
): {
  data: T | null;
  setData: React.Dispatch<React.SetStateAction<T | null>>;
  loading: boolean;
  error: string;
  /** 供调用方上报**自己的**操作错误（例如发送请求失败），与加载错误共用同一条提示 */
  setError: React.Dispatch<React.SetStateAction<string>>;
  reload: () => Promise<void>;
} {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  /** 最近一次发起的请求序号：只有它的结果会被采纳 */
  const latest = useRef(0);
  // 加载器与回调放 ref：调用方**不必**为了「别重复触发」去 memo 加载器，
  // 也避免内联箭头函数让 effect 每次渲染都重跑（那是无限刷新）。
  // 需要「状态变化后重新加载」时，调用方在自己的 effect 里显式调 reload。
  const loadRef = useRef(load);
  loadRef.current = load;
  const onErrorRef = useRef(options.onError);
  onErrorRef.current = options.onError;

  const reload = useCallback(async () => {
    const seq = ++latest.current;
    setLoading(true);
    setError("");
    try {
      const value = await loadRef.current();
      if (seq !== latest.current) return; // 已被更新的请求取代：丢弃
      setData(value);
    } catch (cause) {
      if (seq !== latest.current) return; // 旧请求的失败不打扰当前状态
      const message = errorText(cause);
      setError(message);
      onErrorRef.current?.(message);
    } finally {
      if (seq === latest.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  return { data, setData, loading, error, setError, reload };
}
