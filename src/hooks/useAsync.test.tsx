import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { useAsync } from "./useAsync";

/** 可控的 promise：手动决定何时、以什么结果结束 */
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("useAsync", () => {
  it("成功后写入 data 并结束 loading", async () => {
    const { result } = renderHook(() => useAsync(async () => 42));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.data).toBe(42);
    expect(result.current.error).toBe("");
  });

  it("失败时写入 error 并调用 onError，data 保持原值", async () => {
    const onError = vi.fn();
    let shouldFail = false;
    const { result } = renderHook(() =>
      useAsync(
        async () => {
          if (shouldFail) throw new Error("boom");
          return "ok";
        },
        { onError },
      ),
    );
    await waitFor(() => expect(result.current.data).toBe("ok"));

    shouldFail = true;
    await act(async () => {
      await result.current.reload();
    });
    expect(result.current.error).toContain("boom");
    expect(onError).toHaveBeenCalledTimes(1);
    expect(result.current.data).toBe("ok"); // 失败不清空已有数据
  });

  it("乱序响应：先发的慢请求后到时不得覆盖后发的快请求", async () => {
    const slow = deferred<string>();
    const fast = deferred<string>();
    let call = 0;
    const { result } = renderHook(() =>
      useAsync(() => {
        call += 1;
        return call === 1 ? slow.promise : fast.promise;
      }),
    );

    // 第二次请求（快）先返回
    await act(async () => {
      void result.current.reload();
    });
    await act(async () => {
      fast.resolve("新结果");
    });
    await waitFor(() => expect(result.current.data).toBe("新结果"));

    // 第一次请求（慢）随后才返回：必须被丢弃
    await act(async () => {
      slow.resolve("旧结果");
    });
    expect(result.current.data).toBe("新结果");
    expect(result.current.loading).toBe(false);
  });

  it("旧请求失败不覆盖当前状态，也不触发 onError", async () => {
    const slow = deferred<string>();
    const fast = deferred<string>();
    let call = 0;
    const onError = vi.fn();
    const { result } = renderHook(() =>
      useAsync(
        () => {
          call += 1;
          return call === 1 ? slow.promise : fast.promise;
        },
        { onError },
      ),
    );

    await act(async () => {
      void result.current.reload();
    });
    await act(async () => {
      fast.resolve("新结果");
    });
    await waitFor(() => expect(result.current.data).toBe("新结果"));

    await act(async () => {
      slow.reject(new Error("旧请求超时"));
    });
    expect(result.current.error).toBe("");
    expect(onError).not.toHaveBeenCalled();
    expect(result.current.data).toBe("新结果");
  });
});
