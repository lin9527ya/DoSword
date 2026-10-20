import { useCallback, useEffect, useState } from "react";
import { Copy, LoaderCircle, Network, Plus, Trash2 } from "lucide-react";
import { api, errorText } from "../api";
import type { ProxyChainInfo, ShellSummary } from "../api";
import { useToast } from "../components/Toast";

type HopDraft = {
  shellId: string;
  host: string;
  port: number;
  username: string;
  password: string;
};

export function ProxyChainView() {
  const toast = useToast();
  const [shells, setShells] = useState<ShellSummary[]>([]);
  const [hops, setHops] = useState<HopDraft[]>([]);
  const [localPort, setLocalPort] = useState(0);
  const [targetHost, setTargetHost] = useState("");
  const [targetPort, setTargetPort] = useState(0);
  const [chains, setChains] = useState<ProxyChainInfo[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      setChains(await api.proxyChainList());
    } catch (cause) {
      setError(errorText(cause));
    }
  }, []);

  useEffect(() => {
    // Shell 选择器只要精简列表（无密码），不再拉整个看板
    void api
      .listShellSummaries()
      .then((shellList) => {
        setShells(shellList);
        setHops((current) =>
          current.length > 0
            ? current
            : [
                {
                  shellId: shellList[0]?.id ?? "",
                  host: hostOf(shellList[0]?.endpoint ?? ""),
                  port: 1080,
                  username: "",
                  password: "",
                },
              ],
        );
      })
      .catch((cause) => setError(errorText(cause)));
    void refresh();
  }, [refresh]);

  function hostOf(endpoint: string): string {
    try {
      return new URL(endpoint).hostname;
    } catch {
      return "";
    }
  }

  function addHop() {
    setHops((current) => [
      ...current,
      { shellId: "", host: "", port: 1080, username: "", password: "" },
    ]);
  }

  function updateHop(index: number, patch: Partial<HopDraft>) {
    setHops((current) =>
      current.map((hop, i) => (i === index ? { ...hop, ...patch } : hop)),
    );
  }

  function removeHop(index: number) {
    setHops((current) => current.filter((_, i) => i !== index));
  }

  async function start() {
    if (hops.length === 0) {
      toast.warning("请至少配置一跳");
      return;
    }
    const invalid = hops.find(
      (hop) => !hop.shellId || !hop.host.trim() || !hop.port,
    );
    if (invalid) {
      toast.warning("每一跳都需要选择 Shell 并填写地址与端口");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const result = await api.proxyChainStart({
        hops: hops.map((hop) => ({
          shellId: hop.shellId,
          host: hop.host.trim(),
          port: hop.port,
          username: hop.username || undefined,
          password: hop.password || undefined,
        })),
        localPort,
        targetHost: targetHost.trim() || null,
        targetPort: targetPort || null,
      });
      toast.success(
        `本地 SOCKS5：${result.localAddr}（${result.hops ?? hops.length} 跳）`,
        "代理链已启动",
      );
      await refresh();
    } catch (cause) {
      const message = errorText(cause);
      setError(message);
      toast.error(message, "启动失败");
    } finally {
      setBusy(false);
    }
  }

  async function stop(chainId: string) {
    try {
      await api.proxyChainStop(chainId);
      await refresh();
      toast.info("代理链已关闭");
    } catch (cause) {
      toast.error(errorText(cause), "关闭失败");
    }
  }

  function copy(value: string) {
    void navigator.clipboard.writeText(value);
    toast.info("已复制");
  }

  return (
    <div className="detail-panel" style={{ display: "grid", gap: 14 }}>
      <div className="panel" style={{ padding: 14 }}>
        <div className="panel-heading">
          <div className="panel-heading-title">
            <Network size={15} /> 多跳代理链
          </div>
        </div>
        <p className="form-note" style={{ marginTop: 6 }}>
          每一跳都必须是已启动的 SOCKS5（先在目标上运行「Socks 代理」插件）。
          链路从第一跳开始逐级 CONNECT，最后一跳连到目标。每一跳都会做授权复查。
        </p>
      </div>

      {error && <p className="form-note error">{error}</p>}

      <div className="panel" style={{ padding: 12, display: "grid", gap: 10 }}>
        <strong style={{ fontSize: 12.5 }}>跳点（按顺序：操作机 → 目标）</strong>
        {hops.map((hop, index) => (
          <div
            key={index}
            style={{
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-md)",
              padding: "8px 10px",
              display: "grid",
              gap: 6,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <strong style={{ fontSize: 12 }}>第 {index + 1} 跳</strong>
              <button
                className="button compact secondary"
                onClick={() => removeHop(index)}
                title="删除该跳"
              >
                <Trash2 size={12} />
              </button>
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              <label style={{ flex: "1 1 220px" }}>
                对应 Shell
                <select
                  value={hop.shellId}
                  onChange={(event) => {
                    const shell = shells.find((item) => item.id === event.target.value);
                    updateHop(index, {
                      shellId: event.target.value,
                      host: hostOf(shell?.endpoint ?? ""),
                    });
                  }}
                >
                  <option value="">请选择</option>
                  {shells.map((shell) => (
                    <option key={shell.id} value={shell.id}>
                      {shell.name}
                    </option>
                  ))}
                </select>
              </label>
              <label style={{ flex: "1 1 180px" }}>
                地址（从前一跳看）
                <input
                  value={hop.host}
                  onChange={(event) => updateHop(index, { host: event.target.value })}
                  placeholder="10.0.0.5"
                />
              </label>
              <label style={{ flex: "0 0 100px" }}>
                端口
                <input
                  type="number"
                  value={hop.port}
                  onChange={(event) =>
                    updateHop(index, { port: Number(event.target.value) || 0 })
                  }
                />
              </label>
              <label style={{ flex: "1 1 130px" }}>
                用户名（可选）
                <input
                  value={hop.username}
                  onChange={(event) => updateHop(index, { username: event.target.value })}
                />
              </label>
              <label style={{ flex: "1 1 130px" }}>
                密码（可选）
                <input
                  type="password"
                  value={hop.password}
                  onChange={(event) => updateHop(index, { password: event.target.value })}
                />
              </label>
            </div>
          </div>
        ))}
        <div>
          <button className="button compact secondary" onClick={addHop}>
            <Plus size={12} /> 增加一跳
          </button>
        </div>

        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <label style={{ flex: "0 0 140px" }}>
            本地端口（0=随机）
            <input
              type="number"
              value={localPort}
              onChange={(event) => setLocalPort(Number(event.target.value) || 0)}
            />
          </label>
          <label style={{ flex: "1 1 180px" }}>
            固定目标主机（可选）
            <input
              value={targetHost}
              onChange={(event) => setTargetHost(event.target.value)}
              placeholder="留空 = 动态 SOCKS5"
            />
          </label>
          <label style={{ flex: "0 0 110px" }}>
            固定目标端口
            <input
              type="number"
              value={targetPort}
              onChange={(event) => setTargetPort(Number(event.target.value) || 0)}
            />
          </label>
        </div>
        <div className="form-note">
          留空固定目标时为动态 SOCKS5：把「设置 → 代理」指向返回的地址即可让应用流量走链。
          固定目标时，本地端口直接把流量转发到该目标（类似 ssh -L）。
        </div>
        <div>
          <button className="button primary" onClick={() => void start()} disabled={busy}>
            {busy ? <LoaderCircle className="spin" size={14} /> : <Network size={14} />}
            {busy ? "启动中…" : "启动代理链"}
          </button>
        </div>
      </div>

      <div className="panel" style={{ padding: 12 }}>
        <strong style={{ fontSize: 12.5 }}>运行中的链路（{chains.length}）</strong>
        {chains.length === 0 ? (
          <div className="form-note" style={{ marginTop: 6 }}>
            暂无运行中的代理链。
          </div>
        ) : (
          <div style={{ display: "grid", gap: 6, marginTop: 6 }}>
            {chains.map((chain) => (
              <div
                key={chain.chainId}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "6px 9px",
                }}
              >
                <code className="mono" style={{ fontSize: 11.5 }}>
                  {chain.localAddr}
                </code>
                <button
                  className="button compact secondary"
                  onClick={() => copy(chain.localAddr)}
                >
                  <Copy size={12} />
                </button>
                <button
                  className="button compact secondary"
                  style={{ marginLeft: "auto" }}
                  onClick={() => void stop(chain.chainId)}
                >
                  关闭
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
