import { Empty } from "../components/common";

/** 规划中模块的占位视图（文件传输/请求调试/数据库）。 */
export function PlaceholderView({ title, eyebrow }: { title: string; eyebrow: string }) {
  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">{eyebrow}</p>
          <h1>{title}</h1>
        </div>
      </header>
      <div className="panel placeholder-panel">
        <Empty
          icon={<span className="placeholder-emoji">🚧</span>}
          title="该模块规划于 V2.0"
          detail="当前里程碑聚焦 Shell 管理、文件管理与命令终端。敬请期待。"
        />
      </div>
    </>
  );
}
