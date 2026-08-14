import { Component, type ReactNode } from "react";

export function Metric({
  label,
  value,
  detail,
  accent = false,
}: {
  label: string;
  value: number;
  detail: string;
  accent?: boolean;
}) {
  return (
    <article className={`metric ${accent ? "accent" : ""}`}>
      <span>{label}</span>
      <strong>{value > 0 ? String(value).padStart(2, "0") : detail}</strong>
      <small>{value > 0 ? detail : "最近连接时间"}</small>
    </article>
  );
}

export function Empty({
  icon,
  title,
  detail,
}: {
  icon: ReactNode;
  title: string;
  detail?: string;
}) {
  return (
    <div className="empty-state">
      {icon}
      <strong>{title}</strong>
      {detail && <p>{detail}</p>}
    </div>
  );
}

export function ErrorBanner({ message }: { message: string }) {
  return <div className="error-banner">{message}</div>;
}

export function Panel({
  title,
  eyebrow,
  actions,
  children,
  className,
}: {
  title: string;
  eyebrow: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className ?? ""}`}>
      <div className="panel-heading">
        <div>
          <p className="eyebrow">{eyebrow}</p>
          <h2>{title}</h2>
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}

/** 错误边界：任一子视图渲染异常时显示提示而非白屏。 */
export class ErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null }
> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error) {
    console.error("渲染异常：", error);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="panel detail-panel">
          <p className="eyebrow">渲染异常</p>
          <pre className="plugin-result error">{String(this.state.error)}</pre>
          <button className="button secondary" onClick={() => this.setState({ error: null })}>
            重试
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
