import { Component, useEffect, useRef, useState, type ReactNode } from "react";
import { AlertCircle, Check, ChevronUp, RefreshCw } from "lucide-react";

export function Metric({
  label,
  value,
  detail,
  accent = false,
  icon,
  onClick,
}: {
  label: string;
  value: number | string;
  detail: string;
  accent?: boolean;
  icon?: ReactNode;
  onClick?: () => void;
}) {
  return (
    <article
      className={`metric ${accent ? "accent" : ""} ${onClick ? "clickable" : ""}`}
      onClick={onClick}
      style={onClick ? { cursor: "pointer" } : undefined}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <span>{label}</span>
        {icon && <span style={{ color: "var(--text-faint)", opacity: 0.8 }}>{icon}</span>}
      </div>
      <strong>{typeof value === "number" && value >= 0 ? String(value).padStart(2, "0") : value}</strong>
      <small>{detail}</small>
    </article>
  );
}

export function Empty({
  icon,
  title,
  detail,
  action,
}: {
  icon: ReactNode;
  title: string;
  detail?: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state fade-in">
      {icon}
      <strong>{title}</strong>
      {detail && <p>{detail}</p>}
      {action && <div style={{ marginTop: 8 }}>{action}</div>}
    </div>
  );
}

export function ErrorBanner({ message }: { message: string }) {
  if (!message) return null;
  return (
    <div className="error-banner">
      <AlertCircle size={16} style={{ flexShrink: 0, marginTop: 1 }} />
      <span>{message}</span>
    </div>
  );
}

export function Panel({
  title,
  eyebrow,
  actions,
  children,
  className,
  style,
}: {
  title: string;
  eyebrow: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  style?: React.CSSProperties;
}) {
  return (
    <section className={`panel ${className ?? ""}`} style={style}>
      <div className="panel-heading">
        <div className="panel-heading-title">
          <p className="eyebrow">{eyebrow}</p>
          <h2>{title}</h2>
        </div>
        {actions && <div className="panel-actions">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

/** 错误边界：任一子视图渲染异常时显示优雅提示而非白屏。 */
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
        <div className="panel detail-panel" style={{ padding: 24 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, color: "var(--err)" }}>
            <AlertCircle size={20} />
            <h2 style={{ color: "var(--err)" }}>视图渲染异常</h2>
          </div>
          <pre className="plugin-result error" style={{ margin: "16px 0" }}>
            {String(this.state.error.stack || this.state.error.message)}
          </pre>
          <div>
            <button
              className="button primary"
              onClick={() => this.setState({ error: null })}
            >
              <RefreshCw size={14} />
              重试恢复
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

/** 向上展开的每页条数选择器，防止全屏或靠底时下拉被视口裁切 */
export function UpwardPageSizeSelect({
  value,
  onChange,
  options = [50, 100, 200, 500, 0],
  unit = "条",
}: {
  value: number;
  onChange: (val: number) => void;
  options?: number[];
  unit?: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handleClickOutside = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    window.addEventListener("mousedown", handleClickOutside);
    return () => window.removeEventListener("mousedown", handleClickOutside);
  }, [open]);

  const label = value === 0 ? "全部显示" : `${value} ${unit} / 页`;

  return (
    <div className="upward-select-wrap" ref={ref}>
      <button
        type="button"
        className="upward-select-trigger"
        onClick={() => setOpen((o) => !o)}
        title="选择每页显示条数（向上展开）"
      >
        <span>{label}</span>
        <ChevronUp
          size={12}
          style={{
            transform: open ? "rotate(180deg)" : "none",
            transition: "transform 0.15s ease",
          }}
        />
      </button>

      {open && (
        <div className="upward-select-menu">
          {options.map((opt) => {
            const optLabel = opt === 0 ? "全部显示" : `${opt} ${unit} / 页`;
            const isAct = opt === value;
            return (
              <button
                key={opt}
                type="button"
                className={`upward-select-option ${isAct ? "active" : ""}`}
                onClick={() => {
                  onChange(opt);
                  setOpen(false);
                }}
              >
                <span>{optLabel}</span>
                {isAct && <Check size={12} />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
