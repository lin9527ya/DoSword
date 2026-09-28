import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { CheckCircle2, AlertCircle, Info, AlertTriangle, X } from "lucide-react";

export type ToastType = "success" | "error" | "info" | "warning";

export type ToastItem = {
  id: string;
  type: ToastType;
  title?: string;
  message: string;
  duration?: number;
};

type ToastContextType = {
  toast: {
    success: (message: string, title?: string, duration?: number) => void;
    error: (message: string, title?: string, duration?: number) => void;
    info: (message: string, title?: string, duration?: number) => void;
    warning: (message: string, title?: string, duration?: number) => void;
    show: (item: Omit<ToastItem, "id">) => void;
    dismiss: (id: string) => void;
  };
};

const ToastContext = createContext<ToastContextType | null>(null);

let toastSeq = 0;
const lastToastTimes = new Map<string, number>();

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const show = useCallback(
    ({ type, title, message, duration = 4000 }: Omit<ToastItem, "id">) => {
      // 防抖去重：同一消息在 1.5 秒内只显示一次，防止死循环或批量报错刷屏
      const key = `${type}:${title ?? ""}:${message}`;
      const now = Date.now();
      const last = lastToastTimes.get(key) ?? 0;
      if (now - last < 1500) {
        return;
      }
      lastToastTimes.set(key, now);

      const id = `toast-${++toastSeq}`;
      const item: ToastItem = { id, type, title, message, duration };

      // 限制屏幕最多同时展示 4 条，超出自动移出最早的提示
      setToasts((prev) => {
        const next = [...prev, item];
        if (next.length > 4) {
          return next.slice(next.length - 4);
        }
        return next;
      });

      if (duration > 0) {
        setTimeout(() => {
          dismiss(id);
        }, duration);
      }
    },
    [dismiss],
  );

  const toast = useMemo(
    () => ({
      success: (message: string, title?: string, duration?: number) =>
        show({ type: "success", title, message, duration }),
      error: (message: string, title?: string, duration?: number) =>
        show({ type: "error", title, message, duration }),
      info: (message: string, title?: string, duration?: number) =>
        show({ type: "info", title, message, duration }),
      warning: (message: string, title?: string, duration?: number) =>
        show({ type: "warning", title, message, duration }),
      show,
      dismiss,
    }),
    [show, dismiss],
  );

  const getIcon = (type: ToastType) => {
    switch (type) {
      case "success":
        return <CheckCircle2 size={18} className="toast-icon ok" />;
      case "error":
        return <AlertCircle size={18} className="toast-icon err" />;
      case "warning":
        return <AlertTriangle size={18} className="toast-icon warn" />;
      case "info":
      default:
        return <Info size={18} className="toast-icon info" />;
    }
  };

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <div className="toast-container" aria-live="polite">
        {toasts.map((item) => (
          <div key={item.id} className={`toast-item toast-${item.type}`}>
            {getIcon(item.type)}
            <div className="toast-content">
              {item.title && <strong className="toast-title">{item.title}</strong>}
              <span className="toast-message">{item.message}</span>
            </div>
            <button
              className="toast-close"
              onClick={() => dismiss(item.id)}
              aria-label="关闭提示"
            >
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    return {
      success: (msg: string) => console.log("[SUCCESS]", msg),
      error: (msg: string) => console.error("[ERROR]", msg),
      info: (msg: string) => console.info("[INFO]", msg),
      warning: (msg: string) => console.warn("[WARN]", msg),
      show: (item: Omit<ToastItem, "id">) => console.log(item),
      dismiss: () => {},
    };
  }
  return context.toast;
}
