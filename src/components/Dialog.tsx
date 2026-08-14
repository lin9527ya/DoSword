import { useEffect, useRef, type ReactNode } from "react";

export function Dialog({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const dialogRef = useRef<HTMLElement>(null);

  // Escape 关闭 + 焦点陷阱（Tab 循环）
  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.stopPropagation();
        onClose();
        return;
      }
      if (event.key === "Tab") {
        const focusables = dialog.querySelectorAll<HTMLElement>(
          'button, input, select, textarea, a[href], [tabindex]:not([tabindex="-1"])',
        );
        if (focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener("keydown", onKeyDown, true);
    // 打开时聚焦首个可聚焦元素
    const focusables = dialog.querySelectorAll<HTMLElement>("button, input, select, textarea");
    if (focusables.length > 0) focusables[0].focus();
    return () => window.removeEventListener("keydown", onKeyDown, true);
  }, [onClose]);

  return (
    <div className="dialog-backdrop" onMouseDown={onClose} role="dialog" aria-modal="true" aria-label={title}>
      <section
        className="dialog"
        ref={dialogRef}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="dialog-title">
          <h2>{title}</h2>
          <button className="icon-button" onClick={onClose}>
            ×
          </button>
        </div>
        {children}
      </section>
    </div>
  );
}
