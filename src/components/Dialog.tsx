import type { ReactNode } from "react";

export function Dialog({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <div className="dialog-backdrop" onMouseDown={onClose}>
      <section className="dialog" onMouseDown={(event) => event.stopPropagation()}>
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
