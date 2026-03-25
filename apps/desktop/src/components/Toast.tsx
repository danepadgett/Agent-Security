import { useEffect } from "react";
import type { Severity } from "../types";
import { SevIcon } from "./icons";

export type ToastItem = {
  id: string;
  severity: Severity;
  title: string;
};

type Props = {
  toasts: ToastItem[];
  onDismiss: (id: string) => void;
};

const TOAST_TTL_MS = 4000;

export function ToastStack({ toasts, onDismiss }: Props) {
  return (
    <div className="toast-stack" aria-live="polite">
      {toasts.map((t) => (
        <ToastCard key={t.id} toast={t} onDismiss={onDismiss} />
      ))}
    </div>
  );
}

function ToastCard({ toast, onDismiss }: { toast: ToastItem; onDismiss: (id: string) => void }) {
  useEffect(() => {
    const timer = setTimeout(() => onDismiss(toast.id), TOAST_TTL_MS);
    return () => clearTimeout(timer);
  }, [toast.id, onDismiss]);

  return (
    <div
      className="toast-card"
      data-sev={toast.severity}
      role="alert"
    >
      <span className="toast-icon">
        <SevIcon severity={toast.severity} size={14} />
      </span>
      <div className="toast-body">
        <span className="toast-label">New incident</span>
        <span className="toast-title">{toast.title}</span>
      </div>
      <button
        className="toast-close"
        onClick={() => onDismiss(toast.id)}
        aria-label="Dismiss"
      >
        ✕
      </button>
    </div>
  );
}
