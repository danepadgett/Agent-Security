import { useEffect } from "react";
import type { Severity } from "../types";
import { XIcon } from "./icons";

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
    <div className={`toast toast--${toast.severity}`} role="alert">
      <div className="toast-body">
        <div className="toast-title">{toast.title}</div>
      </div>
      <button
        className="toast-dismiss"
        onClick={() => onDismiss(toast.id)}
        aria-label="Dismiss"
      >
        <XIcon size={12} />
      </button>
    </div>
  );
}
