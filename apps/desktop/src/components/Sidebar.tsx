import type { FC } from "react";
import type { SVGProps } from "react";
import type { AppView } from "../types";
import { ShieldIcon, HomeIcon, BellIcon, BookOpenIcon, EyeIcon, UserIcon, GearIcon } from "./icons";

type Props = {
  activeView: AppView;
  onNavigate: (view: AppView) => void;
  onOpenSettings: () => void;
  incidentCount: number;
  breachCount?: number;
};

type IconProps = SVGProps<SVGSVGElement> & { size?: number };
const NAV: Array<{ view: AppView; Icon: FC<IconProps>; label: string }> = [
  { view: "dashboard",  Icon: HomeIcon,     label: "Dashboard" },
  { view: "incidents",  Icon: BellIcon,     label: "Traces" },
  { view: "dark-web",   Icon: EyeIcon,      label: "Dark Web" },
  { view: "history",    Icon: BookOpenIcon, label: "History" },
  { view: "account",    Icon: UserIcon,     label: "Account" },
];

export function Sidebar({ activeView, onNavigate, onOpenSettings, incidentCount, breachCount = 0 }: Props) {
  return (
    <nav className="sidebar" aria-label="Main navigation">
      <div className="sidebar-logo" aria-hidden="true">
        <ShieldIcon size={22} />
      </div>

      <div className="sidebar-nav">
        {NAV.map(({ view, Icon, label }) => (
          <button
            key={view}
            className={`sidebar-btn ${activeView === view ? "sidebar-btn--active" : ""}`}
            onClick={() => onNavigate(view)}
            aria-label={label}
            aria-current={activeView === view ? "page" : undefined}
          >
            <Icon size={18} />
            <span className="sidebar-btn-label">{label}</span>
            {view === "incidents" && incidentCount > 0 && (
              <span className="sidebar-badge" aria-label={`${incidentCount} unread`}>
                {incidentCount > 99 ? "99+" : incidentCount}
              </span>
            )}
            {view === "dark-web" && breachCount > 0 && (
              <span className="sidebar-badge sidebar-badge--breach" aria-label={`${breachCount} breaches`}>
                {breachCount > 99 ? "99+" : breachCount}
              </span>
            )}
          </button>
        ))}
      </div>

      <div className="sidebar-footer">
        <button
          className="sidebar-gear-btn"
          onClick={onOpenSettings}
          aria-label="Settings"
        >
          <GearIcon size={16} />
          <span className="sidebar-btn-label">Settings</span>
        </button>
        <span className="sidebar-version">v0.1.0</span>
      </div>
    </nav>
  );
}
