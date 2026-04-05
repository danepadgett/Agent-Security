import type { FC } from "react";
import type { SVGProps } from "react";
import type { AppView } from "../types";
import { ShieldIcon, ActivityIcon, GearIcon, BookOpenIcon, EyeIcon } from "./icons";

type Props = {
  activeView: AppView;
  onNavigate: (view: AppView) => void;
  incidentCount: number;
  breachCount?: number;
};

type IconProps = SVGProps<SVGSVGElement> & { size?: number };
const NAV: Array<{ view: AppView; Icon: FC<IconProps>; label: string }> = [
  { view: "incidents", Icon: ShieldIcon,    label: "Inbox" },
  { view: "health",    Icon: ActivityIcon,  label: "Health" },
  { view: "dark-web",  Icon: EyeIcon,       label: "Dark Web" },
  { view: "history",   Icon: BookOpenIcon,  label: "History" },
  { view: "settings",  Icon: GearIcon,      label: "Settings" },
];

export function Sidebar({ activeView, onNavigate, incidentCount, breachCount = 0 }: Props) {
  return (
    <nav className="sidebar" aria-label="Main navigation">
      <div className="sidebar-nav">
        {NAV.map(({ view, Icon, label }) => (
          <button
            key={view}
            className={`sidebar-btn ${activeView === view ? "sidebar-btn--active" : ""}`}
            onClick={() => onNavigate(view)}
            aria-label={label}
            title={label}
          >
            <Icon size={18} />
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
            {activeView === view && <span className="sidebar-active-pill" />}
          </button>
        ))}
      </div>

      <div className="sidebar-footer">
        <span className="sidebar-version">v0.1.0</span>
      </div>
    </nav>
  );
}
