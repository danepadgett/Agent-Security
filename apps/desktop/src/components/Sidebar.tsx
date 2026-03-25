import type { FC } from "react";
import type { SVGProps } from "react";
import type { AppView } from "../types";
import { ShieldIcon, ActivityIcon, GearIcon } from "./icons";

type Props = {
  activeView: AppView;
  onNavigate: (view: AppView) => void;
  incidentCount: number;
};

type IconProps = SVGProps<SVGSVGElement> & { size?: number };
const NAV: Array<{ view: AppView; Icon: FC<IconProps> }> = [
  { view: "incidents", Icon: ShieldIcon },
  { view: "health", Icon: ActivityIcon },
  { view: "settings", Icon: GearIcon },
];

export function Sidebar({ activeView, onNavigate, incidentCount }: Props) {
  return (
    <nav className="sidebar" aria-label="Main navigation">
      <div className="sidebar-nav">
        {NAV.map(({ view, Icon }) => (
          <button
            key={view}
            className={`sidebar-btn ${activeView === view ? "sidebar-btn--active" : ""}`}
            onClick={() => onNavigate(view)}
            aria-label={view}
            title={view.charAt(0).toUpperCase() + view.slice(1)}
          >
            <Icon size={18} />
            {view === "incidents" && incidentCount > 0 && (
              <span className="sidebar-badge" aria-label={`${incidentCount} active`}>
                {incidentCount > 99 ? "99+" : incidentCount}
              </span>
            )}
            {activeView === view && <span className="sidebar-active-pill" />}
          </button>
        ))}
      </div>

      <div className="sidebar-footer">
        <span className="sidebar-version">0.1</span>
      </div>
    </nav>
  );
}
