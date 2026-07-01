"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { navigation } from "../lib/navigation";

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">AS</div>
          <h1>AgentShield</h1>
          <p>Kernel traces and Agent intent in one operations surface.</p>
        </div>
        <nav className="nav" aria-label="Main navigation">
          {navigation.map((item) => {
            const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
            return (
              <Link key={item.href} className={`nav-link${active ? " active" : ""}`} href={item.href}>
                <span>{item.label}</span>
                <span>{item.code}</span>
              </Link>
            );
          })}
        </nav>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}
