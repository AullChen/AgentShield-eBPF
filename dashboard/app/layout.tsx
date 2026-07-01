import type { Metadata } from "next";
import "./globals.css";
import { Shell } from "../components/shell";

export const metadata: Metadata = {
  title: "AgentShield Dashboard",
  description: "Runtime security dashboard for AgentShield-eBPF",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}
