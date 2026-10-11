import "./globals.css";
import Nav from "@/components/NavClient";
import type { Metadata } from "next";
import "./layout.css";

export const metadata: Metadata = {
  title: "Veylix - Cyber Threat Intelligence",
  description:
    "Explainable vulnerability prioritization, KEV prediction, and grounded threat intelligence",
};

const NAV = [
  { href: "/overview", label: "Overview" },
  { href: "/queue", label: "Remediation Queue" },
  { href: "/vulnerabilities", label: "Vulnerabilities" },
  { href: "/assets", label: "Assets" },
  { href: "/assistant", label: "AI Analyst" },
  { href: "/ml-evaluation", label: "ML Evaluation" },
  { href: "/settings", label: "Settings" },
];

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="dark">
      <body>
<Nav />
        <main className="main">{children}</main>
        <footer className="footer">Veylix 0.1.0 - Evidence-based security intelligence</footer>
      </body>
    </html>
  );
}
