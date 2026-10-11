"use client";

const LINKS = [
  { href: "/overview", label: "Overview" },
  { href: "/queue", label: "Remediation Queue" },
  { href: "/vulnerabilities", label: "Vulnerabilities" },
  { href: "/assets", label: "Assets" },
  { href: "/assistant", label: "AI Analyst" },
  { href: "/ml-evaluation", label: "ML Evaluation" },
  { href: "/settings", label: "Settings" },
];

export default function Nav() {
  return (
    <nav className="nav">
      <div className="nav-inner">
        <a href="/overview" className="brand">
          <span className="brand-mark">Veylix</span>
        </a>
        <div className="nav-links">
          {LINKS.map((item) => (
            <a key={item.href} href={item.href} className="nav-link">
              {item.label}
            </a>
          ))}
        </div>
        <div className="nav-user">
          <button
            className="btn-ghost"
            onClick={() => {
              if (typeof window !== "undefined") {
                localStorage.removeItem("veylix_token");
                window.location.href = "/login";
              }
            }}
          >
            Sign out
          </button>
        </div>
      </div>
    </nav>
  );
}
