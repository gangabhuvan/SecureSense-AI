import { Outlet, Link } from "react-router-dom";

export default function MainLayout() {
  const menuItems = [
    { name: "Dashboard", path: "/" },
    { name: "Upload", path: "/upload" },
    { name: "Analysis", path: "/analysis" },
    { name: "Passport", path: "/passport" },
    { name: "Trust Graph", path: "/trust-graph" },
    { name: "Evidence Ledger", path: "/ledger" },
    { name: "Reports", path: "/reports" },
    { name: "Settings", path: "/settings" },
  ];

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <aside
        style={{
          width: "250px",
          background: "#0F172A",
          color: "white",
          padding: "20px",
        }}
      >
        <h2>SecureSense AI</h2>

        <nav style={{ marginTop: "30px" }}>
          {menuItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              style={{
                display: "block",
                color: "white",
                textDecoration: "none",
                padding: "12px 0",
              }}
            >
              {item.name}
            </Link>
          ))}
        </nav>
      </aside>

      <main style={{ flex: 1, padding: "30px" }}>
        <Outlet />
      </main>
    </div>
  );
}