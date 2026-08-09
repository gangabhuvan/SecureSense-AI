import {
  useEffect,
  useState,
} from "react";

import {
  NavLink,
  Outlet,
  useLocation,
  useNavigate,
  useParams,
} from "react-router-dom";

import { useAuth } from "../context/AuthContext";

import {
  BarChart3,
  FileBadge2,
  FileSearch,
  LayoutDashboard,
  Menu,
  Network,
  Settings2,
  ShieldCheck,
  Upload,
  X,
  Database,
} from "lucide-react";

const NAV_ITEMS = [
  {
    label: "Dashboard",
    path: "/dashboard",
    icon: LayoutDashboard,
  },
  {
    label: "Upload",
    path: "/upload",
    icon: Upload,
  },
  {
    label: "Analysis",
    path: "/analysis",
    contextual: true,
    icon: FileSearch,
  },
  {
    label: "Passport",
    path: "/passport",
    contextual: true,
    icon: FileBadge2,
  },
  {
    label: "Trust Graph",
    path: "/trust-graph",
    contextual: true,
    icon: Network,
  },
  {
    label: "Evidence Ledger",
    path: "/ledger",
    contextual: true,
    icon: Database,
  },
  {
    label: "Reports",
    path: "/reports",
    contextual: true,
    icon: BarChart3,
  },
  {
    label: "Settings",
    path: "/settings",
    icon: Settings2,
  },
];

function getCommunicationId(pathname) {
  const match = pathname.match(
    /^\/(?:analysis|passport|trust-graph|ledger)\/([^/]+)/
  );

  return match
    ? decodeURIComponent(match[1])
    : null;
}

function getCurrentPage(pathname) {
  if (pathname === "/dashboard") {
    return "Dashboard";
  }

  const item = NAV_ITEMS.find(
    (navItem) =>
      navItem.path !== "/" &&
      (pathname === navItem.path ||
        pathname.startsWith(
          `${navItem.path}/`
        ))
  );

  return item?.label || "SecureSense AI";
}

export default function MainLayout() {
  const location = useLocation();
  const params = useParams();

  const navigate = useNavigate();

  const {
    user,
    logout,
    loading,
    isAuthenticated,
  } = useAuth();

  const [
    mobileNavigationOpen,
    setMobileNavigationOpen,
  ] = useState(false);

  const communicationId =
    params.communicationId ||
    getCommunicationId(
      location.pathname
    );

  const currentPage =
    getCurrentPage(
      location.pathname
    );

  const resolvePath = (item) => {
    if (
      item.contextual &&
      communicationId
    ) {
      return `${item.path}/${encodeURIComponent(
        communicationId
      )}`;
    }

    return item.path;
  };

  const isItemActive = (item) => {
    if (item.path === "/") {
      return location.pathname === "/dashboard";
    }

    return (
      location.pathname === item.path ||
      location.pathname.startsWith(
        `${item.path}/`
      )
    );
  };

  // Close mobile navigation whenever
  // the user changes routes.
  useEffect(() => {
    setMobileNavigationOpen(false);
  }, [location.pathname]);

  // Prevent the page behind the drawer
  // from scrolling while mobile navigation
  // is open.
  useEffect(() => {
    if (!mobileNavigationOpen) {
      return undefined;
    }

    const previousOverflow =
      document.body.style.overflow;

    document.body.style.overflow =
      "hidden";

    return () => {
      document.body.style.overflow =
        previousOverflow;
    };
  }, [mobileNavigationOpen]);

  // Allow Escape to close the mobile drawer.
  useEffect(() => {
    const handleKeyDown = (event) => {
      if (
        event.key === "Escape" &&
        mobileNavigationOpen
      ) {
        setMobileNavigationOpen(false);
      }
    };

    window.addEventListener(
      "keydown",
      handleKeyDown
    );

    return () => {
      window.removeEventListener(
        "keydown",
        handleKeyDown
      );
    };
  }, [mobileNavigationOpen]);

  useEffect(() => {
    if (!loading && !isAuthenticated) {
      navigate("/login", {
        replace: true,
      });
    }

  }, [
    loading,
    isAuthenticated,
    navigate,
  ]);

  const navigation = (
    <>
      <div className="sidebar-section-label">
        WORKSPACE
      </div>

      <nav
        className="sidebar-navigation"
        aria-label="Primary navigation"
      >
        {NAV_ITEMS.map((item) => {
          const target =
            resolvePath(item);

          const active =
            isItemActive(item);

          const Icon = item.icon;

          return (
            <NavLink
              key={item.path}
              to={target}
              end={item.path === "/"}
              className={`sidebar-nav-item ${
                active
                  ? "sidebar-nav-item-active"
                  : ""
              }`}
              aria-current={
                active
                  ? "page"
                  : undefined
              }
            >
              <span className="sidebar-nav-icon">
                <Icon
                  size={17}
                  strokeWidth={1.9}
                />
              </span>

              <span className="sidebar-nav-label">
                {item.label}
              </span>

              {active && (
                <span
                  className="sidebar-active-indicator"
                  aria-hidden="true"
                />
              )}
            </NavLink>
          );
        })}
      </nav>
    </>
  );

  return (
    <div className="app-shell">
      {/* =================================================
          DESKTOP SIDEBAR
      ================================================== */}

      <aside className="app-sidebar app-sidebar-desktop">
        <div className="sidebar-brand">
          <div className="sidebar-brand-mark">
            <ShieldCheck
              size={20}
              strokeWidth={2}
            />
          </div>

          <div className="sidebar-brand-copy">
            <div className="sidebar-brand-name">
              SecureSense AI
            </div>

            <div className="sidebar-brand-subtitle">
              Multi-Modal Explainable Trust Intelligence Platform
            </div>
          </div>
        </div>

        {navigation}

        {communicationId && (
          <div className="sidebar-investigation">
            <div className="sidebar-investigation-label">
              ACTIVE INVESTIGATION
            </div>

            <div className="sidebar-investigation-status">
              <span className="sidebar-status-dot" />

              Investigation loaded
            </div>

            <div
              className="sidebar-investigation-id"
              title={communicationId}
            >
              {communicationId}
            </div>
          </div>
        )}

        {user && (
  <div
    style={{
      padding: "16px",
      borderTop: "1px solid rgba(255,255,255,0.08)",
    }}
  >
    <div
      style={{
        fontSize: "13px",
        marginBottom: "10px",
      }}
    >
      Signed in as
      <br />
      <strong>{user.username}</strong>
    </div>

    <button
      onClick={logout}
      style={{
        width: "100%",
        padding: "10px",
        borderRadius: "8px",
        border: "none",
        cursor: "pointer",
      }}
    >
      Logout
    </button>
  </div>
)}

        <div className="sidebar-footer">
          <div className="sidebar-product-status">
            <div className="sidebar-product-icon">
              <ShieldCheck
                size={15}
                strokeWidth={1.9}
              />
            </div>

            <div>
              <strong>
                Security Workspace
              </strong>

              <span>
                Multimodal trust intelligence
              </span>
            </div>
          </div>

          <div className="sidebar-footer-caption">
            SecureSense AI
          </div>
        </div>
      </aside>

      {/* =================================================
          MOBILE HEADER
      ================================================== */}

      <header className="app-mobile-header">
        <div className="mobile-brand">
          <div className="mobile-brand-mark">
            <ShieldCheck
              size={18}
              strokeWidth={2}
            />
          </div>

          <div className="mobile-brand-copy">
            <strong>
              SecureSense AI
            </strong>

            <span>
              {currentPage}
            </span>
          </div>
        </div>

        <button
          type="button"
          className="mobile-menu-button"
          onClick={() =>
            setMobileNavigationOpen(true)
          }
          aria-label="Open navigation"
          aria-expanded={
            mobileNavigationOpen
          }
        >
          <Menu size={21} />
        </button>
      </header>

      {/* =================================================
          MOBILE BACKDROP
      ================================================== */}

      {mobileNavigationOpen && (
        <button
          type="button"
          className="mobile-sidebar-backdrop"
          onClick={() =>
            setMobileNavigationOpen(false)
          }
          aria-label="Close navigation"
        />
      )}

      {/* =================================================
          MOBILE DRAWER
      ================================================== */}

      <aside
        className={`app-mobile-sidebar ${
          mobileNavigationOpen
            ? "app-mobile-sidebar-open"
            : ""
        }`}
        aria-hidden={
          !mobileNavigationOpen
        }
      >
        <div className="mobile-sidebar-header">
          <div className="sidebar-brand">
            <div className="sidebar-brand-mark">
              <ShieldCheck
                size={20}
                strokeWidth={2}
              />
            </div>

            <div className="sidebar-brand-copy">
              <div className="sidebar-brand-name">
                SecureSense AI
              </div>

              <div className="sidebar-brand-subtitle">
                Trust Intelligence
              </div>
            </div>
          </div>

          <button
            type="button"
            className="mobile-sidebar-close"
            onClick={() =>
              setMobileNavigationOpen(false)
            }
            aria-label="Close navigation"
          >
            <X size={20} />
          </button>
        </div>

        <div className="mobile-sidebar-content">
          {navigation}

          {communicationId && (
            <div className="sidebar-investigation">
              <div className="sidebar-investigation-label">
                ACTIVE INVESTIGATION
              </div>

              <div className="sidebar-investigation-status">
                <span className="sidebar-status-dot" />

                Investigation loaded
              </div>

              <div
                className="sidebar-investigation-id"
                title={communicationId}
              >
                {communicationId}
              </div>
            </div>
          )}
        </div>

        <div className="mobile-sidebar-footer">
          <div className="sidebar-product-status">
            <div className="sidebar-product-icon">
              <ShieldCheck
                size={15}
                strokeWidth={1.9}
              />
            </div>

            <div>
              <strong>
                Security Workspace
              </strong>

              <span>
                Multimodal trust intelligence
              </span>
            </div>
          </div>
        </div>
      </aside>

      {/* =================================================
          APPLICATION CONTENT
      ================================================== */}

      <main className="app-main">
        <div className="app-content">
          <Outlet />
        </div>
      </main>
    </div>
  );
}