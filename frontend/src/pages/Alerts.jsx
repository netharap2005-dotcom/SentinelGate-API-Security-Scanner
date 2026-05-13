import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import "../styles/sentinel.css";
import NewScan from "../components/NewScan";

function SidebarIcon({ type }) {
  const common = {
    width: "18",
    height: "18",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "1.8",
    strokeLinecap: "round",
    strokeLinejoin: "round",
  };

  if (type === "dashboard") {
    return (
      <svg {...common}>
        <rect x="3" y="3" width="7" height="7" rx="1.5" />
        <rect x="14" y="3" width="7" height="7" rx="1.5" />
        <rect x="3" y="14" width="7" height="7" rx="1.5" />
        <rect x="14" y="14" width="7" height="7" rx="1.5" />
      </svg>
    );
  }

  if (type === "scan") {
    return (
      <svg {...common}>
        <circle cx="11" cy="11" r="6.5" />
        <path d="M20 20l-3.5-3.5" />
      </svg>
    );
  }

  if (type === "results") {
    return (
      <svg {...common}>
        <path d="M5 19V10" />
        <path d="M12 19V5" />
        <path d="M19 19v-8" />
      </svg>
    );
  }

  if (type === "history") {
    return (
      <svg {...common}>
        <path d="M3 12a9 9 0 1 0 3-6.7" />
        <path d="M3 4v5h5" />
        <path d="M12 7v5l3 2" />
      </svg>
    );
  }

  if (type === "alerts") {
    return (
      <svg {...common}>
        <path d="M15 17H5.8a1 1 0 0 1-.8-1.6l1.3-1.7A4 4 0 0 0 7 11.3V10a5 5 0 1 1 10 0v1.3a4 4 0 0 0 .7 2.4l1.3 1.7a1 1 0 0 1-.8 1.6H15" />
        <path d="M10 20a2 2 0 0 0 4 0" />
      </svg>
    );
  }

  if (type === "settings") {
    return (
      <svg {...common}>
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.2a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.2a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3h.1a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.2a1.7 1.7 0 0 0 1 1.5h.1a1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8v.1a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.2a1.7 1.7 0 0 0-1.5 1z" />
      </svg>
    );
  }

  return null;
}

function Alerts() {
  const navigate = useNavigate();

  const [alerts, setAlerts] = useState([]);
  const [sortBy, setSortBy] = useState("priority");
  const [searchTerm, setSearchTerm] = useState("");
  const [openScan, setOpenScan] = useState(false);
  const [toast, setToast] = useState("");
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [user, setUser] = useState(null);

  const handleLogout = async () => {
    const user_id = localStorage.getItem("user_id");
    
    try {
      await fetch("http://127.0.0.1:5000/api/auth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_id, session_token: localStorage.getItem("session_token"), }),
      });
    } catch (err) {
      console.error("Logout request failed", err);
    }
    
    localStorage.removeItem("user");
    localStorage.removeItem("user_id");
    localStorage.removeItem("session_token");
    navigate("/");
  };

  useEffect(() => {
    const storedUser = localStorage.getItem("user");
    if (storedUser) {
      setUser(JSON.parse(storedUser));
    }
  }, []);

  useEffect(() => {
  const checkSession = async () => {
    const user_id = localStorage.getItem("user_id");
    const session_token = localStorage.getItem("session_token");

    if (!user_id || !session_token) {
      navigate("/");
      return;
    }

    try {
      const res = await fetch(
        `http://127.0.0.1:5000/api/settings/manage-sessions?user_id=${user_id}&session_token=${session_token}`
      );

      const data = await res.json();

      if (
        !res.ok ||
        !data.current_session ||
        data.current_session.status !== "Active"
      ) {
        localStorage.removeItem("user");
        localStorage.removeItem("user_id");
        localStorage.removeItem("session_token");
        navigate("/");
      }
    } catch (err) {
      navigate("/");
    }
  };

  checkSession();
  const interval = setInterval(checkSession, 3000);

  return () => clearInterval(interval);
}, [navigate]);

  useEffect(() => {
    const user_id = localStorage.getItem("user_id");
    if (!user_id) return;
    
    const fetchAlerts = async () => {
      try {
        const res = await fetch(
          `http://127.0.0.1:5000/api/alerts?user_id=${user_id}`
        );
        const data = await res.json();
        
        if (res.ok) {
          setAlerts(data.alerts || []);
        }
      } catch (err) {
        console.error("Failed to fetch alerts", err);
      }
    };
    
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 3000);
    
    return () => clearInterval(interval);
  }, []);

  const firstName = user?.full_name?.split(" ")[0] || "User";

  const showToast = (message) => {
    setToast(message);
    setTimeout(() => setToast(""), 2200);
  };

  const totalCount = alerts.filter(
    (alert) => alert.status !== "Resolved" && (alert.unread ?? !alert.is_read)
  ).length;

  const updateAlertState = (id, updates) => {
    setAlerts((prev) =>
      prev.map((alert) => (alert.id === id ? { ...alert, ...updates } : alert))
    );
  };

  const handleInvestigate = async (id) => {
    try {
      const res = await fetch(`http://127.0.0.1:5000/api/alerts/${id}/investigate`, {
        method: "POST",
      });

      if (!res.ok) {
        showToast("Failed to update alert");
        return;
      }

      updateAlertState(id, { status: "Investigating", unread: false });
      showToast("Alert marked as investigating");
    } catch {
      showToast("Failed to update alert");
    }
  };

  const handleResolve = async (id) => {
    try {
      const res = await fetch(`http://127.0.0.1:5000/api/alerts/${id}/resolve`, {
        method: "POST",
      });

      if (!res.ok) {
        showToast("Failed to resolve alert");
        return;
      }

      updateAlertState(id, { status: "Resolved", unread: false });
      showToast("Alert marked as resolved");
    } catch {
      showToast("Failed to resolve alert");
    }
  };

  const handleMarkRead = async (id) => {
    try {
      const res = await fetch(`http://127.0.0.1:5000/api/alerts/${id}/read`, {
        method: "POST",
      });

      if (!res.ok) {
        showToast("Failed to mark alert as read");
        return;
      }

      updateAlertState(id, { unread: false, is_read: true });
      showToast("Alert marked as read");
    } catch {
      showToast("Failed to mark alert as read");
    }
  };

  const handleMarkAllRead = async () => {
    try {
      const user_id = localStorage.getItem("user_id");
      const res = await fetch(
        `http://127.0.0.1:5000/api/alerts/mark-all-read`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ user_id }),
        }
      );

      if (!res.ok) {
        showToast("Failed to mark all alerts as read");
        return;
      }

      setAlerts((prev) =>
        prev.map((alert) => ({ ...alert, unread: false, is_read: true }))
      );
      showToast("All alerts marked as read");
    } catch {
      showToast("Failed to mark all alerts as read");
    }
  };

  const handleRemoveAlert = async (id) => {
    try {
      const res = await fetch(`http://127.0.0.1:5000/api/alerts/${id}`, {
        method: "DELETE",
      });

      if (!res.ok) {
        showToast("Delete failed");
        return;
      }

      setAlerts((prev) => prev.filter((alert) => alert.id !== id));
      showToast("Alert removed");
    } catch {
      showToast("Delete failed");
    }
  };

  const getSeverityChip = (severity) => {
    if (severity === "Critical") return "chip chip-red";
    if (severity === "High") return "chip chip-yellow";
    if (severity === "Medium") return "chip chip-blue";
    return "chip chip-green";
  };

  const getStatusChip = (status) => {
    if (status === "Resolved") return "chip chip-green";
    if (status === "Investigating") return "chip chip-purple";
    return "chip chip-yellow";
  };

  const getSectionClass = (severity) => {
    if (severity === "Critical") return "sg-alerts-section critical";
    if (severity === "High") return "sg-alerts-section high";
    if (severity === "Medium") return "sg-alerts-section medium";
    return "sg-alerts-section low";
  };

  const getSectionDotClass = (severity) => {
    if (severity === "Critical") return "sg-alerts-dot critical";
    if (severity === "High") return "sg-alerts-dot high";
    if (severity === "Medium") return "sg-alerts-dot medium";
    return "sg-alerts-dot low";
  };

  const severityOrder = {
    Critical: 0,
    High: 1,
    Medium: 2,
    Low: 3,
  };

  const filteredAlerts = alerts.filter((alert) => {
    const term = searchTerm.trim().toLowerCase();
    if (!term) return true;

    return (
      (alert.title || "").toLowerCase().includes(term) ||
      (alert.endpoint || "").toLowerCase().includes(term) ||
      (alert.message || alert.description || "").toLowerCase().includes(term) ||
      (alert.category || "").toLowerCase().includes(term)
    );
  });

  const sortedAlerts = [...filteredAlerts].sort((a, b) => {
    if (sortBy === "priority") {
      const severityCompare = severityOrder[a.severity] - severityOrder[b.severity];
      if (severityCompare !== 0) return severityCompare;

      return (a.timeValue || 999999) - (b.timeValue || 999999);
    }

    if (sortBy === "newest") {
      return (a.timeValue || 999999) - (b.timeValue || 999999);
    }

    if (sortBy === "unread") {
      const aUnread = a.unread ?? !a.is_read;
      const bUnread = b.unread ?? !b.is_read;
      if (aUnread !== bUnread) return aUnread ? -1 : 1;
      return (a.timeValue || 999999) - (b.timeValue || 999999);
    }

    return 0;
  });

  const groupedAlerts = ["Critical", "High", "Medium", "Low"].reduce(
    (acc, severity) => {
      const sectionAlerts = sortedAlerts.filter((alert) => alert.severity === severity);
      if (sectionAlerts.length > 0) {
        acc[severity] = sectionAlerts;
      }
      return acc;
    },
    {}
  );

  return (
    <div className="sg-dashboard-shell sg-alerts-shell">
      <aside className={`sg-dashboard-sidebar ${mobileMenuOpen ? "open" : ""}`}>
        <div className="sg-dashboard-sidebar-inner">
          <div className="sg-sidebar-brand">
            <div className="sg-sidebar-logo-wrap">
              <img
                src="/logo.png"
                alt="Sentinel Gate Logo"
                className="sg-sidebar-logo-img"
              />
            </div>
            <div>
              <div className="sg-sidebar-brand-title">Sentinel Gate</div>
            </div>
          </div>

          <div className="sg-sidebar-menu">
            <div className="sg-sidebar-item" onClick={() => navigate("/dashboard")}>
              <span className="sg-sidebar-menu-icon">
                <SidebarIcon type="dashboard" />
              </span>
              <span>Dashboard</span>
            </div>

            <div className="sg-sidebar-item" onClick={() => setOpenScan(true)}>
              <span className="sg-sidebar-menu-icon">
                <SidebarIcon type="scan" />
              </span>
              <span>New Scan</span>
            </div>

            <div className="sg-sidebar-item" onClick={() => navigate("/results")}>
              <span className="sg-sidebar-menu-icon">
                <SidebarIcon type="results" />
              </span>
              <span>Results</span>
            </div>

            <div className="sg-sidebar-item" onClick={() => navigate("/history")}>
              <span className="sg-sidebar-menu-icon">
                <SidebarIcon type="history" />
              </span>
              <span>History</span>
            </div>

            <div className="sg-sidebar-item active">
              <span className="sg-sidebar-menu-icon">
                <SidebarIcon type="alerts" />
              </span>
              <span>Alerts</span>
              {totalCount > 0 && (
                <span className="sg-alerts-side-badge">{totalCount}</span>
              )}
            </div>

            <div className="sg-sidebar-separator" />

            <div className="sg-sidebar-item" onClick={() => navigate("/settings")}>
              <span className="sg-sidebar-menu-icon">
                <SidebarIcon type="settings" />
              </span>
              <span>Settings</span>
            </div>
          </div>

          <div className="sg-sidebar-user">
            <div className="sg-sidebar-user-left">
              <div className="sg-sidebar-avatar">
                {firstName.charAt(0).toUpperCase()}
              </div>
              <div>
                <div className="sg-sidebar-user-name">{firstName}</div>
              </div>
            </div>
            <div
              className="sg-sidebar-logout"
              onClick={handleLogout}
              style={{ cursor: "pointer" }}
              title="Logout"
            >
              ↗
            </div>
          </div>
        </div>
      </aside>

      {mobileMenuOpen && (
        <div
          className="sg-mobile-overlay"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      <main className="sg-dashboard-main sg-alerts-main">
        <div className="sg-dashboard-topbar">
          <div className="sg-mobile-topbar-left">
            <button
              className="sg-mobile-icon-btn"
              onClick={() => setMobileMenuOpen(true)}
            >
              ☰
            </button>

            <div>
              <div className="sg-dashboard-title">Alerts</div>
              <div className="sg-dashboard-sub">Welcome, {firstName}</div>
            </div>
          </div>

          <div className="sg-dashboard-actions">
            <input
              className="sg-dashboard-search"
              placeholder="Search alerts..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
            
            <button
              className="sg-dashboard-scan-btn"
              onClick={() => setOpenScan(true)}
            >
              ⚙ New Scan
              </button>
              
              <button
                className="sg-mobile-plus-btn"
                onClick={() => setOpenScan(true)}
              >
                +
              </button>
          </div>
        </div>

        <div className="card sg-alerts-board">
          <div className="sg-alerts-board-head">
            <div>
              <div className="sg-alerts-board-title">Active Alerts</div>
              <div className="sg-alerts-board-sub">
                Grouped by severity and sorted with critical alerts first
              </div>
            </div>

            <div className="sg-alerts-board-actions">
              <select
                className="sg-alerts-priority-select"
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
              >
                <option value="priority">Priority: Critical first</option>
                <option value="newest">Newest first</option>
                <option value="unread">Unread first</option>
              </select>

              <button className="sg-alerts-markall-btn" onClick={handleMarkAllRead}>
                Mark All Read
              </button>
            </div>
          </div>

          {sortBy === "priority" ? (
            ["Critical", "High", "Medium", "Low"].map((severity) => {
              const sectionAlerts = groupedAlerts[severity] || [];

              if (sectionAlerts.length === 0) return null;

              const activeSectionCount = sectionAlerts.filter(
                (alert) => alert.status !== "Resolved"
              ).length;

              return (
                <section key={severity} className="sg-alerts-group">
                  <div className="sg-alerts-group-head">
                    <div className="sg-alerts-group-left">
                      <span className={getSectionDotClass(severity)} />
                      <span className="sg-alerts-group-title">{severity} Alerts</span>
                    </div>
                    <span className="sg-alerts-group-count">{activeSectionCount}</span>
                  </div>

                  <div className="sg-alerts-group-list">
                    {sectionAlerts.map((alert) => (
                      <article
                        key={alert.id}
                        className={`${getSectionClass(alert.severity)} ${
                          (alert.unread ?? !alert.is_read) ? "unread" : ""
                        }`}
                      >
                        <div className="sg-alerts-item-top">
                          <div className="sg-alerts-item-left">
                            <div className="sg-alerts-item-icon">🔔</div>

                            <div className="sg-alerts-item-content">
                              <div className="sg-alerts-item-title-row">
                                <div className="sg-alerts-item-title">{alert.title}</div>

                                <div className="sg-alerts-inline-chips">
                                  <span className={getSeverityChip(alert.severity)}>
                                    {alert.severity}
                                  </span>
                                  <span className="chip chip-blue">{alert.category}</span>
                                  <span className={getStatusChip(alert.status)}>
                                    {alert.status}
                                  </span>
                                </div>
                              </div>

                              <div className="sg-alerts-item-desc">
                                {alert.message || alert.description}
                              </div>

                              <div className="sg-alerts-meta-row">
                                <span className="chip chip-purple">
                                  ML: {alert.mlSeverity || alert.ml_severity}
                                </span>
                                <span className="chip chip-gray">
                                  CVSS: {alert.cvss || alert.cvss_score}
                                </span>
                                <span className="sg-alerts-time">
                                  {alert.timeLabel || alert.time_ago || "—"}
                                </span>
                                {alert.emailSent || alert.email_sent ? (
                                  <span className="chip chip-green">Email sent</span>
                                ) : null}
                              </div>
                            </div>
                          </div>

                          <div className="sg-alerts-item-actions">
                            <button
                              className="sg-alerts-mini-btn investigate"
                              disabled={alert.status !== "Open"}
                              onClick={() => handleInvestigate(alert.id)}
                            >
                              Investigate
                            </button>

                            <button
                              className="sg-alerts-mini-btn resolve"
                              disabled={alert.status === "Resolved"}
                              onClick={() => handleResolve(alert.id)}
                            >
                              Resolve
                            </button>

                            <button
                              className="sg-alerts-mini-btn markread"
                              onClick={() => {
                                if (!(alert.unread ?? !alert.is_read)) {
                                  showToast("Alert already marked as read");
                                  return;
                                }
                                handleMarkRead(alert.id);
                              }}
                            >
                              Mark read
                            </button>

                            <button
                              className="sg-alerts-close-btn"
                              onClick={() => handleRemoveAlert(alert.id)}
                            >
                              ×
                            </button>
                          </div>
                        </div>

                        <div className="sg-alerts-recommend-box">
                          <div className="sg-alerts-recommend-title">Recommended Action</div>
                          <div className="sg-alerts-recommend-text">
                            {alert.recommendation}
                          </div>
                        </div>
                      </article>
                    ))}
                  </div>
                </section>
              );
            })
          ) : (
            <section className="sg-alerts-group">
              <div className="sg-alerts-group-head">
                <div className="sg-alerts-group-left">
                  <span className="sg-alerts-group-title">
                    {sortBy === "newest" ? "Newest Alerts" : "Unread Alerts"}
                  </span>
                </div>
                <span className="sg-alerts-group-count">
                  {sortedAlerts.filter((alert) => alert.status !== "Resolved").length}
                </span>
              </div>

              <div className="sg-alerts-group-list">
                {sortedAlerts.map((alert) => (
                  <article
                    key={alert.id}
                    className={`${getSectionClass(alert.severity)} ${
                      (alert.unread ?? !alert.is_read) ? "unread" : ""
                    }`}
                  >
                    <div className="sg-alerts-item-top">
                      <div className="sg-alerts-item-left">
                        <div className="sg-alerts-item-icon">🔔</div>

                        <div className="sg-alerts-item-content">
                          <div className="sg-alerts-item-title-row">
                            <div className="sg-alerts-item-title">{alert.title}</div>

                            <div className="sg-alerts-inline-chips">
                              <span className={getSeverityChip(alert.severity)}>
                                {alert.severity}
                              </span>
                              <span className="chip chip-blue">{alert.category}</span>
                              <span className={getStatusChip(alert.status)}>
                                {alert.status}
                              </span>
                            </div>
                          </div>

                          <div className="sg-alerts-item-desc">
                            {alert.message || alert.description}
                          </div>

                          <div className="sg-alerts-meta-row">
                            <span className="chip chip-purple">
                              ML: {alert.mlSeverity || alert.ml_severity}
                            </span>
                            <span className="chip chip-gray">
                              CVSS: {alert.cvss || alert.cvss_score}
                            </span>
                            <span className="sg-alerts-time">
                              {alert.timeLabel || alert.time_ago || "—"}
                            </span>
                            {alert.emailSent || alert.email_sent ? (
                              <span className="chip chip-green">Email sent</span>
                            ) : null}
                          </div>
                        </div>
                      </div>

                      <div className="sg-alerts-item-actions">
                        <button
                          className="sg-alerts-mini-btn investigate"
                          disabled={alert.status !== "Open"}
                          onClick={() => handleInvestigate(alert.id)}
                        >
                          Investigate
                        </button>

                        <button
                          className="sg-alerts-mini-btn resolve"
                          disabled={alert.status === "Resolved"}
                          onClick={() => handleResolve(alert.id)}
                        >
                          Resolve
                        </button>

                        <button
                          className="sg-alerts-mini-btn markread"
                          onClick={() => {
                            if (!(alert.unread ?? !alert.is_read)) {
                              showToast("Alert already marked as read");
                              return;
                            }
                            handleMarkRead(alert.id);
                          }}
                        >
                          Mark read
                        </button>

                        <button
                          className="sg-alerts-close-btn"
                          onClick={() => handleRemoveAlert(alert.id)}
                        >
                          ×
                        </button>
                      </div>
                    </div>

                    <div className="sg-alerts-recommend-box">
                      <div className="sg-alerts-recommend-title">Recommended Action</div>
                      <div className="sg-alerts-recommend-text">{alert.recommendation}</div>
                    </div>
                  </article>
                ))}
              </div>
            </section>
          )}
        </div>

        {toast && <div className="sg-alerts-toast">{toast}</div>}
      </main>

      <NewScan isOpen={openScan} onClose={() => setOpenScan(false)} />
    </div>
  );
}

export default Alerts;