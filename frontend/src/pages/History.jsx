import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import "../styles/sentinel.css";
import NewScan from "../components/NewScan";

function History() {
  const navigate = useNavigate();
  const handleLogout = async () => {
    const user_id = localStorage.getItem("user_id");
    
    try {
      await fetch("http://127.0.0.1:5000/api/auth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_id, session_token: localStorage.getItem("session_token"),}),
      });
    } catch (err) {
      console.error("Logout request failed", err);
    }
    
    localStorage.removeItem("user");
    localStorage.removeItem("user_id");
    localStorage.removeItem("session_token");
    navigate("/");
  };
  const [openScan, setOpenScan] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [severityFilter, setSeverityFilter] = useState("All Severities");
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");

  const [appliedSearch, setAppliedSearch] = useState("");
  const [appliedStatusFilter, setAppliedStatusFilter] = useState("All");
  const [appliedSeverityFilter, setAppliedSeverityFilter] = useState("All Severities");
  const [appliedFromDate, setAppliedFromDate] = useState("");
  const [appliedToDate, setAppliedToDate] = useState("");
  const [historyItems, setHistoryItems] = useState([]);

  const [user, setUser] = useState(null);
  
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

  const firstName = user?.full_name?.split(" ")[0] || "User";

  const [totalAlerts, setTotalAlerts] = useState(0);
  
  useEffect(() => {
    const user_id = localStorage.getItem("user_id");
    if (!user_id) return;
    
    const fetchHistory = async () => {
      try {
        const res = await fetch(`http://127.0.0.1:5000/api/scans/history?user_id=${user_id}`);
        const data = await res.json();
        
        if (res.ok) {
          setHistoryItems(data.scans || []);
        }
      } catch (err) {
        console.error("Failed to fetch history", err);
      }
    };
    
    fetchHistory();
    
    const interval = setInterval(fetchHistory, 2000);
    
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const user_id = localStorage.getItem("user_id");
    if (!user_id) return;
    
    const fetchAlertCount = async () => {
      try {
        const res = await fetch(`http://127.0.0.1:5000/api/alerts?user_id=${user_id}`);
        const data = await res.json();
        
        if (res.ok) {
          const activeUnreadAlerts = (data.alerts || []).filter(
            (alert) => alert.status !== "Resolved" && (alert.unread ?? !alert.is_read)
          );
          setTotalAlerts(activeUnreadAlerts.length);
        }
      } catch (err) {
        console.error("Failed to fetch alert count", err);
      }
    };
    
    fetchAlertCount();
    const interval = setInterval(fetchAlertCount, 3000);
    
    return () => clearInterval(interval);
  }, []);
 
  const handleView = (scanId) => {
    navigate(`/results?scan_id=${scanId}`);
  };
  
  const handleRerun = async (scanId) => {
    try {
      const response = await fetch(
        `http://127.0.0.1:5000/api/scans/${scanId}/rerun`,
        {
          method: "POST",
        }
      );
      
      const data = await response.json();
      
      if (!response.ok) {
        alert(data.error || "Failed to re-run scan.");
        return;
      }
      
      window.location.reload();
    } catch (err) {
      alert("Server error. Please try again.");
    }
  };
  
  const handleDelete = async (scanId) => {
    const confirmed = window.confirm("Are you sure you want to delete this scan?");
    if (!confirmed) return;
    
    try {
      const response = await fetch(
        `http://127.0.0.1:5000/api/scans/${scanId}`,
        {
          method: "DELETE",
        }
      );
      
      const data = await response.json();
      
      if (!response.ok) {
        alert(data.error || "Failed to delete scan.");
        return;
      }
      
      setHistoryItems((prev) => prev.filter((item) => item.scan_id !== scanId));
    } catch (err) {
      alert("Server error. Please try again.");
    }
  };

  const handleApplyFilters = () => {
    setAppliedSearch(search);
    setAppliedStatusFilter(statusFilter);
    setAppliedSeverityFilter(severityFilter);
    setAppliedFromDate(fromDate);
    setAppliedToDate(toDate);
  };

  const filteredItems = useMemo(() => {
    return historyItems.filter((item) => {
      const searchMatch =
        (item.target_url || "").toLowerCase().includes(appliedSearch.toLowerCase()) ||
        (item.scan_depth || "").toLowerCase().includes(appliedSearch.toLowerCase());
        
      const statusMatch =
        appliedStatusFilter === "All" ||
        (item.status || "").toLowerCase() === appliedStatusFilter.toLowerCase();
        
      const severityMatch =
        appliedSeverityFilter === "All Severities" ||
        (item.ml_severity || "").toLowerCase() ===
          appliedSeverityFilter.toLowerCase();
      
      const itemDate = item.started_at ? new Date(item.started_at.replace(" ", "T")) : null;
      
      const fromDateObj = appliedFromDate ? new Date(appliedFromDate) : null;
      const toDateObj = appliedToDate ? new Date(appliedToDate) : null;
      
      if (toDateObj) {
        toDateObj.setHours(23, 59, 59, 999);
      }
      
      const dateMatch =
      (!fromDateObj || (itemDate && itemDate >= fromDateObj)) &&
      (!toDateObj || (itemDate && itemDate <= toDateObj));
      return searchMatch && statusMatch && severityMatch && dateMatch;
    });
  }, [
    historyItems,
    appliedSearch,
    appliedStatusFilter,
    appliedSeverityFilter,
    appliedFromDate,
    appliedToDate,
  ]);

  const getChipClass = (value) => {
    if (value === "Critical") return "chip chip-red";
    if (value === "High") return "chip chip-yellow";
    if (value === "Medium") return "chip chip-blue";
    if (value === "Low") return "chip chip-green";
    return "chip chip-purple";
  };

  const getStatusIconClass = (status) => {
    if (status === "Running") return "sg-history-status-icon running";
    return "sg-history-status-icon complete";
  };

  const SidebarIcon = ({ type }) => {
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
  };

  return (
    <div className="sg-dashboard-shell">
      {mobileMenuOpen && (
        <div
          className="sg-mobile-overlay"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}
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
            <div
              className="sg-sidebar-item"
              onClick={() => {
              navigate("/dashboard");
              setMobileMenuOpen(false);
              }}
            >
              <span className="sg-sidebar-menu-icon">
                <SidebarIcon type="dashboard" />
              </span>
              <span>Dashboard</span>
            </div>

            <div
              className="sg-sidebar-item"
              onClick={() => {
              setOpenScan(true);
              setMobileMenuOpen(false);
              }}
            >
              <span className="sg-sidebar-menu-icon">
                <SidebarIcon type="scan" />
              </span>
              <span>New Scan</span>
            </div>

            <div
              className="sg-sidebar-item"
              onClick={() => {
              navigate("/results");
              setMobileMenuOpen(false);
              }}
              >
              <span className="sg-sidebar-menu-icon">
                <SidebarIcon type="results" />
              </span>
              <span>Results</span>
            </div>

            <div className="sg-sidebar-item active">
              <span className="sg-sidebar-menu-icon">
                <SidebarIcon type="history" />
              </span>
              <span>History</span>
            </div>

            <div
              className="sg-sidebar-item"
              onClick={() => {
                navigate("/alerts");
                setMobileMenuOpen(false);
              }}
            >
              <span className="sg-sidebar-menu-icon">
                <SidebarIcon type="alerts" />
              </span>
              <span>Alerts</span>
              {totalAlerts > 0 && (
                <span className="sg-alerts-side-badge">{totalAlerts}</span>
              )}
            </div>

            <div className="sg-sidebar-separator" />

            <div
              className="sg-sidebar-item"
              onClick={() => {
                navigate("/settings");
                setMobileMenuOpen(false);
                }}
              >
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

      <main className="sg-dashboard-main">
        <div className="sg-dashboard-topbar">
          <div className="sg-mobile-topbar-left">
            <button
              className="sg-mobile-icon-btn"
              onClick={() => setMobileMenuOpen(true)}
            >
              ☰
            </button>

            <div>
              <div className="sg-dashboard-title">Scan History</div>
              <div className="sg-dashboard-sub">Welcome, {firstName}</div>
            </div>
          </div>

          <div className="sg-dashboard-actions">
            <input
              className="sg-dashboard-search"
              placeholder="Search URL or depth..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  setAppliedSearch(search);
                }
              }}
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

        <div className="card sg-history-page-card">
          <div className="sg-history-header-row">
            <div className="sg-dashboard-card-title">History</div>

            <div className="sg-history-tabs">
              {["All", "Completed", "Running"].map((tab) => (
                <button
                  key={tab}
                  className={statusFilter === tab ? "active" : ""}
                  onClick={() => setStatusFilter(tab)}
                >
                  {tab}
                </button>
              ))}
            </div>
          </div>

          <div className="sg-history-filter-panel">
            <div className="sg-field" style={{ marginBottom: 0 }}>
              <label className="sg-label">From Date</label>
              <input
                className="sg-input"
                type="date"
                value={fromDate}
                onChange={(e) => setFromDate(e.target.value)}
              />
            </div>

            <div className="sg-field" style={{ marginBottom: 0 }}>
              <label className="sg-label">To Date</label>
              <input
                className="sg-input"
                type="date"
                value={toDate}
                onChange={(e) => setToDate(e.target.value)}
              />
            </div>

            <div className="sg-field" style={{ marginBottom: 0 }}>
              <label className="sg-label">Severity</label>
              <select
                className="sg-input"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option>All Severities</option>
                <option>Critical</option>
                <option>High</option>
                <option>Medium</option>
                <option>Low</option>
              </select>
            </div>

            <button className="sg-history-apply-btn" onClick={handleApplyFilters}>
              Apply Filters
            </button>
          </div>

          <div className="sg-history-list">
            {filteredItems.map((item) => (
              <div key={item.scan_id} className="sg-history-card">
                <div className="sg-history-left">
                  <div className={getStatusIconClass(item.status)}>
                    {item.status === "Running" ? "✳" : "✓"}
                  </div>

                  <div className="sg-history-main">
                    <div className="sg-history-url">{item.target_url}</div>
                    <div className="sg-history-meta">
                      {item.scan_depth} • {item.time_ago || "—"} • {item.display_date || "—"}
                    </div>
                    <div className="sg-history-endpoints">
                      {item.total_endpoints} endpoints ({item.tested_endpoints} tested / {item.skipped_endpoints} skipped)
                    </div>

                    {item.status === "Running" && (
                      <>
                        <div className="sg-history-progress-head">
                          <span>Scan Progress</span>
                          <span>{item.progress_percent}%</span>
                        </div>
                        <div className="sg-history-progress-track">
                          <div
                            className="sg-history-progress-fill"
                            style={{ width: `${item.progress_percent}%` }}
                          />
                        </div>
                      </>
                    )}

                    <div className="sg-history-counts">
                      <span className="critical">C:{item.ml_severity === "Critical" ? item.vulnerabilities_found : 0}</span>
                      <span className="high">H:{item.ml_severity === "High" ? item.vulnerabilities_found : 0}</span>
                      <span className="medium">M:{item.ml_severity === "Medium" ? item.vulnerabilities_found : 0}</span>
                      <span className="low">L:{item.ml_severity === "Low" ? item.vulnerabilities_found : 0}</span>
                    </div>
                  </div>
                </div>

                <div className="sg-history-right">
                  <div className="sg-history-chip-row">
                    <span className={getChipClass(item.ml_severity)}>
                      ML Severity: {item.ml_severity}
                      </span>
                    <span className="chip chip-blue">
                      CVSS Score: {item.cvss_score}
                      </span>  
                  </div>

                  <div className="sg-history-actions">
                    <button
                    className="sg-history-soft-btn view"
                    onClick={() => handleView(item.scan_id)}
                    >
                      View
                    </button>
                    
                    <button
                    className="sg-history-soft-btn rerun"
                    onClick={() => handleRerun(item.scan_id)}
                    >
                      Re-run
                    </button>
                    
                    <button
                    className="sg-history-soft-btn delete"
                    onClick={() => handleDelete(item.scan_id)}
                    >
                      Delete
                    </button>
                  </div>

                  <div className="sg-history-status-box">
                    <div className={item.status === "Running" ? "running" : "complete"}>
                      {item.status}...
                    </div>
                    <div>{item.time_ago}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </main>

      <NewScan isOpen={openScan} onClose={() => setOpenScan(false)} />
    </div>
  );
}

export default History;