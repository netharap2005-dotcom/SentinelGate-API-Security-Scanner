import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Bar, Doughnut } from "react-chartjs-2";
import {
  Chart as ChartJS,
  ArcElement,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
} from "chart.js";
import "../styles/sentinel.css";
import NewScan from "../components/NewScan";

ChartJS.register(
  ArcElement,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend
);


function Dashboard() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [isMobile, setIsMobile] = useState(window.innerWidth <= 900);

  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth <= 900);
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  const [view, setView] = useState("week");
  const [openTip, setOpenTip] = useState("");
  const [monthPage, setMonthPage] = useState(0);

  const [openScan, setOpenScan] = useState(false);
  const [user, setUser] = useState(null);
  const [dashboardData, setDashboardData] = useState(null);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [searchQuery, setSearchQuery] = useState("");
  
  const navigate = useNavigate();
  
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
  
  useEffect(() => {
    const fetchDashboard = async () => {
      const user_id = localStorage.getItem("user_id");
      
      if (!user_id) return;
      
      try {
        const response = await fetch(
          `http://127.0.0.1:5000/api/dashboard/summary?user_id=${user_id}&period=${view}&month_page=${monthPage}`
        );
        
        const data = await response.json();
        
        if (response.ok) {
          setDashboardData(data);
        }
      } catch (err) {
        console.error("Dashboard fetch failed", err);
      }
    };

  fetchDashboard();
}, [view, monthPage]);

const handleLogout = async () => {
    const user_id = localStorage.getItem("user_id");
    
    try {
      await fetch("http://127.0.0.1:5000/api/auth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_id, session_token: localStorage.getItem("session_token") }),
      });
    } catch (err) {
      console.error("Logout request failed", err);
    }
    
    localStorage.removeItem("user");
    localStorage.removeItem("user_id");
    localStorage.removeItem("session_token");
    navigate("/");
  };

  const firstName = user?.full_name?.split(" ")[0] || "User";

  const topCards = dashboardData?.top_cards || {};
  const lastScan = dashboardData?.last_scan_summary || null;
  const recentThreats = dashboardData?.recent_threats || [];
  const severityBreakdown = dashboardData?.severity_breakdown || {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  };
  const threatActivity = dashboardData?.threat_activity || [];
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

  

  const threatChartData = {
    labels: threatActivity.map((item) => item.label),
    datasets: [
      {
        label: "Detected Threats",
        data: threatActivity.map((item) => item.value),
        backgroundColor: "#3b82f6",
        borderRadius: 8,
        maxBarThickness: 38,
      },
    ],
  };
  
  const threatChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: { enabled: true },
    },
    scales: {
      x: {
        grid: { display: false },
        ticks: { color: "#6b7a90" },
      },
      y: {
        beginAtZero: true,
        ticks: {
          stepSize: 1,
          color: "#94a3b8",
        },
        grid: {
          color: "#e5edf8",
        },
      },
    },
  };
  
  const severityChartData = {
    labels: ["Critical", "High", "Medium", "Low"],
    datasets: [
      {
        data: [
          severityBreakdown.Critical || 0,
          severityBreakdown.High || 0,
          severityBreakdown.Medium || 0,
          severityBreakdown.Low || 0,
        ],
        backgroundColor: ["#ef4444", "#f59e0b", "#3b82f6", "#22c55e"],
        borderWidth: 0,
        cutout: "64%",
      },
    ],
  };
  
  const severityChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
    },
  };



  const badgeClass = (value) => {
    if (value === "Critical") return "chip chip-red";
    if (value === "High") return "chip chip-yellow";
    if (value === "Medium") return "chip chip-blue";
    if (value === "Low") return "chip chip-green";
    return "chip chip-purple";
  };

  const statusColor = (status) => {
    if (status === "Open") return "#dc2626";
    if (status === "Investigating") return "#d97706";
    if (status === "Mitigated") return "#2563eb";
    if (status === "Closed") return "#16a34a";
    return "#64748b";
  };

  const toggleTip = (name) => {
    setOpenTip((prev) => (prev === name ? "" : name));
  };

  const handleDashboardSearch = (e) => {
    if (e.key !== "Enter") return;
    
    const query = searchQuery.toLowerCase().trim();
    if (!query) return;
    
    if (query.includes("alert")) {
      navigate("/alerts");
    } else if (query.includes("history")) {
      navigate("/history");
    } else if (query.includes("result")) {
      navigate("/results");
    } else if (query.includes("setting")) {
      navigate("/settings");
    } else if (query.includes("scan")) {
      setOpenScan(true);
    } else if (
      query.includes("threat") ||
      query.includes("chart") ||
      query.includes("activity")
    ) {
      document
        .getElementById("threat-activity-section")
        ?.scrollIntoView({ behavior: "smooth", block: "start" });
    } else if (
      query.includes("severity") ||
      query.includes("breakdown")
    ) {
      document
        .getElementById("severity-breakdown-section")
        ?.scrollIntoView({ behavior: "smooth", block: "start" });
    } else {
      alert("No matching dashboard section found");
    }
  };

  return (
    <div className="sg-dashboard-shell">
      {isMobile && menuOpen && (
        <div className="sg-mobile-overlay" onClick={() => setMenuOpen(false)} />
      )}
      <aside className={`sg-dashboard-sidebar ${menuOpen ? "open" : ""}`}>
        <div className="sg-dashboard-sidebar-inner">
          <div className="sg-sidebar-brand">
            <div className="sg-sidebar-logo-wrap">
              <img src="/logo.png" alt="Sentinel Gate Logo" className="sg-sidebar-logo-img" />
            </div>
            <div>
              <div className="sg-sidebar-brand-title">Sentinel Gate</div>
            </div>
          </div>

          <div className="sg-sidebar-menu">
            <div className="sg-sidebar-item active">
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

            <div className="sg-sidebar-item" onClick={() => navigate("/alerts")}>
              <span className="sg-sidebar-menu-icon">
                <SidebarIcon type="alerts" />
              </span>
              <span>Alerts</span>
                {totalAlerts > 0 && (
                  <span className="sg-alerts-side-badge">{totalAlerts}</span>
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

      <main className="sg-dashboard-main">
        <div className="sg-dashboard-topbar">
          <div className="sg-mobile-topbar-left">

            {isMobile && (
              <button
                className="sg-mobile-icon-btn"
                onClick={() => setMenuOpen(true)}
              >
                ☰
              </button>
            )}

            <div>
              <div className="sg-dashboard-title">Dashboard</div>
              <div className="sg-dashboard-sub">Welcome, {firstName}</div>
            </div>

          </div>

          <div className="sg-dashboard-actions">
            <input
              className="sg-dashboard-search"
              placeholder="Search..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={handleDashboardSearch}
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

        <div className="sg-dashboard-metrics">
          <div className="metric sg-dashboard-metric-card">
            <div className="sg-metric-head">
              <div className="sg-metric-label">TOTAL ENDPOINTS SCANNED</div>
              <div className="sg-metric-icon blue">🌐</div>
            </div>
            <div className="sg-metric-value">{topCards.total_apis || 0}</div>
            <div className="sg-metric-sub green">↗ +12 this week</div>
          </div>

          <div className="metric sg-dashboard-metric-card">
            <div className="sg-metric-head">
              <div className="sg-metric-label">VULNERABILITIES</div>
              <div className="sg-metric-icon red">⚠</div>
            </div>
            <div className="sg-metric-value">{topCards.vulnerabilities || 0}</div>
            <div className="sg-metric-chip-row">
              <span className="chip chip-red">{topCards.critical_count || 0} Critical</span>
              <span className="chip chip-yellow">{topCards.high_count || 0} High</span>
            </div>
          </div>

          <div className="metric sg-dashboard-metric-card sg-tip-parent">
            <div className="sg-metric-head">
              <div className="sg-metric-label-row">
                <div className="sg-metric-label">CVSS SCORE</div>
                <button
                  className="sg-info-btn"
                  onClick={() => toggleTip("cvss")}
                >
                  i
                </button>
              </div>
              <div className="sg-metric-icon amber">◔</div>
            </div>

            <div className="sg-cvss-row">
              <div>
                <div className="sg-metric-value">{topCards.cvss_score || 0}</div>
                <div className="sg-metric-sub amber-text">High Risk</div>
              </div>
              <div className="sg-cvss-gauge" />
            </div>

            <div className={`tooltip ${openTip === "cvss" ? "show" : ""}`}>
              CVSS is a standard security score used to measure how serious a
              vulnerability is. Higher scores mean greater risk and should be
              fixed more urgently.
              <br />
              <br />
              CVSS Breakdown
              <br />
              0.1 – 3.9 = Low
              <br />
              4.0 – 6.9 = Medium
              <br />
              7.0 – 8.9 = High
              <br />
              9.0 – 10.0 = Critical
            </div>
          </div>

          <div className="metric sg-dashboard-metric-card sg-tip-parent">
            <div className="sg-metric-head">
              <div className="sg-metric-label-row">
                <div className="sg-metric-label">ML SEVERITY</div>
                <button
                  className="sg-info-btn"
                  onClick={() => toggleTip("ml")}
                >
                  i
                </button>
              </div>
              <div className="sg-metric-icon red">◑</div>
            </div>
            <div className="sg-metric-value">{topCards.ml_severity || "Low"}</div>
            <div className="sg-metric-sub amber-text">Predicted risk level</div>

            <div className={`tooltip ${openTip === "ml" ? "show" : ""}`}>
              Machine Learning predicted severity based on scan patterns and
              detected behavior.
            </div>
          </div>

          <div className="metric sg-dashboard-metric-card">
            <div className="sg-metric-head">
              <div className="sg-metric-label">ACTIVE ALERTS</div>
              <div className="sg-metric-icon sky">
                <span style={{
                  width: "10px",
                  height: "10px",
                  borderRadius: "50%",
                  background: "#3b82f6",
                  display: "inline-block"
                }} />
              </div>
            </div>

            <div className="sg-metric-value">{totalAlerts}</div>

            <div className="sg-metric-sub green">
              -3 from yesterday
            </div>
          </div>
        </div>

        <div className="sg-dashboard-row">
          <div id="threat-activity-section" className="card sg-dashboard-chart-card sg-tip-parent">
            <div className="sg-dashboard-card-head">
              <div>
                <div className="sg-dashboard-card-title-row">
                  <div className="sg-dashboard-card-title">Threat Activity</div>
                  <button
                    className="sg-info-btn"
                    onClick={() => toggleTip("threat")}
                  >
                    i
                  </button>
                </div>
                <div className="sg-dashboard-card-sub">
                  {view === "week"
                    ? "Detected vulnerabilities over the last 7 days"
                    : "Detected vulnerabilities over recent months"}
                </div>
              </div>

              <div className="sg-chart-controls">
                <div className="seg">
                  <button
                    className={view === "week" ? "active" : ""}
                    onClick={() => {
                      setView("week");
                      setMonthPage(0);
                    }}
                  >
                    Week
                  </button>
                  <button
                    className={view === "month" ? "active" : ""}
                    onClick={() => setView("month")}
                  >
                    Month
                  </button>
                </div>
                {view === "month" && (
                  <div style={{ display: "flex", gap: "8px", marginTop: "10px" }}>
                    <button
                      onClick={() => setMonthPage(0)}
                      style={{
                        padding: "8px 12px",
                        borderRadius: "10px",
                        border: "1px solid #dbe7fb",
                        background: monthPage === 0 ? "#eef4ff" : "#fff",
                        cursor: "pointer",
                      }}
                    >
                      Jan – Jun
                    </button>
                    
                    <button
                      onClick={() => setMonthPage(1)}
                      style={{
                        padding: "8px 12px",
                        borderRadius: "10px",
                        border: "1px solid #dbe7fb",
                        background: monthPage === 1 ? "#eef4ff" : "#fff",
                        cursor: "pointer",
                      }}
                    >
                      Jul – Dec
                    </button>
                  </div>
                )}

                {view === "month" && (
                  <button
                    className="sg-month-arrow"
                    onClick={() => setMonthPage((prev) => (prev === 0 ? 1 : 0))}
                    aria-label={monthPage === 0 ? "Show August to December" : "Show January to June"}
                    title={monthPage === 0 ? "Show August to December" : "Show January to June"}
                  >
                    {monthPage === 0 ? "→" : "←"}
                  </button>
                )}
              </div>
            </div>

            <div className={`tooltip ${openTip === "threat" ? "show" : ""}`}>
              Shows the number of detected vulnerabilities over time to help
              users spot unusual spikes.
            </div>

            <div className="sg-threat-legend">
              <span className="sg-threat-legend-dot" />
              <span>Detected Threats</span>
              <span className="sg-threat-legend-note">
                Higher bars indicate more detected vulnerabilities
              </span>
            </div>

            <div style={{ height: "280px", marginTop: "16px", width: "100%" }}>
              <Bar key={JSON.stringify(threatActivity)} data={threatChartData} options={threatChartOptions} />
            </div>
          </div>

          <div id="severity-breakdown-section" className="card sg-dashboard-severity-card">
            <div className="sg-dashboard-card-title">Final Risk Severity Breakdown</div>
            <div className="sg-dashboard-card-sub">
              Combined severity based on CVSS score and ML prediction
            </div>

            <div style={{ height: "210px", position: "relative", marginTop: "10px" }}>
              <Doughnut key={JSON.stringify(severityBreakdown)} data={severityChartData} options={severityChartOptions} />
              <div
                style={{
                  position: "absolute",
                  inset: 0,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  flexDirection: "column",
                  pointerEvents: "none",
                }}
              >
                <div style={{ fontSize: "22px", fontWeight: 800, color: "#0f2042" }}>
                  {topCards.vulnerabilities || 0}
                </div>
                <div style={{ fontSize: "13px", color: "#7a8ca8" }}>Total</div>
              </div>
            </div>

            <div className="sg-react-severity-list">
              <div className="severity-row">
                <div className="sg-react-severity-left">
                  <span
                    className="severity-dot"
                    style={{ background: "#ef4444" }}
                  />
                  <span>Critical</span>
                </div>
                <span className="sg-react-severity-num">{severityBreakdown.Critical || 0}</span>
              </div>

              <div className="severity-row">
                <div className="sg-react-severity-left">
                  <span
                    className="severity-dot"
                    style={{ background: "#f59e0b" }}
                  />
                  <span>High</span>
                </div>
                <span className="sg-react-severity-num">{severityBreakdown.High || 0}</span>
              </div>

              <div className="severity-row">
                <div className="sg-react-severity-left">
                  <span
                    className="severity-dot"
                    style={{ background: "#3b82f6" }}
                  />
                  <span>Medium</span>
                </div>
                <span className="sg-react-severity-num">{severityBreakdown.Medium || 0}</span>
              </div>

              <div className="severity-row">
                <div className="sg-react-severity-left">
                  <span
                    className="severity-dot"
                    style={{ background: "#22c55e" }}
                  />
                  <span>Low</span>
                </div>
                <span className="sg-react-severity-num">{severityBreakdown.Low || 0}</span>
              </div>
            </div>
          </div>
        </div>

        <div className="card sg-dashboard-summary-card">
          <div className="sg-summary-head">
            <div className="sg-dashboard-card-title">Last Scan Summary</div>
            <div className="sg-summary-right">Latest completed scan</div>
          </div>

          <div className="sg-summary-grid-react">
            <div>
              <div className="sg-summary-label">Endpoints</div>
              <div className="sg-summary-value">{lastScan?.endpoints || 0}</div>
            </div>
            <div>
              <div className="sg-summary-label">Vulnerabilities</div>
              <div className="sg-summary-value">{lastScan?.vulnerabilities || 0}</div>
            </div>
            <div>
              <div className="sg-summary-label">CVSS</div>
              <div className="sg-summary-value">{lastScan?.cvss_score || 0}</div>
            </div>
            <div>
              <div className="sg-summary-label">ML Severity</div>
              <div className="sg-summary-value amber-text">{lastScan?.ml_severity || "Low"}</div>
            </div>
          </div>
        </div>

        <div className="card sg-dashboard-table-card">
          <div className="sg-summary-head">
            <div className="sg-dashboard-card-title">Recent Threats Detected</div>
            <div
              className="sg-view-all"
              onClick={() => navigate("/history")}
              style={{ cursor: "pointer" }}
            >
              View All
            </div>
          </div>

          {/* Desktop / Laptop table */}
          <div className="sg-table-wrap sg-desktop-threats">
            <table className="sg-table-react">
                <thead>
                  <tr>
                    <th>ENDPOINT</th>
                    <th>TYPE</th>
                    <th>SEVERITY</th>
                    <th>ML SEVERITY</th>
                    <th>CVSS</th>
                    <th>STATUS</th>
                    <th>TIME</th>
                  </tr>
                </thead>
                <tbody>
                  {recentThreats.map((item) => (
                    <tr key={item.endpoint}>
                      <td className="sg-endpoint-cell">{item.endpoint}</td>
                      <td>{item.type}</td>
                      <td>
                        <span className={badgeClass(item.severity)}>{item.severity}</span>
                      </td>
                      <td>
                        <span className={badgeClass(item.ml_severity)}>{item.ml_severity}</span>
                      </td>
                      <td className="sg-cvss-number">{item.cvss_score}</td>
                      <td
                        style={{
                          color: statusColor(item.status),
                          fontWeight: 600,
                        }}
                      >
                        • {item.status}
                      </td>
                      <td>{item.time}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Mobile cards */}
            <div className="sg-mobile-threats">
              {recentThreats.map((item) => (
                <div className="sg-mobile-threat-card" key={item.endpoint}>
                  <div className="sg-mobile-threat-top">
                    <div>
                      <div className="sg-mobile-threat-endpoint">{item.endpoint}</div>
                      <div className="sg-mobile-threat-sub">
                        {item.type} • {item.time}
                      </div>
                    </div>

                    <div className="sg-mobile-threat-badges">
                      <span className={badgeClass(item.severity)}>{item.severity}</span>
                      <span className={badgeClass(item.ml_severity)}>ML {item.ml_severity}</span>
                    </div>
                  </div>

                  <div className="sg-mobile-threat-meta">
                    <div className="sg-mobile-threat-meta-item">
                      <span className="sg-mobile-threat-meta-label">CVSS</span>
                      <span className="sg-mobile-threat-meta-value">{item.cvss_score}</span>
                    </div>

                    <div className="sg-mobile-threat-meta-item">
                      <span className="sg-mobile-threat-meta-label">Status</span>
                      <span
                        className="sg-mobile-threat-meta-value"
                        style={{ color: statusColor(item.status) }}
                      >
                        {item.status}
                      </span>
                    </div>

                    <div className="sg-mobile-threat-meta-item">
                      <span className="sg-mobile-threat-meta-label">Time</span>
                      <span className="sg-mobile-threat-meta-value">{item.time}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
      </main>
      <NewScan
        isOpen={openScan}
        onClose={() => setOpenScan(false)}
      />
    </div>
  );
}

export default Dashboard;