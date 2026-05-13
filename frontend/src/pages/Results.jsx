import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
} from "chart.js";
import "../styles/sentinel.css";
import NewScan from "../components/NewScan";

ChartJS.register(BarElement, CategoryScale, LinearScale, Tooltip, Legend);

function Results() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const scan_id = searchParams.get("scan_id");
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
  const [scanData, setScanData] = useState(null);
  const [latestScanId, setLatestScanId] = useState(null);
  const [filters, setFilters] = useState({
    severity: "all",
    endpoint: "",
    status: "all",
  });
  const [openIds, setOpenIds] = useState([]);
  const [toastMessage, setToastMessage] = useState("");

  const [menuOpen, setMenuOpen] = useState(false);
  const [isMobile, setIsMobile] = useState(window.innerWidth <= 900);

  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth <= 900);
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
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
    
    const fetchResults = async () => {
      try {
        let targetScanId = scan_id;
        
        if (!targetScanId && user_id) {
          const latestRes = await fetch(
            `http://127.0.0.1:5000/api/scans/latest-results?user_id=${user_id}`
          );
          const latestData = await latestRes.json();
          
          if (latestRes.ok && latestData.scan?.scan_id) {
            targetScanId = latestData.scan.scan_id;
            setLatestScanId(targetScanId);
            setScanData(latestData);
            return;
          }
        }
        
        if (!targetScanId) return;
        
        const res = await fetch(`http://127.0.0.1:5000/api/scans/${targetScanId}/results`);
        const data = await res.json();
        
        if (res.ok) {
          setScanData(data);
          
          const alreadyDownloaded = JSON.parse(
            localStorage.getItem("autoDownloadedReports") || "{}"
          );
          
          const autoDownloadEnabled =
            JSON.parse(localStorage.getItem("settings_auto_download") || "false");
            
          if (
            autoDownloadEnabled &&
            data?.scan?.scan_id &&
            !alreadyDownloaded[data.scan.scan_id]
          ) {
            const link = document.createElement("a");
            link.href = `http://127.0.0.1:5000/api/scans/${data.scan.scan_id}/export-pdf`;
            link.download = `scan_${data.scan.scan_id}_report.pdf`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            alreadyDownloaded[data.scan.scan_id] = true;
            localStorage.setItem(
              "autoDownloadedReports",
              JSON.stringify(alreadyDownloaded)
            )
        }
      }
      } catch (err) {
        console.error("Failed to load results", err);
      }
    };
    
    fetchResults();
  }, [scan_id]);

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

  const [user, setUser] = useState(null);

  useEffect(() => {
    const storedUser = localStorage.getItem("user");
    if (storedUser) {
      setUser(JSON.parse(storedUser));
    }
  }, []);

  const firstName = user?.full_name?.split(" ")[0] || "User";

  const [totalAlerts, setTotalAlerts] = useState(0);

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

  const summaryCards = scanData
    ? [
        { label: "Total", value: scanData.summary_boxes?.Total || 0, color: "neutral" },
        { label: "Critical", value: scanData.summary_boxes?.Critical || 0, color: "critical" },
        { label: "High", value: scanData.summary_boxes?.High || 0, color: "high" },
        { label: "Medium", value: scanData.summary_boxes?.Medium || 0, color: "medium" },
        { label: "Low", value: scanData.summary_boxes?.Low || 0, color: "low" },
      ]
    : [];

  const categories = scanData?.category_breakdown || [];

  const categoryChartData = {
    labels: categories.map((item) => item.display_label),
    datasets: [
      {
        label: "Vulnerabilities",
        data: categories.map((item) => item.count),
        backgroundColor: "#3b82f6",
        borderRadius: 10,
        maxBarThickness: 18,
        barPercentage: 0.7,
        categoryPercentage: 0.7,
      },
    ],
  };
  
  const categoryChartOptions = {
    indexAxis: "y",
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        enabled: true,
        backgroundColor: "rgba(15, 32, 66, 0.95)",
        titleColor: "#ffffff",
        bodyColor: "#eaf2ff",
        borderColor: "#3b82f6",
        borderWidth: 1,
        cornerRadius: 10,
        padding: 12,
        displayColors: true,
        titleFont: {
          size: 14,
          weight: "700",
        },
        bodyFont: {
          size: 13,
        },
        callbacks: {
          label: function (context) {
            return ` Vulnerabilities: ${context.raw}`;
          },
        },
      },
    },
    scales: {
      x: {
        beginAtZero: true,
        ticks: {
          precision: 0,
          stepSize: 1,
          color: "#7a8ca8",
          font: {
            size: 12,
          },
        },
        grid: {
          color: "#eef2f8",
        },
        border: {
          display: false,
        },
      },
      y: {
        grid: { display: false },
        ticks: {
          color: "#0f2042",
          padding: 12,
          font: {
            size: window.innerWidth <= 600 ? 9 : 13,
            weight: "600",
          },
          callback: function (value) {
            const label = this.getLabelForValue(value);
            
            if (window.innerWidth <= 600) {
              if (label.includes("/")) {
                return label.split("/").map((part) => part.trim());
              }
              
              const words = label.split(" ");
              if (words.length >= 2) {
                const mid = Math.ceil(words.length / 2);
                return [
                  words.slice(0, mid).join(" "),
                  words.slice(mid).join(" "),
                ];
              }
            }
            
            return label;
          },
        },
        border: {
          display: false,
        },
      },
    },
  };

  const findings = scanData?.findings || [];

  const filteredFindings = findings.filter((item) => {
    const severityMatch =
      filters.severity === "all" ||
      (item.cvss_severity || "").toLowerCase() === filters.severity.toLowerCase();
    
    const endpointMatch =
      !filters.endpoint ||
      (item.endpoint || "").toLowerCase().includes(filters.endpoint.toLowerCase());
    
    const statusMatch =
      filters.status === "all" ||
      (item.status || "").toLowerCase() === filters.status.toLowerCase();
      
    return severityMatch && endpointMatch && statusMatch;
  });

  const toggleFinding = (id) => {
    setOpenIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const showToast = (message) => {
  setToastMessage(message);
  setTimeout(() => {
    setToastMessage("");
  }, 2200);
};
   
  const handleDownloadPdf = () => {
    if (!scanData?.scan?.scan_id) {
      showToast("No scan available to export.");
      return;
    }
    
    showToast("Downloading PDF report.");
    
    const link = document.createElement("a");
    link.href = `http://127.0.0.1:5000/api/scans/${scanData.scan.scan_id}/export-pdf`;
    link.download = `scan_${scanData.scan.scan_id}_report.pdf`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilters((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const severityChipClass = (value) => {
    if (value === "Critical") return "chip chip-red";
    if (value === "High") return "chip chip-yellow";
    if (value === "Medium") return "chip chip-blue";
    if (value === "Low") return "chip chip-green";
    return "chip chip-purple";
  };



  return (
    <div className="sg-dashboard-shell">
    {toastMessage && (
      <div className="sg-results-toast">
        {toastMessage}
      </div>
    )}
      {isMobile && menuOpen && (
        <div className="sg-mobile-overlay" onClick={() => setMenuOpen(false)} />
      )}
      <aside className={`sg-dashboard-sidebar ${menuOpen ? "open" : ""}`}>
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
              onClick={() => navigate("/dashboard")}
            >
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

            <div className="sg-sidebar-item active">
              <span className="sg-sidebar-menu-icon">
                <SidebarIcon type="results" />
              </span>
              <span>Results</span>
            </div>

            <div
              className="sg-sidebar-item"
              onClick={() => navigate("/history")}
            >
              <span className="sg-sidebar-menu-icon">
                <SidebarIcon type="history" />
              </span>
              <span>History</span>
            </div>

            <div
              className="sg-sidebar-item"
              onClick={() => navigate("/alerts")}
            >
              <span className="sg-sidebar-menu-icon">
                <SidebarIcon type="alerts" />
              </span>
              <span>Alerts</span>
              {totalAlerts > 0 && (
                <span className="sg-results-alert-badge">{totalAlerts}</span>
              )}
            </div>

            <div className="sg-sidebar-separator" />

            <div
              className="sg-sidebar-item"
              onClick={() => navigate("/settings")}
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
            {isMobile && (
              <button
                className="sg-mobile-icon-btn"
                onClick={() => setMenuOpen(true)}
              >
                 ☰
              </button>
            )}

            <div>
              <div className="sg-results-page-title">Scan Results</div>
              <div className="sg-dashboard-sub">
                {isMobile ? "Latest scan overview" : `Welcome, ${firstName}`}
              </div>
            </div>
          </div> 

          <div className="sg-dashboard-actions">
            <input
              className="sg-dashboard-search"
              placeholder="Search endpoint..."
              value={filters.endpoint}
              onChange={(e) =>
                setFilters((prev) => ({ ...prev, endpoint: e.target.value }))
              }
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

        {!scanData ? (
          <div className="card sg-results-wireframe-card">
            <div
              style={{
                minHeight: "420px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                flexDirection: "column",
                gap: "14px",
                textAlign: "center",
              }}
            >
              <div style={{ fontSize: "22px", fontWeight: "700", color: "#0f2042" }}>
                No scan results yet
              </div>
              
              <div style={{ fontSize: "14px", color: "#7a8ca8", maxWidth: "420px" }}>
                Run your first scan to see vulnerabilities, CVSS scores, and reports here.
              </div>
              
              <button
                className="sg-dashboard-scan-btn"
                onClick={() => setOpenScan(true)}
              >
                ⚙ New Scan
              </button>
            </div>
          </div>
        ) : (
          <div className="card sg-results-wireframe-card">
          <div className="sg-results-wireframe-top">
            <div>
              <div className="sg-results-section-title">Latest Scan Results</div>
              <div className="sg-results-header-row">
  <div className="sg-results-meta-line sg-results-meta-line-desktop">
    <strong>{scanData?.scan?.target_url}</strong>
    <span>• Date: {scanData?.scan?.display_date || "—"}</span>
    <span>• Duration: {scanData?.scan?.duration || "—"}</span>
  </div>

  <button
    className="sg-results-soft-btn sg-download-btn"
    onClick={handleDownloadPdf}
  >
    ↓ Download PDF
  </button>
</div>
              <div className="sg-results-overview-text">
                Overview of detected vulnerabilities, CVSS score, ML prediction, and final risk severity
              </div>
            </div>
          </div>

          <div className="sg-results-summary-strip">
            {summaryCards.map((item) => (
              <div
                key={item.label}
                className={`sg-results-summary-box ${item.color}`}
              >
                <div className="sg-results-summary-label">
                  {isMobile ? item.label.replace("Critical", "Critical").replace("Medium", "Medium") : item.label}
                </div>
                <div className="sg-results-summary-number">{item.value}</div>
              </div>
            ))}
          </div>

          <div className="sg-results-two-cards">
            <div className={`card sg-results-mini-card ${
              scanData?.cvss_panel?.severity === "Critical"
                ? "risk-card-critical"
                : scanData?.cvss_panel?.severity === "High"
                ? "risk-card-high"
                : scanData?.cvss_panel?.severity === "Medium"
                ? "risk-card-medium"
                : "risk-card-low"
            }`}>
              <div className="sg-results-mini-title">CVSS Score</div>

              <div className="sg-results-big-risk-row">
                <div
                  className={`sg-results-big-risk-number ${
                    scanData?.cvss_panel?.severity === "Critical"
                      ? "critical"
                      : scanData?.cvss_panel?.severity === "High"
                      ? "high"
                      : scanData?.cvss_panel?.severity === "Medium"
                      ? "medium"
                      : "low"
                  }`}
                >
                  {scanData?.cvss_panel?.score || 0}</div>
                <span className={severityChipClass(scanData?.cvss_panel?.severity || "Low")}>
                    {scanData?.cvss_panel?.severity || "Low"}
                </span>
              </div>

              <div className="sg-results-mini-text">
                {scanData?.cvss_panel?.score >= 7
                  ? "High overall risk detected in the latest security assessment."
                  : scanData?.cvss_panel?.score >= 4
                  ? "Moderate risk detected. Review recommended."
                  : "Low risk detected. No critical issues found."}
              </div>

              <div className="sg-results-breakdown-box">
                <div className="sg-results-breakdown-title">CVSS Breakdown</div>

                <div className="sg-results-breakdown-row">
                  <span className="sg-low">0.1 – 3.9</span>
                  <span>Low</span>
                </div>
                <div className="sg-results-breakdown-row">
                  <span className="sg-medium">4.0 – 6.9</span>
                  <span>Medium</span>
                </div>
                <div className="sg-results-breakdown-row">
                  <span className="sg-high">7.0 – 8.9</span>
                  <span>High</span>
                </div>
                <div className="sg-results-breakdown-row">
                  <span className="sg-critical">9.0 – 10.0</span>
                  <span>Critical</span>
                </div>
              </div>
            </div>

            <div className={`card sg-results-mini-card ${
              scanData?.ml_panel?.severity === "Critical"
                ? "risk-card-critical"
                : scanData?.ml_panel?.severity === "High"
                ? "risk-card-high"
                : scanData?.ml_panel?.severity === "Medium"
                ? "risk-card-medium"
                : "risk-card-low"
            }`}>
              <div className="sg-results-mini-title">ML Prediction Severity</div>

              <div className="sg-results-big-risk-row">
                <div
                  className={`sg-results-big-risk-word ${
                    scanData?.ml_panel?.severity === "Critical"
                      ? "critical"
                      : scanData?.ml_panel?.severity === "High"
                      ? "high"
                      : scanData?.ml_panel?.severity === "Medium"
                      ? "medium"
                    : "low"
                }`}
              >
                {scanData?.ml_panel?.severity || "Low"}
                </div>
                
                <span
                  className={
                    scanData?.ml_panel?.severity === "Critical"
                      ? "chip chip-red"
                      : scanData?.ml_panel?.severity === "High"
                      ? "chip chip-yellow"
                      : scanData?.ml_panel?.severity === "Medium"
                      ? "chip chip-blue"
                      : "chip chip-green"
                  }
                >
                  {scanData?.ml_panel?.severity === "Critical"
                    ? "High Risk"
                    : scanData?.ml_panel?.severity === "High"
                    ? "Elevated Risk"
                    : scanData?.ml_panel?.severity === "Medium"
                    ? "Moderate Risk"
                    : "Low Risk"}
                </span>
              </div>

              <div className="sg-results-mini-text">
                {scanData?.ml_panel?.severity === "Critical"
                  ? "High likelihood of exploitation detected."
                  : scanData?.ml_panel?.severity === "High"
                  ? "Potential risk detected by ML model."
                  : scanData?.ml_panel?.severity === "Medium"
                  ? "Moderate behaviour detected."
                  : "Low risk behaviour detected."}
              </div>
            </div>
          </div>

          <div className="card sg-results-category-card">
            <div className="sg-results-mini-title">Vulnerabilities by Category</div>
            
           <div
             style={{
               height: "210px",
               marginTop: "12px",
               position: "relative",
               overflow: "hidden",
               width: "100%",
             }}
            >
              <Bar key={JSON.stringify(categories)} data={categoryChartData} options={categoryChartOptions} />
            </div>
            
            <div className="sg-results-foot-note">
              Only the main categories are shown here.
            </div>
          </div>

          <div className="sg-results-findings-title">Detailed Findings</div>

          <div className="sg-results-filter-panel">
            <div>
              <label className="sg-label">Final Risk Severity</label>
              <select
                className="sg-input sg-mobile-native-select"
                name="severity"
                value={filters.severity}
                onChange={handleFilterChange}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
            </select>
            </div>

            <div>
              <label className="sg-label">Endpoint</label>
              <input
                className="sg-input"
                name="endpoint"
                value={filters.endpoint}
                onChange={handleFilterChange}
                placeholder="/api/v1/..."
              />
            </div>

            <div>
              <label className="sg-label">Status</label>
              <select
                className="sg-input sg-mobile-native-select"
                name="status"
                value={filters.status}
                onChange={handleFilterChange}
              >
                <option value="all">All Status</option>
                <option value="open">Open</option>
                <option value="investigating">Investigating</option>
                <option value="mitigated">Mitigated</option>
                <option value="closed">Closed</option>
              </select>
            </div>
          </div>

          <div className="sg-results-findings-list-2">
            {filteredFindings.map((item) => {
              const isOpen = openIds.includes(item.id);

              return (
                <div key={item.id} className="sg-findings-wire-card">
                  <div
                    className="sg-findings-wire-head"
                    onClick={() => toggleFinding(item.id)}
                  >
                    <div className="sg-findings-wire-left">
                      <div className="sg-findings-wire-name">{item.vuln_name}</div>
                      <div className="sg-findings-wire-endpoint">
                        {item.endpoint}
                      </div>
                    </div>

                    <div className="sg-findings-wire-chips">
                      <span className={severityChipClass(item.cvss_severity)}>
                        CVSS Severity: {item.cvss_severity}
                      </span>
                      
                      <span className={severityChipClass(item.ml_severity)}>
                        ML Severity: {item.ml_severity}
                      </span>
                      
                      <span className={severityChipClass(item.severity)}>
                        Final Risk: {item.severity}
                      </span>
                      <span className={`sg-findings-chevron ${isOpen ? "open" : ""}`}>
                        ⌄
                      </span>
                    </div>
                  </div>

                  <div className="sg-findings-wire-stats">
                    <div className="sg-findings-stat-inline">
                      <span className="sg-findings-stat-label">CVSS</span>
                      <span className="sg-findings-stat-value">{item.cvss_score}</span>
                    </div>

                    <div className="sg-findings-stat-inline">
                      <span className="sg-findings-stat-label">Status</span>
                      <span className="sg-findings-stat-text">{item.status}</span>
                    </div>

                    <div className="sg-findings-stat-inline">
                      <span className="sg-findings-stat-label">Detected</span>
                      <span className="sg-findings-stat-text">{item.detected_time_ago}</span>
                    </div>
                  </div>

                  {isOpen && (
                    <div className="sg-findings-wire-details">
                      <div className="sg-findings-details-two-col">
                        <div className="sg-findings-detail-item">
                          <div className="sg-summary-label">Method</div>
                          <div className="sg-findings-detail-value">{item.method}</div>
                        </div>

                        <div className="sg-findings-detail-item">
                          <div className="sg-summary-label">Affected Parameter</div>
                          <div className="sg-findings-detail-value">{item.affected_parameter}</div>
                        </div>
                      </div>

                      <div className="sg-findings-detail-item">
                        <div className="sg-summary-label">Payload / Example</div>
                        <div className="sg-findings-mobile-pill">{item.payload_example}</div>
                      </div>

                      <div className="sg-findings-recommendation-block">
                        <div className="sg-summary-label">Recommendations</div>
                        <ul className="sg-findings-steps">
                          {(Array.isArray(item.recommendation)
                            ? item.recommendation
                            : [item.recommendation]
                          ).map((rec, index) => (
                            <li key={index}>{rec}</li>
                          ))}
                        </ul>
                      </div>

                      <div className="sg-findings-recommendation-block">
                        <div className="sg-summary-label">Mitigation Steps</div>
                          <ul className="sg-findings-steps">
                            {(item.mitigation_steps || []).map((step, index) => (
                              <li key={index}>{step}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    )}
                </div>
              );
            })}
          </div>
        </div>
        )}
      </main>

      <NewScan isOpen={openScan} onClose={() => setOpenScan(false)} />
    </div>
  );
}

export default Results;