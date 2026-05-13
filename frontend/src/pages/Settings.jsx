import { useEffect, useState } from "react";
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

function Settings() {
  const navigate = useNavigate();
  const handleLogout = async () => {
    const user_id = localStorage.getItem("user_id");
    const session_token = localStorage.getItem("session_token");
    
    try {
      await fetch("http://127.0.0.1:5000/api/auth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_id, session_token }),
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
  const [toast, setToast] = useState("");
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [user, setUser] = useState(null);
  const [settingsData, setSettingsData] = useState(null);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [activityLogs, setActivityLogs] = useState([]);
  const [sessionsData, setSessionsData] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");

  const firstName = user?.full_name?.split(" ")[0] || "User";

  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [company, setCompany] = useState("");

  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [autoScan, setAutoScan] = useState(true);
  const [autoDownload, setAutoDownload] = useState(false);
  const [deleteOldScans, setDeleteOldScans] = useState(false);

  const [emailAlerts, setEmailAlerts] = useState(true);
  const [scanCompleteAlerts, setScanCompleteAlerts] = useState(true);
  const [realTimeNotifications, setRealTimeNotifications] = useState(false);
  const [criticalAlerts, setCriticalAlerts] = useState(true);

  const [summaryReports, setSummaryReports] = useState("Weekly");
  const [apiKeyVisible, setApiKeyVisible] = useState(false);


  const [passwordMfaCode, setPasswordMfaCode] = useState(["", "", "", "", "", ""]);
  const [passwordMfaSeconds, setPasswordMfaSeconds] = useState(30);
  const [showClearHistoryModal, setShowClearHistoryModal] = useState(false);
  const [showDeleteAccountModal, setShowDeleteAccountModal] = useState(false);
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [showPasswordSuccessModal, setShowPasswordSuccessModal] = useState(false);
  const [showDeleteMfaModal, setShowDeleteMfaModal] = useState(false);
  const [showConfirmDeleteModal, setShowConfirmDeleteModal] = useState(false);
  const [showConfirmClearHistoryModal, setShowConfirmClearHistoryModal] = useState(false);
  const [showSessionsModal, setShowSessionsModal] = useState(false);
  const [mfaAction, setMfaAction] = useState(null);


  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [clearHistoryPassword, setClearHistoryPassword] = useState("");
  const [deleteAccountPassword, setDeleteAccountPassword] = useState("");
  const [deleteMfaCode, setDeleteMfaCode] = useState(["", "", "", "", "", ""]);
  const [deleteMfaSeconds, setDeleteMfaSeconds] = useState(30);
  const [passwordError, setPasswordError] = useState("");
  const [deleteMfaError, setDeleteMfaError] = useState("");
  const [apiKey, setApiKey] = useState("sk-sg-4f8a2b1c9d3e7f6a0b5c8d2e1f4a7b3c");

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
    
    const fetchSettings = async () => {
      try {
        const res = await fetch(`http://127.0.0.1:5000/api/settings?user_id=${user_id}`);
        const data = await res.json();
        
        if (res.ok) {
          setSettingsData(data);
          
          setFullName(data.account_details?.full_name || "");
          setEmail(data.account_details?.email || "");
          setCompany(data.account_details?.company_name || "");
          
          setMfaEnabled(data.security_session?.mfa_enabled || false);
          
          setAutoScan(data.scan_automation?.auto_scan || false);
          setSummaryReports(data.scan_automation?.summary_reports || "Weekly");
          setAutoDownload(data.scan_automation?.auto_download_report || false);
          setDeleteOldScans(data.scan_automation?.delete_old_scans || false);
          
          setEmailAlerts(data.notifications?.email_alerts || false);
          setScanCompleteAlerts(data.notifications?.email_scan_complete || false);
          setRealTimeNotifications(data.notifications?.real_time_notifications || false);
          setCriticalAlerts(data.notifications?.critical_vulnerability_alerts || false);
          
          setApiKey(data.api_integration?.api_key || "");
        }
      } catch (err) {
        console.error("Failed to fetch settings", err);
      }
    };
    
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
    
    const fetchActivityLogs = async () => {
      try {
        const res = await fetch(`http://127.0.0.1:5000/api/settings/activity-logs?user_id=${user_id}`);
        const data = await res.json();
        
        if (res.ok) {
          setActivityLogs(data.logs || []);
        }
      } catch (err) {
        console.error("Failed to fetch activity logs", err);
      }
    };
    
    fetchSettings();
    fetchAlertCount();
    fetchActivityLogs();
    
    const interval = setInterval(() => {
      fetchAlertCount();
      fetchActivityLogs();
    }, 3000);
    
    return () => clearInterval(interval);
  }, []);

  
    const showToast = (message, force = false) => {
      if (!force && settingsData && !realTimeNotifications) {
        return;
      }
      
      setToast(message);
      setTimeout(() => setToast(""), 2200);
    };

    useEffect(() => {
      if (!showDeleteMfaModal) return;

      setDeleteMfaSeconds(30);

      const timer = setInterval(() => {
        setDeleteMfaSeconds((prev) => {
          if (prev <= 1) return 30;
          return prev - 1;
        });
      }, 1000);

      return () => clearInterval(timer);
    }, [showDeleteMfaModal]);

    



  const isStrongPassword = (value) => {
    return (
      value.length >= 8 &&
      /[A-Za-z]/.test(value) &&
      /\d/.test(value) &&
      /[^A-Za-z0-9]/.test(value)
    );
  };

  const passwordStrength = () => {
    if (!newPassword) return { label: "", level: 0 };
    let score = 0;
    if (newPassword.length >= 8) score++;
    if (/[A-Z]/.test(newPassword) || /[a-z]/.test(newPassword)) score++;
    if (/\d/.test(newPassword)) score++;
    if (/[^A-Za-z0-9]/.test(newPassword)) score++;

    if (score <= 1) return { label: "Weak", level: 1 };
    if (score === 2) return { label: "Fair", level: 2 };
    if (score === 3) return { label: "Good", level: 3 };
    return { label: "Strong - excellent security", level: 4 };
  };

  const strength = passwordStrength();

  const maskEmail = (email) => {
    const [name, domain] = (email || "").split("@");
    if (!name || !domain) return email;
    return `${name.slice(0, 3)}***@${domain}`;
  };
 
  const handleToggleMfa = async () => {
    const user_id = localStorage.getItem("user_id");
    const newValue = !mfaEnabled;
    
    try {
      const res = await fetch("http://127.0.0.1:5000/api/settings/mfa", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user_id,
          mfa_enabled: newValue,
        }),
      });
      
      const data = await res.json();
      
      if (res.ok) {
        setMfaEnabled(newValue);
        showToast(data.message || "MFA updated successfully");
      } else {
        showToast(data.error || "Failed to update MFA", true);
      }
    } catch (err) {
      showToast("Failed to update MFA", true);
    }
  };

  const handleSaveChanges = async () => {
    const user_id = localStorage.getItem("user_id");
    if (!user_id) return;
    
    try {
      const accountRes = await fetch("http://127.0.0.1:5000/api/settings/account", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user_id,
          full_name: fullName,
          company_name: company,
          email,
        }),
      });
      
      const prefRes = await fetch("http://127.0.0.1:5000/api/settings/preferences", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user_id,
          auto_scan: autoScan,
          summary_reports: summaryReports,
          auto_download_report: autoDownload,
          delete_old_scans: deleteOldScans,
          email_alerts: emailAlerts,
          email_scan_complete: scanCompleteAlerts,
          real_time_notifications: realTimeNotifications,
          critical_vulnerability_alerts: criticalAlerts,
        }),
      });
      
      if (accountRes.ok && prefRes.ok) {
        const updatedUser = JSON.parse(localStorage.getItem("user") || "{}");
        updatedUser.full_name = fullName;
        updatedUser.company_name = company;
        updatedUser.email = email;
        localStorage.setItem("user", JSON.stringify(updatedUser));
        localStorage.setItem("settings_auto_download", JSON.stringify(autoDownload));
        setUser(updatedUser);
        showToast("Settings saved successfully", true);
      } else {
        showToast("Failed to save settings", true);
      }
    } catch (err) {
      showToast("Failed to save settings", true);
    }
  };

  const handleUpdatePassword = async () => {
    setPasswordError("");
    if (!currentPassword || !newPassword || !confirmPassword) {
      setPasswordError("Please fill all password fields.");
      return;
    }
    
    if (!isStrongPassword(newPassword)) {
      setPasswordError(
        "Use at least 8 characters with a mix of letters, numbers, and symbols."
      );
      return;
    }
    
    if (newPassword !== confirmPassword) {
      setPasswordError("Passwords do not match.");
      return;
    }
    
    const user_id = localStorage.getItem("user_id");
    
    try {
      const res = await fetch("http://127.0.0.1:5000/api/settings/password", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user_id,
          current_password: currentPassword,
          new_password: newPassword,
        }),
      });
      
      const data = await res.json();
      
      if (!res.ok) {
        setPasswordError(data.error || "Failed to update password");
        return;
      }
      
      setShowPasswordModal(false);
      setShowPasswordSuccessModal(true);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setPasswordError("");
      showToast("Password updated successfully");
    } catch (err) {
      setPasswordError("Failed to update password");
    }
  };


  const handleDeleteAccountContinue = () => {
    if (!deleteAccountPassword) return;

    setDeleteMfaError("");
    setShowDeleteAccountModal(false);
    setMfaAction("deleteAccount");
    setShowDeleteMfaModal(true);
  };

  const handleDeleteMfaChange = (index, value) => {
    if (!/^\d?$/.test(value)) return;

    const updated = [...deleteMfaCode];
    updated[index] = value;
    setDeleteMfaCode(updated);

    if (value && index < 5) {
      const next = document.getElementById(`delete-mfa-${index + 1}`);
      if (next) next.focus();
    }

    const filledCode = updated.join("");
    if (filledCode.length === 6 && !updated.includes("")) {
      setTimeout(() => {
        handleVerifyDeleteMfa(updated.join(""));
      }, 150);
    }
  };

  const handleVerifyDeleteMfa = async (codeFromAutoFill) => {
    const enteredCode = codeFromAutoFill || deleteMfaCode.join("");
    const user_id = localStorage.getItem("user_id");
    if (enteredCode.length !== 6) {
      setDeleteMfaError("Please enter the 6-digit code.");
      return;
    }
    
    try {
      let endpoint = "";
      let body = {};
      
      if (mfaAction === "clearHistory") {
        endpoint = "http://127.0.0.1:5000/api/settings/clear-scan-history/start";
        body = {
          user_id,
          password: clearHistoryPassword,
          mfa_code: enteredCode,
        };
      } else if (mfaAction === "deleteAccount") {
        endpoint = "http://127.0.0.1:5000/api/settings/delete-account/start";
        body = {
          user_id,
          password: deleteAccountPassword,
          mfa_code: enteredCode,
        };
      } else {
        setDeleteMfaError("Unknown MFA action.");
        return;
      }
      
      const res = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      });
      
      const data = await res.json();
      
      if (!res.ok) {
        setDeleteMfaError(data.error || "Invalid or expired authenticator code.");
        return;
      }
      
      setDeleteMfaError("");
      setShowDeleteMfaModal(false);
      setDeleteMfaCode(["", "", "", "", "", ""]);
      
      if (mfaAction === "deleteAccount") {
        setShowConfirmDeleteModal(true);
      } else if (mfaAction === "clearHistory") {
        setShowConfirmClearHistoryModal(true);
      }
    } catch (err) {
      setDeleteMfaError("Verification failed. Please try again.");
    }
  };

  const handleConfirmDelete = async () => {
    const user_id = localStorage.getItem("user_id");
    
    try {
      const res = await fetch("http://127.0.0.1:5000/api/settings/delete-account/confirm", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_id }),
      });
      
      const data = await res.json();
      
      if (res.ok) {
        localStorage.removeItem("user");
        localStorage.removeItem("user_id");
        
        setShowConfirmDeleteModal(false);
        setDeleteAccountPassword("");
        setDeleteMfaCode(["", "", "", "", "", ""]);
        
        navigate("/register");
      } else {
        setToast(data.error || "Failed to delete account", true);
      }
    } catch (err) {
      setToast("Failed to delete account", true);
    }
  };

  const handleOpenSessions = async () => {
    const user_id = localStorage.getItem("user_id");
    const session_token = localStorage.getItem("session_token");
    
    try {
      const res = await fetch(
        `http://127.0.0.1:5000/api/settings/manage-sessions?user_id=${user_id}&session_token=${session_token || ""}`
      );
      const data = await res.json();
      
      if (res.ok) {
        setSessionsData(data);
        setSettingsData((prev) => ({
          ...prev,
          security_session: {
            ...prev?.security_session,
            active_sessions: data.active_sessions_count,
          },
        }));
        setShowSessionsModal(true);
      } else {
        showToast(data.error || "Failed to load sessions", true);
      }
    } catch (err) {
      showToast("Failed to load sessions", true);
    }
  };

  const handleCopyApiKey = async () => {
    try {
      await navigator.clipboard.writeText(apiKey);
      showToast("API key copied", true);
    } catch {
      showToast("API key copied", true);
    }
  };

  const handleRegenerateKey = async () => {
    const user_id = localStorage.getItem("user_id");
    
    try {
      const res = await fetch("http://127.0.0.1:5000/api/settings/api-key/regenerate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_id }),
      });
      const data = await res.json();
      
      if (res.ok) {
        setApiKey(data.api_key || "");
        showToast("New API key generated", true);
      } else {
        showToast(data.error || "Failed to regenerate API key", true);
      }
    } catch (err) {
      showToast("Failed to regenerate API key", true);
    }
  };

  const handleSettingsSearch = (e) => {
  if (e.key !== "Enter") return;

  const query = searchQuery.toLowerCase().trim();

  const sectionMap = {
    account: "account-section",
    profile: "account-section",
    password: "account-section",
    mfa: "security-section",
    session: "security-section",
    security: "security-section",
    scan: "automation-section",
    automation: "automation-section",
    notification: "notification-section",
    email: "notification-section",
    activity: "activity-section",
    log: "activity-section",
    api: "api-section",
    key: "api-section",
    delete: "data-section",
    export: "data-section",
  };

  const matchedKey = Object.keys(sectionMap).find((key) =>
    query.includes(key)
  );

  if (!matchedKey) {
    showToast("No matching settings section found", true);
    return;
  }

  const section = document.getElementById(sectionMap[matchedKey]);
  if (section) {
    section.scrollIntoView({ behavior: "smooth", block: "start" });
  }
};

  return (
    <>
    <div className="sg-dashboard-shell sg-settings-shell">
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

            <div className="sg-sidebar-item active">
              <span className="sg-sidebar-menu-icon">
                <SidebarIcon type="settings" />
              </span>
              <span>Settings</span>
            </div>
          </div>

          <div className="sg-sidebar-user">
            <div className="sg-sidebar-user-left">
              <div className="sg-sidebar-avatar">{firstName.charAt(0).toUpperCase()}</div>
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

      <main className="sg-dashboard-main sg-settings-main">
        <div className="sg-dashboard-topbar">
          <div className="sg-mobile-topbar-left">
            <button
              className="sg-mobile-icon-btn"
              onClick={() => setMobileMenuOpen(true)}
            >
              ☰
            </button>

            <div>
              <div className="sg-dashboard-title">Settings</div>
              <div className="sg-dashboard-sub">Welcome, {firstName}</div>
            </div>
          </div>

          <div className="sg-dashboard-actions">
            <input
              className="sg-dashboard-search"
              placeholder="Search..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={handleSettingsSearch}
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

        <div className="sg-settings-stack">
          <section id="account-section" className="card sg-settings-card">
            <div className="sg-settings-card-head">
              <div className="sg-settings-icon blue">👤</div>
              <div className="sg-settings-card-title">Account Details</div>
            </div>

            <div className="sg-settings-grid-two">
              <div>
                <label className="sg-label">Full Name</label>
                <input
                  className="sg-input"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                />
              </div>

              <div>
                <label className="sg-label">Company Name</label>
                <input
                  className="sg-input"
                  value={company}
                  onChange={(e) => setCompany(e.target.value)}
                />
              </div>

              <div>
                <label className="sg-label">Email Address</label>
                <input
                  className="sg-input"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>

              <div>
                <label className="sg-label">Change Password</label>
                <button
                  className="sg-settings-wide-btn primary"
                  onClick={() => setShowPasswordModal(true)}
                >
                  Update Password
                </button>
              </div>
            </div>
          </section>

          <section id="security-section" className="card sg-settings-card">
            <div className="sg-settings-card-head">
              <div className="sg-settings-icon blue">🔐</div>
              <div className="sg-settings-card-title">Security & Session</div>
            </div>

            <div className="sg-settings-row-toggle">
              <div>
                <div className="sg-settings-item-title">Multi-Factor Authentication</div>
                <div className="sg-settings-item-sub">
                  Protect your account with a second verification step
                </div>
              </div>
              <button
                className={`sg-switch ${mfaEnabled ? "on" : ""}`}
                onClick={handleToggleMfa}
              >
                <span />
              </button>
            </div>

            <div className="sg-settings-field-block">
              <label className="sg-label">Last Login</label>
              <div className="sg-settings-readonly">
                {settingsData?.security_session?.last_login || "No login record"}
              </div>
            </div>

            <div className="sg-settings-field-block">
              <label className="sg-label">Active Sessions</label>
              <div className="sg-settings-readonly">
                {settingsData?.security_session?.active_sessions || 0} active sessions
              </div>
            </div>

            <button
              className="sg-settings-manage-btn"
              onClick={handleOpenSessions}
            >
              Manage Sessions
              </button>
          </section>

          <div className="sg-settings-two-col">
            <section id="automation-section" className="card sg-settings-card">
              <div className="sg-settings-card-head">
                <div className="sg-settings-icon blue">🔄</div>
                <div className="sg-settings-card-title">Scan & Automation Settings</div>
              </div>

              <div className="sg-settings-row-toggle">
                <div>
                  <div className="sg-settings-item-title">Auto-scan</div>
                  <div className="sg-settings-item-sub">Enable scheduled scans</div>
                </div>
                <button
                  className={`sg-switch ${autoScan ? "on" : ""}`}
                  onClick={() => setAutoScan(!autoScan)}
                >
                  <span />
                </button>
              </div>

              <div className="sg-settings-field-block">
                <label className="sg-label">Summary Reports</label>
                <select
                  className="sg-input"
                  value={summaryReports}
                  onChange={(e) => setSummaryReports(e.target.value)}
                >
                  <option>Weekly</option>
                  <option>Monthly</option>
                </select>
              </div>

              <div className="sg-settings-row-toggle">
                <div>
                  <div className="sg-settings-item-title">Auto-download after scan</div>
                  <div className="sg-settings-item-sub">Download report automatically</div>
                </div>
                <button
                  className={`sg-switch ${autoDownload ? "on" : ""}`}
                  onClick={() => setAutoDownload(!autoDownload)}
                >
                  <span />
                </button>
              </div>

              <div className="sg-settings-row-toggle">
                <div>
                  <div className="sg-settings-item-title">Delete old scans automatically</div>
                  <div className="sg-settings-item-sub">Remove older saved scans</div>
                </div>
                <button
                  className={`sg-switch ${deleteOldScans ? "on" : ""}`}
                  onClick={() => setDeleteOldScans(!deleteOldScans)}
                >
                  <span />
                </button>
              </div>

              <div className="sg-settings-field-block">
                <label className="sg-label">Alert Threshold</label>
                <div className="sg-settings-readonly">
                  Trigger alert when CVSS &gt; 7.0 or ML Severity is High/Critical
                </div>
              </div>
            </section>

            <section id="notification-section" className="card sg-settings-card">
              <div className="sg-settings-card-head">
                <div className="sg-settings-icon blue">🔔</div>
                <div className="sg-settings-card-title">Notifications</div>
              </div>

              <div className="sg-settings-row-toggle">
                <div>
                  <div className="sg-settings-item-title">Email alerts</div>
                  <div className="sg-settings-item-sub">Turn general alerts on or off</div>
                </div>
                <button
                  className={`sg-switch ${emailAlerts ? "on" : ""}`}
                  onClick={() => setEmailAlerts(!emailAlerts)}
                >
                  <span />
                </button>
              </div>

              <div className="sg-settings-row-toggle">
                <div>
                  <div className="sg-settings-item-title">Email alerts on scan completion</div>
                  <div className="sg-settings-item-sub">Get notified when a scan finishes</div>
                </div>
                <button
                  className={`sg-switch ${scanCompleteAlerts ? "on" : ""}`}
                  onClick={() => setScanCompleteAlerts(!scanCompleteAlerts)}
                >
                  <span />
                </button>
              </div>

              <div className="sg-settings-row-toggle">
                <div>
                  <div className="sg-settings-item-title">Real-time notifications</div>
                  <div className="sg-settings-item-sub">Instant in-app notifications</div>
                </div>
                <button
                  className={`sg-switch ${realTimeNotifications ? "on" : ""}`}
                  onClick={() => setRealTimeNotifications(!realTimeNotifications)}
                >
                  <span />
                </button>
              </div>

              <div className="sg-settings-row-toggle">
                <div>
                  <div className="sg-settings-item-title">Critical vulnerability alerts</div>
                  <div className="sg-settings-item-sub">Instant email for severe issues</div>
                </div>
                <button
                  className={`sg-switch ${criticalAlerts ? "on" : ""}`}
                  onClick={() => setCriticalAlerts(!criticalAlerts)}
                >
                  <span />
                </button>
              </div>
            </section>
          </div>

          <section id="activity-section" className="card sg-settings-card">
            <div className="sg-settings-card-head">
              <div className="sg-settings-icon blue">🕘</div>
              <div className="sg-settings-card-title">Activity Logs</div>
            </div>

            <div className="sg-settings-log-list">
              {activityLogs.map((log) => (
                <div key={log.id} className="sg-settings-log-item">
                  <div className="sg-settings-log-title">{log.action}</div>
                  <div className="sg-settings-log-sub">
                    {log.description} • {log.created_at}
                  </div>
                </div>
              ))}
            </div>
          </section>

          <div className="sg-settings-two-col">
            <section id="api-section" className="card sg-settings-card">
              <div className="sg-settings-card-head">
                <div className="sg-settings-icon blue">🗝</div>
                <div className="sg-settings-card-title">API Integration</div>
              </div>

              <div className="sg-settings-field-block">
                <label className="sg-label">API Key</label>
                <div className="sg-settings-api-row">
                  <input
                    className="sg-input"
                    value={apiKeyVisible ? apiKey : "••••••••••••••••••••••••"}
                    readOnly
                  />
                  <button className="sg-settings-small-btn" onClick={() => setApiKeyVisible(!apiKeyVisible)}>
                    {apiKeyVisible ? "Hide" : "Show"}
                  </button>
                  <button className="sg-settings-small-btn" onClick={handleCopyApiKey}>
                    Copy
                  </button>
                </div>
              </div>

              <button className="sg-settings-manage-btn" onClick={handleRegenerateKey}>
                Regenerate Key
              </button>
            </section>

            <section id="data-section" className="card sg-settings-card">
              <div className="sg-settings-card-head">
                <div className="sg-settings-icon red">🗃</div>
                <div className="sg-settings-card-title">Data & Account Management</div>
              </div>

              <div className="sg-settings-field-block">
                <label className="sg-label">Export Format</label>
                <div className="sg-settings-readonly">PDF</div>
              </div>

              <div className="sg-settings-danger-grid">
                <button
                  className="sg-settings-danger-btn orange"
                  onClick={() => setShowClearHistoryModal(true)}
                >
                  Clear Scan History
                </button>

                <button
                  className="sg-settings-danger-btn red"
                  onClick={() => setShowDeleteAccountModal(true)}
                >
                  Delete Account
                </button>
              </div>
            </section>
          </div>

          <button className="sg-settings-save-btn" onClick={handleSaveChanges}>
            Save Changes
          </button>
        </div>
      </main>

      {showPasswordModal && (
        <div className="sg-settings-modal-overlay">
          <div className="sg-settings-modal">
            <button className="sg-settings-modal-close" onClick={() => setShowPasswordModal(false)}>
              ×
            </button>

            <div className="sg-settings-modal-head">
              <div className="sg-settings-modal-icon blue">🔒</div>
              <div>
                <div className="sg-settings-modal-title">Update Password</div>
                <div className="sg-settings-modal-sub">SENTINEL GATE</div>
              </div>
            </div>

            <div className="sg-settings-field-block">
              <label className="sg-label">Current Password</label>
              <input
                className="sg-input"
                type="password"
                placeholder="Enter current password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
              />
            </div>

            <div className="sg-settings-field-block">
              <label className="sg-label">New Password</label>
              <input
                className="sg-input"
                type="password"
                placeholder="Enter new password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </div>

            {newPassword && (
              <div className="sg-settings-strength-wrap">
                <div className="sg-settings-strength-bars">
                  <span className={strength.level >= 1 ? "active" : ""} />
                  <span className={strength.level >= 2 ? "active" : ""} />
                  <span className={strength.level >= 3 ? "active" : ""} />
                  <span className={strength.level >= 4 ? "active" : ""} />
                </div>
                <div className="sg-settings-strength-text">{strength.label}</div>
              </div>
            )}

            <div className="sg-settings-field-block">
              <label className="sg-label">Confirm New Password</label>
              <input
                className="sg-input"
                type="password"
                placeholder="Confirm new password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
            </div>

            {confirmPassword && newPassword === confirmPassword && (
              <div className="sg-settings-match-text">✓ Passwords match</div>
            )}

            <div className="sg-settings-password-help">
              Use at least 8 characters with a mix of letters, numbers, and symbols
            </div>

            {passwordError && <div className="sg-error">{passwordError}</div>}

            <div className="sg-settings-modal-actions">
              <button className="sg-settings-modal-btn secondary" onClick={() => setShowPasswordModal(false)}>
                Cancel
              </button>
              <button className="sg-settings-modal-btn primary" onClick={handleUpdatePassword}>
                Update Password
              </button>
            </div>
          </div>
        </div>
      )}


      {showPasswordSuccessModal && (
        <div className="sg-settings-modal-overlay">
          <div className="sg-settings-modal success">
            <div className="sg-settings-success-icon">✓</div>
            <div className="sg-settings-success-text">Password updated successfully</div>
            <button
              className="sg-settings-modal-btn primary single"
              onClick={() => setShowPasswordSuccessModal(false)}
            >
              ← Done
            </button>
          </div>
        </div>
      )}

      {showClearHistoryModal && (
        <div className="sg-settings-modal-overlay">
          <div className="sg-settings-modal danger">
            <button className="sg-settings-modal-close" onClick={() => setShowClearHistoryModal(false)}>
              ×
            </button>

            <div className="sg-settings-danger-title">Clear Scan History</div>

            <div className="sg-settings-danger-box">
              <div className="sg-settings-danger-box-head">
                This will remove all saved scan records
              </div>
              <div className="sg-settings-danger-box-text">
                Your previous scan history will be permanently deleted. This action cannot be undone.
              </div>
            </div>

            <div className="sg-settings-field-block">
              <label className="sg-label">Enter Password</label>
              <input
                className="sg-input"
                type="password"
                placeholder="••••••••"
                value={clearHistoryPassword}
                onChange={(e) => setClearHistoryPassword(e.target.value)}
              />
            </div>

            <div className="sg-settings-modal-actions">
              <button className="sg-settings-modal-btn secondary" onClick={() => setShowClearHistoryModal(false)}>
                Cancel
              </button>
              <button
                className="sg-settings-modal-btn danger-btn"
                onClick={() => {
                  if (!clearHistoryPassword.trim()) {
                  showToast("Please enter your password", true);
                  return;
                }

                setShowClearHistoryModal(false);
                setMfaAction("clearHistory");
                setDeleteMfaError("");
                setDeleteMfaCode(["", "", "", "", "", ""]);
                setShowDeleteMfaModal(true);
              }}
            >
              Continue
            </button>
            </div>
          </div>
        </div>
      )}

      {showDeleteAccountModal && (
        <div className="sg-settings-modal-overlay">
          <div className="sg-settings-modal danger">
            <button className="sg-settings-modal-close" onClick={() => setShowDeleteAccountModal(false)}>
              ×
            </button>

            <div className="sg-settings-danger-title">Delete Account</div>

            <div className="sg-settings-danger-box">
              <div className="sg-settings-danger-box-head">This action is permanent</div>
              <div className="sg-settings-danger-box-text">
                Deleting your account will remove your profile, settings, scan history, and saved data.
              </div>
            </div>

            <div className="sg-settings-field-block">
              <label className="sg-label">Enter Password</label>
              <input
                className="sg-input"
                type="password"
                placeholder="••••••••"
                value={deleteAccountPassword}
                onChange={(e) => setDeleteAccountPassword(e.target.value)}
              />
            </div>

            <div className="sg-settings-modal-actions">
              <button className="sg-settings-modal-btn secondary" onClick={() => setShowDeleteAccountModal(false)}>
                Cancel
              </button>
              <button className="sg-settings-modal-btn danger-btn" onClick={handleDeleteAccountContinue}>
                Continue
              </button>
            </div>
          </div>
        </div>
      )}

      {showDeleteMfaModal && (
        <div className="sg-settings-modal-overlay">
          <div className="sg-settings-modal mfa">
            <button
              className="sg-settings-modal-close"
              onClick={() => {
                setShowDeleteMfaModal(false);
                setDeleteMfaCode(["", "", "", "", "", ""]);
                setDeleteMfaError("");
              }}
            >
              ×
            </button>

            <div className="sg-settings-mfa-icon-wrap">
              <div className="sg-settings-mfa-icon">🔐</div>
            </div>

            <div className="sg-settings-modal-title center">
              Multi-Factor Authentication
            </div>

            <div className="sg-settings-success-sub">
              Enter the current 6-digit code from Microsoft Authenticator for
              <br />
              <strong>{maskEmail(email)}</strong>
            </div>

            <div className="sg-settings-mfa-grid">
              {deleteMfaCode.map((digit, index) => (
                <input
                  key={index}
                  id={`delete-mfa-${index}`}
                  className="sg-settings-mfa-input"
                  type="text"
                  maxLength={1}
                  value={digit}
                  onChange={(e) => handleDeleteMfaChange(index, e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      handleVerifyDeleteMfa();
                    }

                    if (e.key === "Backspace" && !deleteMfaCode[index] && index > 0) {
                      const prev = document.getElementById(`delete-mfa-${index - 1}`);
                      if (prev) prev.focus();
                    }
                  }}
                />
              ))}
            </div>

            {deleteMfaError && <div className="sg-error">{deleteMfaError}</div>}

            <button
              className="sg-settings-modal-btn primary single full"
              onClick={() => handleVerifyDeleteMfa()}
            >
              Verify Code
            </button>

            <div className="sg-settings-mfa-help">
              Use the latest code shown in Microsoft Authenticator.
            </div>

            <div className="sg-settings-mfa-expiry">
              Code refreshes automatically in <strong>{deleteMfaSeconds}s</strong>
            </div>
          </div>
        </div>
      )}

    

      {showConfirmDeleteModal && (
        <div className="sg-settings-modal-overlay">
          <div className="sg-settings-modal success">
            <div className="sg-settings-success-icon red">🗑</div>
            <div className="sg-settings-modal-title center">Confirm Account Deletion</div>
            <div className="sg-settings-success-sub">
              MFA verified successfully. Are you sure you want to permanently delete your account?
            </div>
            <div className="sg-settings-modal-actions">
              <button className="sg-settings-modal-btn secondary" onClick={() => setShowConfirmDeleteModal(false)}>
                Cancel
              </button>
              <button className="sg-settings-modal-btn danger-btn" onClick={handleConfirmDelete}>
                Confirm Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {showConfirmClearHistoryModal && (
        <div className="sg-settings-modal-overlay"> 
        <div className="sg-settings-modal success">
        <div className="sg-settings-success-icon red">🗑</div>

        <div className="sg-settings-modal-title center">
        Confirm Clear History
        </div>

        <div className="sg-settings-success-sub">
        MFA verified successfully. Are you sure you want to clear all scan history?
        </div>
        <div className="sg-settings-modal-actions">
          <button
            className="sg-settings-modal-btn secondary"
            onClick={() => setShowConfirmClearHistoryModal(false)}
          >
            Cancel
          </button>
          <button
          className="sg-settings-modal-btn danger-btn"
          onClick={async () => {
            const user_id = localStorage.getItem("user_id");
            try {
              const res = await fetch("http://127.0.0.1:5000/api/settings/clear-scan-history/confirm", {
                method: "DELETE",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ user_id }),
              });
              const data = await res.json();
              
              if (res.ok) {
                setShowConfirmClearHistoryModal(false);
                setClearHistoryPassword("");
                showToast("Scan history cleared successfully");
              } else {
                showToast(data.error || "Failed to clear scan history", true);
              }
            } catch (err) {
              setToast("Failed to clear scan history", true);
            }
          }}
        >
          Confirm Clear
        </button>
        </div>
        </div>
        </div>
      )}

      {showSessionsModal && (
        <div className="sg-settings-modal-overlay">
          <div className="sg-settings-modal">
            <button
              className="sg-settings-modal-close"
              onClick={() => setShowSessionsModal(false)}
            >
              ×
            </button>

            <div className="sg-settings-modal-title">Manage Sessions</div>

            <div className="sg-settings-field-block">
              <div className="sg-settings-item-title">Current Device</div>
              <div className="sg-settings-readonly">
                {sessionsData?.current_session?.device_name || "This Device"} • {sessionsData?.current_session?.status || "Active"} • {sessionsData?.current_session?.ip_address || "No IP"} • {sessionsData?.current_session?.last_active_at || "No activity time"}
              </div>
            </div>

            <div className="sg-settings-field-block">
              <div className="sg-settings-item-title">Other Devices</div>

              {sessionsData?.other_sessions?.map((session) => (
                <div
                key={session.id}
                className="sg-settings-readonly"
                style={{ justifyContent: "space-between", gap: "10px", marginBottom: "8px" }}
              >
                <span>
                  {session.device_name} • {session.status} • {session.ip_address || "Unknown IP"}
                </span>
                
                <button
                  className="sg-settings-small-btn"
                  onClick={async () => {
                    const user_id = localStorage.getItem("user_id");
                    
                    try {
                      const res = await fetch(
                        `http://127.0.0.1:5000/api/settings/logout-session/${session.id}`,
                        {
                          method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: JSON.stringify({ user_id }),
                        }
                      );
                      
                      const data = await res.json();
                      
                      if (res.ok) {
                        showToast("Session logged out");
                        handleOpenSessions();
                      } else {
                        showToast(data.error || "Failed to logout session", true);
                      }
                    } catch (err) {
                      showToast("Failed to logout session", true);
                    }
                  }}
                >
                  Logout
                </button>
              </div>
            ))}
            </div>

            <button
              className="sg-settings-modal-btn danger-btn"
              style={{ width: "100%", marginTop: "10px" }}
              onClick={async () => {
                const user_id = localStorage.getItem("user_id");
                
                try {
                  const res = await fetch(
                    "http://127.0.0.1:5000/api/settings/logout-all-sessions",
                    {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ user_id }),
                    }
                  );
                  
                  const data = await res.json();
                  
                  if (res.ok) {
                    showToast("All other sessions logged out");
                    handleOpenSessions();
                  } else {
                    showToast(data.error || "Failed to logout sessions", true);
                  }
                } catch (err) {
                  showToast("Failed to logout sessions", true);
                }
              }}
            >
              Logout All Other Devices
            </button>
          </div>
        </div>
      )}

      {toast && <div className="sg-settings-toast">{toast}</div>}

      <NewScan isOpen={openScan} onClose={() => setOpenScan(false)} />
    </div>
      </>
  );
}

export default Settings;