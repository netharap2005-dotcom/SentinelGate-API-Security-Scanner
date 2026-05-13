import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import "../styles/sentinel.css";

function NewScan({ isOpen, onClose }) {
  const navigate = useNavigate();
  const pollRef = useRef(null);

  const [url, setUrl] = useState("");
  const [depth, setDepth] = useState("Standard");
  const [error, setError] = useState("");
  const [isStarting, setIsStarting] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  
  
  const depthHelp = {
    Standard:"Standard: Balance scan with broader coverage. Best for regular security review.",
    Deep: "Deep: More aggressive and thorough scan for wider vulnerability coverage.",
    Shallow: "Shallow: Quick scan with limited checks for fast review.",
  };

  const spinnerStyle = {
    width: "14px",
    height: "14px",
    border: "2px solid rgba(255,255,255,0.45)",
    borderTop: "2px solid #ffffff",
    borderRadius: "50%",
    display: "inline-block",
    animation: "sgSpin 0.8s linear infinite",
  };
  
  useEffect(() => {
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, []);

  if (!isOpen) return null;

  const handleStart = async () => {
    setError("");
    if (!url.trim()) {
      setError("Please enter API URL.");
      return;
    }
    
    const user_id = localStorage.getItem("user_id");
    
    if (!user_id) {
      setError("User not logged in.");
      return;
    }
    
    setIsStarting(true);
    setScanProgress(0);
    
    try {
      const response = await fetch("http://127.0.0.1:5000/api/scans/start", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          user_id: Number(user_id),
          target_url: url.trim(),
          scan_depth: depth.toLowerCase(),
        }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        setError(data.error || "Failed to start scan.");
        setIsStarting(false);
        return;
      }
      
      const startedScanId = data.scan_id;
      
      pollRef.current = setInterval(async () => {
        try {
          const progressRes = await fetch(
            `http://127.0.0.1:5000/api/scans/${startedScanId}/progress`
          );
          const progressData = await progressRes.json();
          
          if (!progressRes.ok) return;
          
          setScanProgress(progressData.progress_percent || 0);
          
          if (progressData.status === "Completed") {
            setScanProgress(100);
            clearInterval(pollRef.current);
            pollRef.current = null;
            setIsStarting(false);
            setUrl("");
            setDepth("Standard");
            onClose();
            navigate(`/results?scan_id=${startedScanId}`);
          }
          
          if (progressData.status === "Failed") {
            clearInterval(pollRef.current);
            pollRef.current = null;
            setIsStarting(false);
            setError("Scan failed. Please try again.");
          }
        } catch (err) {
          console.error("Progress polling failed", err);
        }
      }, 2000);
    } catch (err) {
      setError("Server error. Please try again.");
      setIsStarting(false);
    }
  };

  return (
    <>
      <style>
        {`
        @keyframes sgSpin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}
    </style>

    <div
      onClick={() => {
        if (!isStarting) onClose();
      }}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(2, 6, 23, 0.3)",
        zIndex: 9999,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "16px",
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "100%",
          maxWidth: "460px",
          background: "#fff",
          borderRadius: "24px",
          boxShadow: "0 20px 50px rgba(15, 32, 66, 0.18)",
          padding: "24px",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "16px",
          }}
        >
          <div>
            <div
              style={{
                fontSize: "20px",
                fontWeight: "800",
                color: "#0f2042",
              }}
            >
              New Security Scan
            </div>
            <div
              style={{
                fontSize: "13px",
                color: "#7a8ca8",
                marginTop: "4px",
              }}
            >
              Configure scan depth and start
            </div>
          </div>

          <button
            onClick={() => {
              if (!isStarting) onClose();
            }}
            style={{
              width: "38px",
              height: "38px",
              borderRadius: "12px",
              border: "1px solid #dbe7fb",
              background: "#fff",
              cursor: "pointer",
              fontSize: "16px",
            }}
          >
            ✕
          </button>
        </div>

        <div className="sg-field">
          <label className="sg-label">API URL</label>
          <input
            className="sg-input"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://api.example.com"
          />
        </div>

        <div className="sg-field">
          <label className="sg-label">Depth</label>
          <select
            className="sg-input"
            value={depth}
            onChange={(e) => setDepth(e.target.value)}
          >
            <option>Standard</option>
            <option>Deep</option>
            <option>Shallow</option>
          </select>
        </div>

        <div
          style={{
            fontSize: "12px",
            color: "#7a8ca8",
            marginTop: "-4px",
            marginBottom: "14px",
          }}
        >
          {depthHelp[depth]}
        </div>

        {error && <div className="sg-error">{error}</div>}

        <div
          style={{
            background: "#f4f8ff",
            border: "1px solid #dde9fb",
            borderRadius: "14px",
            padding: "14px 16px",
            fontSize: "13px",
            color: "#6c7f9d",
            marginBottom: "18px",
            lineHeight: 1.5,
          }}
        >
          Scan will analyze endpoints for common vulnerabilities like injection
          checks, auth bypass, and rate exposure.
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "12px",
          }}
        >
          <button
            onClick={() => {
              if (!isStarting) onClose();
            }}
            disabled={isStarting}
            style={{
              border: "1px solid #dbe7fb",
              background: "#fff",
              borderRadius: "14px",
              padding: "13px 16px",
              fontWeight: "600",
              cursor: "pointer",
              color: "#0f2042",
            }}
          >
            Cancel
          </button>

          <button
          className="sg-btn-primary"
          onClick={handleStart}
          disabled={isStarting}
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "8px",
            }}
          >
            {isStarting ? (
              <>
                <span style={spinnerStyle} />
                <span>Starting...</span>
                <span style={{ fontSize: "12px", opacity: 0.95 }}>
                  {scanProgress}%
                  </span>
                </>
              ) : (
                "Start Scan"
              )}
            </button>
        </div>
      </div>
    </div>
  </>
  );
}

export default NewScan;