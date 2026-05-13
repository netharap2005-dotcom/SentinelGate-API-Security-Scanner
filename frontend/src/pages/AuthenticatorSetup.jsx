import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import "../styles/sentinel.css";

function AuthenticatorSetup() {
  const navigate = useNavigate();
  const inputsRef = useRef([]);

  const [copied, setCopied] = useState(false);
  const [digits, setDigits] = useState(["", "", "", "", "", ""]);
  const [error, setError] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [qrCode, setQrCode] = useState("");

  const pendingEmail =
    localStorage.getItem("sentinelPendingEmail") || "alex@gmail.com";

  useEffect(() => {
    const fetchMfaSetup = async () => {
      const user_id = localStorage.getItem("pending_user_id");
      if (!user_id) {
        setError("No pending user found. Please log in again.");
        return;
      }
      
      try {
        const response = await fetch("http://127.0.0.1:5000/api/auth/setup-mfa", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ user_id }),
        });
        
        const data = await response.json();
        
        if (!response.ok) {
          setError(data.error || "Failed to load MFA setup.");
          return;
        }
        
        setSecretKey(data.manual_secret || "");
        setQrCode(data.qr_code_base64 ? `data:image/png;base64,${data.qr_code_base64}` : "");
      } catch (error) {
        setError("Server error. Please try again.");
      }
    };
    fetchMfaSetup();
  }, []);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(secretKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (err) {
      console.error("Copy failed", err);
    }
  };

  const handleChange = (value, index) => {
    if (!/^\d?$/.test(value)) return;

    const updated = [...digits];
    updated[index] = value;
    setDigits(updated);

    if (value && index < 5) {
      inputsRef.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (e, index) => {
    if (e.key === "Enter") {
      handleConfirmSetup();
    }

    if (e.key === "Backspace" && !digits[index] && index > 0) {
      inputsRef.current[index - 1]?.focus();
    }
  };

  const handleConfirmSetup = async () => {
    setError("");
    const enteredCode = digits.join("");
    const user_id = localStorage.getItem("pending_user_id");

    if (enteredCode.length !== 6) {
      setError("Please enter the full 6-digit authenticator code.");
      return;
    }

    try {
      const response = await fetch("http://127.0.0.1:5000/api/auth/confirm-mfa", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          user_id,
          code: enteredCode,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || "Invalid authenticator code.");
        return;
      }
      localStorage.setItem("user", JSON.stringify(data.user));
      localStorage.setItem("user_id", data.user.id);
      localStorage.setItem("session_token", data.session_token);
      localStorage.removeItem("pending_user_id");
      
      navigate("/dashboard");
    } catch (error) {
      setError("Server error. Please try again.");
    }
  };

  return (
    <div className="sg-auth-page">
      <div className="sg-auth-setup-card">
        <div className="sg-auth-center-logo">🔐</div>

        <h1 className="sg-mfa-title">Set Up Microsoft Authenticator</h1>
        <p className="sg-mfa-sub">
          Scan the QR code or enter the setup key manually for <br />
          <span className="sg-mfa-email">{pendingEmail}</span>
        </p>

        <div className="sg-setup-qr-card">
          <div className="sg-setup-secret-label">QR Code</div>
          <div className="sg-setup-qr-placeholder">
            {qrCode ? (
              <img
                src={qrCode}
                alt="MFA QR Code"
                style={{ width: "180px", height: "180px" }}
              />
            ) : (
              "QR code from backend will appear here"
            )}
          </div>
        </div>

        <div className="sg-setup-secret-card">
          <div className="sg-setup-secret-label">Setup Key</div>
          <div className="sg-setup-secret-value">{secretKey}</div>
          <button
            type="button"
            className="sg-btn-secondary sg-setup-copy-btn"
            onClick={handleCopy}
          >
            {copied ? "Copied" : "Copy Key"}
          </button>
        </div>

        <div className="sg-setup-code-card">
          <div className="sg-setup-secret-label">Enter First 6-Digit Code</div>

          <div className="sg-mfa-row">
            {digits.map((digit, index) => (
              <input
                key={index}
                ref={(el) => (inputsRef.current[index] = el)}
                className="sg-mfa-box"
                type="text"
                maxLength="1"
                value={digit}
                onChange={(e) => handleChange(e.target.value, index)}
                onKeyDown={(e) => handleKeyDown(e, index)}
              />
            ))}
          </div>
        </div>

        {error && <div className="sg-error">{error}</div>}

        <button
          type="button"
          className="sg-btn-primary"
          onClick={handleConfirmSetup}
        >
          Confirm MFA
        </button>
      </div>
    </div>
  );
}

export default AuthenticatorSetup;