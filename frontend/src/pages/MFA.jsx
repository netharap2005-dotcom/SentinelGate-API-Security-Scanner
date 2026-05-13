import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import "../styles/sentinel.css";

function MFA() {
  const navigate = useNavigate();
  const inputsRef = useRef([]);

  const [digits, setDigits] = useState(["", "", "", "", "", ""]);
  const [error, setError] = useState("");
  const [seconds, setSeconds] = useState(30);

  const pendingEmail =
    localStorage.getItem("sentinelPendingEmail") || "alex@gmail.com";

  

  useEffect(() => {
    const updateTotpTimer = () => {
      const currentUnixTime = Math.floor(Date.now() / 1000);
      const remaining = 30 - (currentUnixTime % 30);
      setSeconds(remaining);
    };
    
    updateTotpTimer();
    
    const timer = setInterval(updateTotpTimer, 1000);
    
    return () => clearInterval(timer);
  }, []);

  const maskEmail = (email) => {
    const [name, domain] = email.split("@");
    if (!name || !domain) return email;
    return `${name.slice(0, 3)}***@${domain}`;
  };

  const handleChange = (value, index) => {
    if (!/^\d?$/.test(value)) return;

    const updated = [...digits];
    updated[index] = value;
    setDigits(updated);

    if (value && index < 5) {
      inputsRef.current[index + 1]?.focus();
    }

    const filledCode = updated.join("");
    if (filledCode.length === 6 && !updated.includes("")) {
      setTimeout(() => {
        handleVerify(updated.join(""));
      }, 150);
    }
  };

  const handleKeyDown = (e, index) => {
    if (e.key === "Enter") {
      handleVerify();
    }

    if (e.key === "Backspace" && !digits[index] && index > 0) {
      inputsRef.current[index - 1]?.focus();
    }
  };

  const handleVerify = async (codeFromAutoFill) => {
  setError("");
  const enteredCode = codeFromAutoFill || digits.join("");
  const user_id = localStorage.getItem("pending_user_id");

  if (enteredCode.length !== 6) {
    setError("Please enter the full 6-digit code.");
    return;
  }

  try {
    const response = await fetch("http://127.0.0.1:5000/api/auth/verify-mfa", {
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
      setError(data.error || "Invalid or expired authenticator code.");
      return;
    }

    localStorage.setItem("user", JSON.stringify(data.user));
    localStorage.setItem("user_id", data.user.id);
    localStorage.setItem("session_token", data.session_token);
    localStorage.removeItem("pending_user_id");

    const postAction = sessionStorage.getItem("sentinelPostMfaAction");
    const returnRoute = sessionStorage.getItem("sentinelReturnRoute") || "/dashboard";

    if (postAction === "clearHistory") {
      sessionStorage.setItem("sentinelSettingsToast", "Scan history cleared successfully");
    }

    sessionStorage.removeItem("sentinelPostMfaAction");
    sessionStorage.removeItem("sentinelReturnRoute");

    navigate(returnRoute);
  } catch (error) {
    setError("Server error. Please try again.");
  }
};

  return (
    <div className="sg-auth-page">
      <div className="sg-mfa-card">
        <div className="sg-auth-center-logo">🔐</div>

        <h1 className="sg-mfa-title">Multi-Factor Authentication</h1>
        <p className="sg-mfa-sub">
          Enter the current 6-digit code from Microsoft Authenticator for <br />
          <span className="sg-mfa-email">{maskEmail(pendingEmail)}</span>
        </p>

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

        {error && <div className="sg-error">{error}</div>}

        <button className="sg-btn-primary" onClick={() => handleVerify()}>
          Verify Code
        </button>

        <div className="sg-mfa-links">
          Use the latest code shown in Microsoft Authenticator.
        </div>

        <div className="sg-mfa-timer">
          Code refreshes automatically in <strong>{seconds}s</strong>
        </div>
      </div>
    </div>
  );
}

export default MFA;