import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import "../styles/sentinel.css";

function ResetPassword() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const token = useMemo(() => searchParams.get("token") || "", [searchParams]);

  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [isResetting, setIsResetting] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);

  const isStrongPassword = (value) => {
    return (
      value.length >= 8 &&
      /[A-Za-z]/.test(value) &&
      /\d/.test(value)
    );
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    
    if (!token) {
      setError("Invalid or expired reset link.");
      return;
    }
    
    if (!newPassword.trim() || !confirmPassword.trim()) {
      setError("Please fill in both password fields.");
      return;
    }
    
    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    
    if (!isStrongPassword(newPassword)) {
      setError("Password must be at least 8 characters and include letters and numbers.");
      return;
    }
    
    setIsResetting(true);
    
    try {
      const response = await fetch("http://127.0.0.1:5000/api/auth/reset-password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          token,
          new_password: newPassword,
        }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        setError(data.error || "Password reset failed.");
        return;
      }
      
      setIsSuccess(true);
    } catch (err) {
      setError("Server error. Please try again.");
    } finally {
      setIsResetting(false);
    }
  };

  if (isSuccess) {
    return (
      <div className="sg-auth-page">
        <div
          className="sg-auth-card"
          style={{ maxWidth: "480px", textAlign: "center" }}
        >
          <div
            style={{
              width: "66px",
              height: "66px",
              borderRadius: "50%",
              margin: "4px auto 18px",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: "linear-gradient(145deg, #22c55e, #16a34a)",
              color: "#fff",
              fontSize: "30px",
              boxShadow: "0 12px 28px rgba(34,197,94,0.28)",
            }}
          >
            ✓
          </div>

          <h1
            style={{
              margin: 0,
              fontSize: "22px",
              fontWeight: "800",
              color: "#0f2042",
            }}
          >
            Password Reset Successfully
          </h1>

          <p
            style={{
              margin: "12px 0 22px",
              color: "#7a8ca8",
              fontSize: "14px",
            }}
          >
            Your password has been updated. You can now sign in with your new password.
          </p>

          <button
            className="sg-btn-primary"
            onClick={() => navigate("/")}
          >
            Back to Sign In
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="sg-auth-page">
      <div
        className="sg-auth-card"
        style={{ maxWidth: "480px", textAlign: "center" }}
      >
        <div className="sg-auth-center-logo">🛡</div>

        <div className="sg-auth-small-brand">SENTINEL GATE</div>

        <h1
          style={{
            margin: "0 0 10px",
            fontSize: "22px",
            fontWeight: "800",
            color: "#0f2042",
          }}
        >
          Reset Password
        </h1>

        <p
          style={{
            margin: "0 0 24px",
            color: "#7a8ca8",
            fontSize: "14px",
          }}
        >
          Enter your new password for your account
        </p>

        <form onSubmit={handleSubmit} style={{ textAlign: "left" }}>
          <div className="sg-field">
            <label className="sg-label">NEW PASSWORD</label>
            <input
              className="sg-input"
              type="password"
              placeholder="Enter new password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </div>

          <div className="sg-field">
            <label className="sg-label">CONFIRM PASSWORD</label>
            <input
              className="sg-input"
              type="password"
              placeholder="Confirm new password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
          </div>

          {!token && <div className="sg-error">Invalid or expired reset link.</div>}
          {error && <div className="sg-error">{error}</div>}

          <button className="sg-btn-primary" type="submit" disabled={isResetting || !token}>
            {isResetting ? "Resetting..." : "Reset Password"}
          </button>
        </form>

        <div className="sg-auth-footer" style={{ marginTop: "18px" }}>
          ← <Link to="/">Back to Sign In</Link>
        </div>
      </div>
    </div>
  );
}

export default ResetPassword;