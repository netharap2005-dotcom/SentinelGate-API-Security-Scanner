import { useState } from "react";
import { Link } from "react-router-dom";
import "../styles/sentinel.css";

function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [isSent, setIsSent] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    
    if (!email.trim()) {
      setError("Please enter your email address.");
      return;
    }
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setError("Please enter a valid email address.");
      return;
    }
    
    setIsSending(true);
    
    try {
      const response = await fetch("http://127.0.0.1:5000/api/auth/forgot-password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: email.trim().toLowerCase(),
        }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        setError(data.error || "Failed to send reset link.");
        setIsSending(false);
        return;
      }
      
      setEmail(data.email || email.trim().toLowerCase());
      setIsSent(true);
    } catch (error) {
      setError("Server error. Please try again.");
    } finally {
      setIsSending(false);
    }
  };

  const handleTryAnother = () => {
    setEmail("");
    setError("");
    setIsSent(false);
    setIsSending(false);
  };

  if (isSent) {
    return (
      <div className="sg-auth-page">
        <div className="sg-auth-card" style={{ maxWidth: "480px", textAlign: "center" }}>
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
            Check Your Email
          </h1>

          <p
            style={{
              margin: "10px 0 6px",
              color: "#7a8ca8",
              fontSize: "14px",
            }}
          >
            Reset link sent to your email
          </p>

          <p
            style={{
              margin: "0 0 18px",
              color: "#2d72ff",
              fontWeight: "700",
              fontSize: "15px",
            }}
          >
            {email}
          </p>

          <div
            style={{
              background: "#f4f8ff",
              border: "1px solid #dde9fb",
              borderRadius: "14px",
              padding: "14px 16px",
              fontSize: "13px",
              color: "#6c7f9d",
              textAlign: "left",
              marginBottom: "18px",
            }}
          >
            ℹ Didn’t get the email? Check your spam folder or try again.
          </div>

          <button className="sg-btn-primary" onClick={handleTryAnother}>
            Try Another Email
          </button>

          <div className="sg-auth-footer" style={{ marginTop: "18px" }}>
            ← <Link to="/">Back to Sign In</Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="sg-auth-page">
      <div className="sg-auth-card" style={{ maxWidth: "480px", textAlign: "center" }}>
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
          Forgot Password
        </h1>

        <p
          style={{
            margin: "0 0 24px",
            color: "#7a8ca8",
            fontSize: "14px",
          }}
        >
          Enter your email to reset your password
        </p>

        <form onSubmit={handleSubmit} style={{ textAlign: "left" }}>
          <div className="sg-field">
            <label className="sg-label">EMAIL ADDRESS</label>
            <input
              className="sg-input"
              type="email"
              placeholder="alex@gmail.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>

          {error && <div className="sg-error">{error}</div>}

          <button className="sg-btn-primary" type="submit" disabled={isSending}>
            {isSending ? "Sending..." : "Send Reset Link →"}
          </button>
        </form>

        <div className="sg-auth-footer" style={{ marginTop: "18px" }}>
          ← <Link to="/">Back to Sign In</Link>
        </div>
      </div>
    </div>
  );
}

export default ForgotPassword;