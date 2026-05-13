import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import "../styles/sentinel.css";


function Login() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    email: "",
    password: "",
    remember: true,
  });
  const [error, setError] = useState("");

  useEffect(() => {
    const remembered = localStorage.getItem("sentinelRememberedEmail");
    if (remembered) {
      setForm((prev) => ({ ...prev, email: remembered }));
    }
  }, []);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setForm((prev) => ({
      ...prev,
      [name]: type === "checkbox" ? checked : value,
    }));
  };

  const handleSubmit = async (e) => {
  e.preventDefault();
  setError("");

  if (!form.email.trim() || !form.password.trim()) {
    setError("Please enter your email and password.");
    return;
  }

  try {
    const response = await fetch("http://127.0.0.1:5000/api/auth/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email: form.email,
        password: form.password,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      setError(data.error || "Login failed.");
      return;
    }

    if (form.remember) {
      localStorage.setItem("sentinelRememberedEmail", form.email);
    } else {
      localStorage.removeItem("sentinelRememberedEmail");
    }

    if (data.setup_required) {
      localStorage.setItem("pending_user_id", data.user_id);
      localStorage.setItem("sentinelPendingEmail", data.email);
      navigate("/authenticator-setup");
      return;
    }

    if (data.mfa_required) {
      localStorage.setItem("pending_user_id", data.user_id);
      localStorage.setItem("sentinelPendingEmail", data.email);
      navigate("/mfa");
      return;
    }

    localStorage.setItem("user", JSON.stringify(data.user));
    localStorage.setItem("user_id", data.user.id);
    localStorage.setItem("session_token", data.session_token);

    navigate("/dashboard");
  } catch (error) {
    setError("Server error. Please try again.");
  }
};

  return (
    <div className="sg-auth-page">
      <div className="sg-auth-card" style={{ maxWidth: "420px" }}>
        <div className="sg-brand-row">
          <div className="sg-auth-logo">
            <img
              src="/logo.png"
              alt="Sentinel Gate Logo"
              className="sg-auth-logo-img"
            />
          </div>
          <div>
            <p className="sg-brand-title">Sentinel Gate</p>
            <p className="sg-brand-sub">API Security Scanning Platform</p>
          </div>
        </div>

        <h1 className="sg-auth-heading">Welcome</h1>
        <p className="sg-auth-sub">Sign in to your security dashboard</p>

        <form onSubmit={handleSubmit}>
          <div className="sg-field">
            <label className="sg-label">Email Address</label>
            <input
              className="sg-input"
              type="email"
              name="email"
              placeholder="alex@gmail.com"
              value={form.email}
              onChange={handleChange}
            />
          </div>

          <div className="sg-field">
            <label className="sg-label">Password</label>
            <input
              className="sg-input"
              type="password"
              name="password"
              placeholder="••••••••"
              value={form.password}
              onChange={handleChange}
            />
          </div>

          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              gap: "10px",
              alignItems: "center",
              margin: "12px 0 16px",
              fontSize: "13px",
              color: "#617391",
            }}
          >
            <label style={{ display: "flex", gap: "8px", alignItems: "center" }}>
              <input
                type="checkbox"
                name="remember"
                checked={form.remember}
                onChange={handleChange}
              />
              <span>Remember me</span>
            </label>

            <Link to="/forgot-password">Forgot password?</Link>
          </div>

          {error && <div className="sg-error">{error}</div>}

          <button className="sg-btn-primary" type="submit">
            Sign In
          </button>
        </form>

        <div className="sg-auth-footer">
          Don’t have an account? <Link to="/register">Sign Up</Link>
        </div>
      </div>
    </div>
  );
}

export default Login;