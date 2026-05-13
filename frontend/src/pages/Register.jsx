import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import "../styles/sentinel.css";



function Register() {
  const navigate = useNavigate();

  const [form, setForm] = useState({
    fullName: "",
    email: "",
    company: "",
    password: "",
    confirmPassword: "",
    agree: false,
  });

  const [error, setError] = useState("");

  const [showTermsModal, setShowTermsModal] = useState(false);
  const [showPrivacyModal, setShowPrivacyModal] = useState(false);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setForm((prev) => ({
      ...prev,
      [name]: type === "checkbox" ? checked : value,
    }));
  };

  const isValidPassword = (password) => {
    return /^(?=.*[A-Za-z])(?=.*\d)(?=.*[^\w\s]).{8,}$/.test(password);
  };

  const handleSubmit = async (e) => {
  e.preventDefault();
  setError("");

  if (!form.fullName || !form.email || !form.password || !form.confirmPassword) {
    setError("Please fill the required fields.");
    return;
  }

  if (form.password !== form.confirmPassword) {
    setError("Passwords do not match.");
    return;
  }

  if (!isValidPassword(form.password)) {
    setError("Use at least 8 characters with letters, numbers, and a symbol.");
    return;
  }

  if (!form.agree) {
    setError("Please agree to the Terms and Privacy Policy.");
    return;
  }

  try {
    const response = await fetch("http://127.0.0.1:5000/api/auth/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        full_name: form.fullName,
        email: form.email.trim().toLowerCase(),
        company_name: form.company,
        password: form.password
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      setError(data.error || "Registration failed.");
      return;
    }

    localStorage.setItem("sentinelRememberedEmail", form.email.trim().toLowerCase());
    navigate("/");
  } catch (error) {
    setError("Server error. Please try again.");
  }
};

  return (
    <div className="sg-auth-page">
      <div className="sg-auth-card">
        <div className="sg-brand-row">
          <div className="sg-brand-logo">
            <img src="/logo.png" alt="Sentinel Gate Logo" className="sg-logo-img" />
          </div>
          <div>
            <p className="sg-brand-title">Sentinel Gate</p>
            <p className="sg-brand-sub">API Security Scanning Platform</p>
          </div>
        </div>

        <h1 className="sg-auth-heading">Create your account</h1>

        <form onSubmit={handleSubmit}>
          <div className="sg-field">
            <label className="sg-label">Full Name</label>
            <input
              className="sg-input"
              name="fullName"
              placeholder="Alex Johnson"
              value={form.fullName}
              onChange={handleChange}
            />
          </div>

          <div className="sg-field">
            <label className="sg-label">Email Address</label>
            <input
              className="sg-input"
              type="email"
              name="email"
              placeholder="alex@company.com"
              value={form.email}
              onChange={handleChange}
            />
          </div>

          <div className="sg-field">
            <label className="sg-label">
              Company Name <span style={{ color: "#8ca0bb" }}>(Optional)</span>
            </label>
            <input
              className="sg-input"
              name="company"
              placeholder="Acme Corp"
              value={form.company}
              onChange={handleChange}
            />
          </div>

          <div className="sg-grid-2">
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
              <div className="sg-help">
                Use at least 8 characters with a mix of letters, numbers, and symbol
              </div>
            </div>

            <div className="sg-field">
              <label className="sg-label">Confirm Password</label>
              <input
                className="sg-input"
                type="password"
                name="confirmPassword"
                placeholder="••••••••"
                value={form.confirmPassword}
                onChange={handleChange}
              />
            </div>
          </div>

          <label className="sg-check-row">
            <input
              type="checkbox"
              name="agree"
              checked={form.agree}
              onChange={handleChange}
            />
            <span>
              I agree to the{" "}
              <button
                type="button"
                className="sg-inline-link"
                onClick={() => setShowTermsModal(true)}
              >
                Terms of Service
              </button>{" "}
              and{" "}
              <button
                type="button"
                className="sg-inline-link"
                onClick={() => setShowPrivacyModal(true)}
              >
                Privacy Policy
              </button>
            </span>
          </label>

          {error && <div className="sg-error">{error}</div>}

          <button className="sg-btn-primary" type="submit">
            Create Account
          </button>
        </form>

        <div className="sg-auth-footer">
          Already have an account? <Link to="/">Sign In</Link>
        </div>
      </div>
      {/* TERMS MODAL */}
{showTermsModal && (
  <div className="sg-modal-overlay" onClick={() => setShowTermsModal(false)}>
    <div className="sg-modal-card" onClick={(e) => e.stopPropagation()}>
      <button
        type="button"
        className="sg-modal-close"
        onClick={() => setShowTermsModal(false)}
      >
        ×
      </button>

      <h2 className="sg-modal-title">Terms of Service</h2>

      <div className="sg-modal-content">
        <p>
          By using Sentinel Gate, you agree to use this platform only for
          authorized API security testing.
        </p>
        <p>
          You are responsible for maintaining the confidentiality of your
          account and activities performed under it.
        </p>
        <p>
          Misuse of the platform for illegal or harmful purposes is strictly
          prohibited.
        </p>
      </div>
    </div>
  </div>
)}

{/* PRIVACY MODAL */}
{showPrivacyModal && (
  <div className="sg-modal-overlay" onClick={() => setShowPrivacyModal(false)}>
    <div className="sg-modal-card" onClick={(e) => e.stopPropagation()}>
      <button
        type="button"
        className="sg-modal-close"
        onClick={() => setShowPrivacyModal(false)}
      >
        ×
      </button>

      <h2 className="sg-modal-title">Privacy Policy</h2>

      <div className="sg-modal-content">
        <p>
          We collect basic information such as your name, email, and company to
          manage your account.
        </p>
        <p>
          Your data is used only for platform functionality and security
          improvements.
        </p>
        <p>
          We do not share your personal data with third parties without your
          consent.
        </p>
      </div>
    </div>
  </div>
)}
    </div>
  );
}

export default Register;