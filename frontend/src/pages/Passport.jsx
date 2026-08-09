import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  CircleHelp,
  FileKey2,
  Fingerprint,
  Globe2,
  KeyRound,
  Mail,
  Network,
  Phone,
  QrCode,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  UserCheck,
  UserX,
} from "lucide-react";

import { getCommunication } from "../services/api";

/* =========================================================
   Formatting helpers
   ========================================================= */

function formatScore(value, digits = 2) {
  if (value === null || value === undefined || value === "") {
    return "N/A";
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "N/A";
  }

  return number.toFixed(digits);
}

function formatPercent(value) {
  if (value === null || value === undefined || value === "") {
    return "N/A";
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "N/A";
  }

  return `${number.toFixed(2)}%`;
}

function formatDate(value) {
  if (!value) {
    return "N/A";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

function riskTone(level) {
  const normalized = String(level || "").toLowerCase();

  if (normalized === "high") {
    return "danger";
  }

  if (normalized === "medium") {
    return "warning";
  }

  if (normalized === "low") {
    return "safe";
  }

  return "neutral";
}

function verificationTone(status) {
  const normalized = String(status || "").toLowerCase();

  if (
    normalized.includes("verified") &&
    !normalized.includes("unverified")
  ) {
    return "safe";
  }

  if (
    normalized.includes("failed") ||
    normalized.includes("mismatch") ||
    normalized.includes("suspicious")
  ) {
    return "danger";
  }

  if (
    normalized.includes("insufficient") ||
    normalized.includes("unknown") ||
    normalized.includes("unverified")
  ) {
    return "warning";
  }

  return "neutral";
}

/* =========================================================
   Verification item
   ========================================================= */

function VerificationItem({
  icon: Icon,
  title,
  description,
  verified,
}) {
  return (
    <div
      className={`passport-verification-item ${
        verified ? "verified" : "unverified"
      }`}
    >
      <div className="passport-verification-icon">
        <Icon size={17} />
      </div>

      <div className="passport-verification-copy">
        <strong>{title}</strong>
        <span>{description}</span>
      </div>

      <div
        className={`passport-verification-result ${
          verified ? "verified" : "unverified"
        }`}
      >
        {verified ? (
          <>
            <CheckCircle2 size={14} />
            Verified
          </>
        ) : (
          <>
            <CircleHelp size={14} />
            Not verified
          </>
        )}
      </div>
    </div>
  );
}

/* =========================================================
   Passport
   ========================================================= */

export default function Passport() {
  const { communicationId } = useParams();

  const [communication, setCommunication] = useState(null);
  const [loading, setLoading] = useState(Boolean(communicationId));
  const [error, setError] = useState("");

  useEffect(() => {
    if (!communicationId) {
      setCommunication(null);
      setLoading(false);
      setError("");
      return;
    }

    let active = true;

    const loadPassport = async () => {
      try {
        setLoading(true);
        setError("");

        const data = await getCommunication(communicationId);

        if (active) {
          setCommunication(data);
        }
      } catch (err) {
        console.error("Failed to load passport:", err);

        if (active) {
          setError(
            err?.response?.data?.detail ||
              "Unable to load the Financial Communication Passport."
          );
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    };

    loadPassport();

    return () => {
      active = false;
    };
  }, [communicationId]);

  /* =======================================================
     Empty state
     ======================================================= */

  if (!communicationId) {
  return (
    <div className="investigation-empty-page">
      <div className="investigation-empty-icon">
        <FileKey2 size={30} />
      </div>

      <h1
        style={{
          maxWidth: "900px",
          margin: "24px auto 0",
          fontSize: "clamp(32px, 4vw, 56px)",
          lineHeight: 1.08,
          letterSpacing: "-0.03em",
          textAlign: "center",
          textWrap: "balance",
        }}
      >
        Financial Communication Passport
      </h1>

      <p
        style={{
          maxWidth: "760px",
          margin: "24px auto 0",
          lineHeight: 1.6,
          textAlign: "center",
        }}
      >
        Open a completed security investigation to inspect its
        generated Financial Communication Passport.
      </p>

      <Link
        to="/analysis"
        className="investigation-primary-link"
        style={{
          marginTop: "24px",
        }}
      >
        Open Investigations
        <ArrowRight size={15} />
      </Link>
    </div>
  );
}

  /* =======================================================
     Loading
     ======================================================= */

  if (loading) {
    return (
      <div className="investigation-loading">
        <Shield size={34} />

        <h2>Loading Financial Communication Passport</h2>

        <p>
          Retrieving persisted trust, authenticity and evidence
          intelligence...
        </p>
      </div>
    );
  }

  /* =======================================================
     Error
     ======================================================= */

  if (error) {
    return (
      <div className="investigation-error-page">
        <ShieldAlert size={38} />

        <h2>Passport unavailable</h2>

        <p>{error}</p>

        <Link
          to={`/analysis/${encodeURIComponent(communicationId)}`}
          className="investigation-primary-link"
        >
          <ArrowLeft size={15} />
          Return to Analysis
        </Link>
      </div>
    );
  }

  /* =======================================================
   Data
   ======================================================= */
const passport = communication?.passport;
const verification = passport.verification || {};

const threatCategories = passport.threat_categories || [];
const aiFindings = passport.ai_manipulation_findings || [];

const tone = riskTone(passport.risk_level);
const verifyTone = verificationTone(verification.status);

const verifiedChecks = [
  verification.official_domain,
  verification.official_email,
  verification.official_phone,
  verification.official_qr,
  verification.digital_signature,
  verification.metadata_consistent,
].filter(Boolean).length;

const totalVerificationChecks = 6;

  /* =======================================================
     UI
     ======================================================= */

  return (
    <div className="investigation-page passport-page">
      {/* ===================================================
          Header
          =================================================== */}

      <header className="investigation-header">
        <div>
          <div className="investigation-eyebrow">
            <FileKey2 size={13} />
            FINANCIAL COMMUNICATION PASSPORT
          </div>

          <h1>
            Trust & Authenticity Profile
          </h1>

          <div className="investigation-meta">
            <span>{passport.passport_id}</span>

            <span className="meta-separator">•</span>

            <span>{passport.communication_id}</span>

            <span className="meta-separator">•</span>

            <span>
              {passport.communication_type || "Unknown"}
            </span>
          </div>
        </div>

        <div className="passport-header-actions">
          <div className="investigation-status completed">
            <CheckCircle2 size={14} />
            Passport Generated
          </div>

          <Link
            to={`/analysis/${encodeURIComponent(
              communicationId
            )}`}
            className="passport-back-link"
          >
            <ArrowLeft size={14} />
            Investigation
          </Link>
        </div>
      </header>

      {/* ===================================================
          Primary passport verdict
          =================================================== */}

      <section className={`passport-identity-card ${tone}`}>
        <div className="passport-identity-main">
          <div className={`verdict-shield ${tone}`}>
            {tone === "danger" ? (
              <ShieldAlert size={31} />
            ) : tone === "safe" ? (
              <ShieldCheck size={31} />
            ) : (
              <ShieldQuestion size={31} />
            )}
          </div>

          <div>
            <span className="verdict-label">
              COMMUNICATION TRUST CLASSIFICATION
            </span>

            <h2>
              {passport.risk_level || "Unknown"} Risk
            </h2>

            <div className="passport-threat-row">
              {threatCategories.length > 0 ? (
                threatCategories.map((category, index) => (
                  <span
                    key={`${category}-${index}`}
                    className={`passport-threat-badge ${tone}`}
                  >
                    {category}
                  </span>
                ))
              ) : (
                <span className="passport-threat-badge neutral">
                  No classified threat
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="passport-score-grid">
          <div>
            <span>Risk Score</span>
            <strong>
              {formatPercent(passport.risk_score)}
            </strong>
          </div>

          <div>
            <span>Trust Score</span>
            <strong>
              {formatScore(passport.trust_score, 4)}
            </strong>
          </div>

          <div>
            <span>Confidence</span>
            <strong>
              {formatPercent(passport.confidence)}
            </strong>
          </div>
        </div>
      </section>

      {/* ===================================================
          Recommended action
          =================================================== */}

      {passport.recommended_action && (
        <div className={`recommended-action ${tone}`}>
          <AlertTriangle size={18} />

          <div>
            <span>RECOMMENDED SECURITY ACTION</span>

            <strong>
              {passport.recommended_action}
            </strong>
          </div>
        </div>
      )}
      {/* ===================================================
          Passport identity
          =================================================== */}

      <section className="investigation-section">
        <div className="investigation-section-heading">
          <div>
            <span>PASSPORT IDENTITY</span>
            <h2>Communication Credentials</h2>
          </div>

          <Fingerprint size={18} />
        </div>

        <div className="passport-credential-grid">
          <div className="passport-credential-primary">
            <span>Passport Identifier</span>
            <strong>{passport.passport_id}</strong>
          </div>

          <div>
            <span>Communication ID</span>
            <strong>{passport.communication_id}</strong>
          </div>

          <div>
            <span>Communication Type</span>
            <strong>
              {passport.communication_type || "Unknown"}
            </strong>
          </div>

          <div>
            <span>Generated</span>
            <strong>
              {formatDate(passport.generated_at)}
            </strong>
          </div>
        </div>
      </section>

      {/* ===================================================
          Authenticity verification
          =================================================== */}

      <section className="investigation-section">
        <div className="investigation-section-heading">
          <div>
            <span>AUTHENTICITY VERIFICATION ENGINE (AVE)</span>
            <h2>Available Authenticity Checks</h2>
          </div>

          <span
            className={`passport-status-pill ${verifyTone}`}
          >
            {verification.status || "Unknown"}
          </span>
        </div>

        <div className="passport-auth-summary">
          <div className="passport-auth-score">
            <div
              className={`passport-auth-icon ${verifyTone}`}
            >
              {passport.verified_sender ? (
                <UserCheck size={23} />
              ) : (
                <UserX size={23} />
              )}
            </div>

            <div>
              <span>VERIFICATION CONFIDENCE</span>

              <strong>
  {verification.status === "Insufficient Data" ||
   verification.verification_confidence == null
    ? "Not available"
    : formatPercent(
        verification.verification_confidence
      )}
</strong>

              <small>
  {passport.verified_sender
    ? "Sender identity independently verified."
    : verification.status === "Insufficient Data"
      ? "Insufficient independent evidence to verify the sender."
      : "Sender identity has not been independently verified."}
</small>
            </div>
          </div>

          <div className="passport-check-counter">
            <strong>{verifiedChecks}</strong>
            <span>
              of {totalVerificationChecks} verification checks
              confirmed
            </span>
          </div>
        </div>

        <div className="passport-verification-grid">
          <VerificationItem
  icon={Globe2}
  title="Official Domain"
  description={
    verification.registered_domain
      ? `Registered: ${verification.registered_domain}`
      : "Sender website/domain authenticity"
  }
  verified={Boolean(
    verification.official_domain
  )}
/>

          <VerificationItem
            icon={Mail}
            title="Official Email"
            description="Known official email identity"
            verified={Boolean(
              verification.official_email
            )}
          />

          <VerificationItem
            icon={Phone}
            title="Official Phone"
            description="Known official telephone identity"
            verified={Boolean(
              verification.official_phone
            )}
          />

          <VerificationItem
            icon={QrCode}
            title="Official QR"
            description="Verified payment or identity QR"
            verified={Boolean(
              verification.official_qr
            )}
          />

          <VerificationItem
            icon={KeyRound}
            title="Digital Signature"
            description="Cryptographic signature verification"
            verified={Boolean(
              verification.digital_signature
            )}
          />

          <VerificationItem
            icon={Fingerprint}
            title="Metadata Consistency"
            description="Communication metadata consistency"
            verified={Boolean(
              verification.metadata_consistent
            )}
          />
        </div>

        {
  verification.official_provider && (
    <div className="passport-context-box">

      <strong>
        Official Provider
      </strong>

      <p>

        {verification.official_provider}

        {verification.registered_domain &&
          ` • ${verification.registered_domain}`}

      </p>

    </div>
  )
}

        <div className="passport-metadata-note">
          <ShieldQuestion size={16} />

          <span>
            Metadata consistency is contextual supporting
            information and does not independently authenticate
            the claimed sender.
          </span>
        </div>
      </section>

      {/* ===================================================
          Threat intelligence
          =================================================== */}

      <section className="investigation-section">
        <div className="investigation-section-heading">
          <div>
            <span>THREAT INTELLIGENCE</span>
            <h2>Security Classification</h2>
          </div>

          <ShieldAlert size={18} />
        </div>

        <div className="passport-threat-layout">
          <div>
            <span className="passport-sub-label">
              DETECTED THREAT CATEGORIES
            </span>

            <div className="passport-large-threats">
              {threatCategories.length > 0 ? (
                threatCategories.map((category, index) => (
                  <span
                    key={`${category}-${index}`}
                    className={`passport-large-threat ${tone}`}
                  >
                    <ShieldAlert size={15} />
                    {category}
                  </span>
                ))
              ) : (
                <span className="passport-large-threat neutral">
                  <ShieldCheck size={15} />
                  No threat category recorded
                </span>
              )}
            </div>
          </div>

          <div>
            <span className="passport-sub-label">
              AI MANIPULATION FINDINGS
            </span>

            {aiFindings.length > 0 ? (
              <div className="passport-ai-findings">
                {aiFindings.map((finding, index) => (
                  <div key={index}>
                    <AlertTriangle size={14} />
                    <span>
                      {typeof finding === "string"
                        ? finding
                        : JSON.stringify(finding)}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="passport-no-finding">
                <CheckCircle2 size={16} />
                No AI manipulation findings were recorded.
              </div>
            )}
          </div>
        </div>
      </section>

      {/* ===================================================
    Trust Profile / STG
    =================================================== */}

<section className="investigation-section">
  <div className="investigation-section-heading">
    <div>
      <span>TRUST PROFILE</span>
      <h2>Securities Trust Graph</h2>
    </div>

    <Network size={18} />
  </div>

  <div className="passport-module-link-card">
    <div>
      <strong>Historical Entity Trust Intelligence</strong>
      <span>
        Explore entity relationships, historical reputation,
        graph trust and graph risk in the dedicated Trust Graph.
      </span>
    </div>

    <Link
      to={`/trust-graph/${encodeURIComponent(communicationId)}`}
      className="investigation-secondary-link"
    >
      Explore Trust Graph
      <ArrowRight size={14} />
    </Link>
  </div>
</section>

      {/* ===================================================
    Auditability / EEL
    =================================================== */}

<section className="investigation-section">
  <div className="investigation-section-heading">
    <div>
      <span>AUDITABILITY</span>
      <h2>Explainable Evidence Ledger</h2>
    </div>

    <FileKey2 size={18} />
  </div>

  <div className="passport-module-link-card">
    <div>
      <strong>Explainable Evidence Ledger</strong>
      <span>
        Inspect the evidence records, intelligence provenance
        and audit trail generated by this investigation.
      </span>
    </div>

    <Link
      to={`/ledger/${encodeURIComponent(communicationId)}`}
      className="investigation-secondary-link"
    >
      Inspect Evidence Ledger
      <ArrowRight size={14} />
    </Link>
  </div>
</section>


      {/* ===================================================
          Passport footer
          =================================================== */}

      <section className="passport-footer-card">
        <div>
          <div className="passport-footer-icon">
            <ShieldCheck size={21} />
          </div>

          <div>
            <strong>
              SecureSense Financial Communication Passport
            </strong>

            <span>
              Generated from the completed SecureSense AI investigation, including trust verification, multimodal intelligence, explainable evidence, and historical trust context.
            </span>
          </div>
        </div>

        <div className="passport-footer-actions">
          <Link
            to={`/analysis/${encodeURIComponent(
              communicationId
            )}`}
            className="passport-outline-link"
          >
            <ArrowLeft size={14} />
            Full Investigation
          </Link>

        </div>
      </section>
    </div>
  );
}