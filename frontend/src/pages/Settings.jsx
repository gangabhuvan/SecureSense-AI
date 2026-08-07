import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  Brain,
  CheckCircle2,
  Database,
  ExternalLink,
  Eye,
  FileBadge2,
  Fingerprint,
  Globe2,
  Network,
  RefreshCw,
  Server,
  Settings2,
  Shield,
  ShieldCheck,
  Upload,
} from "lucide-react";

import api, {
  getEvidenceLedger,
} from "../services/api";

const MODULES = [
  {
    name: "NLP Intelligence",
    description:
      "DistilBERT-based communication intelligence, phishing detection, and explainable language analysis.",
    icon: Brain,
    type: "nlp",
  },
  {
    name: "Visual Intelligence",
    description:
      "ConvNeXt-based visual analysis for fraudulent documents, websites, QR codes, and phishing content with Grad-CAM evidence.",
    icon: Eye,
    type: "vision",
  },
  {
    name: "Voice Intelligence",
    description:
      "Whisper transcription with Spectra-AASIST3 analysis for voice phishing, synthetic voice detection, and communication verification.",
    icon: Activity,
    type: "voice",
  },
  {
    name: "Communication Intent Intelligence",
    description:
      "Semantic communication understanding with explainable intent reasoning and contextual legitimacy assessment.",
    icon: Brain,
    type: "cii",
  },
  {
    name: "URL Intelligence",
    description:
      "Website URL intelligence for phishing detection, domain analysis, and communication link verification.",
    icon: Globe2,
    type: "url",
  },
  {
    name: "Securities Trust Graph (STG)",
    description:
      "Correlates communications, entities, domains, and relationships to identify coordinated fraud campaigns.",
    icon: Network,
    type: "stg",
  },
  {
    name: "Explainable Evidence Ledger (EEL)",
    description:
      "Maintains durable evidence provenance, explainable AI records, and investigation history.",
    icon: Database,
    type: "eel",
  },
  {
    name: "Financial Communication Passport (FCP)",
    description:
      "Generates a standardized trust profile with authenticity findings, risk assessment, trust score, and explainable evidence.",
    icon: FileBadge2,
    type: "fcp",
  },
];

function StatusBadge({
  available,
  label,
}) {
  return (
    <span
      className={`settings-status-badge ${
        available
          ? "settings-status-online"
          : "settings-status-unavailable"
      }`}
    >
      <span className="settings-status-dot" />

      {label ||
        (available
          ? "Available"
          : "Unavailable")}
    </span>
  );
}

export default function Settings() {
  const [checking, setChecking] =
    useState(true);

  const [
    backendOnline,
    setBackendOnline,
  ] = useState(false);

  const [
    nlpOnline,
    setNlpOnline,
  ] = useState(false);

  const [
    ledgerOnline,
    setLedgerOnline,
  ] = useState(false);

  const [
    ledgerRecords,
    setLedgerRecords,
  ] = useState(null);

  const [
    lastChecked,
    setLastChecked,
  ] = useState(null);

  const checkSystem = async () => {
    try {
      setChecking(true);

      // =====================================================
      // Backend API
      // =====================================================

      try {
        await api.get("/");

        setBackendOnline(true);
      } catch (error) {
        console.error(
          "Backend health check failed:",
          error
        );

        setBackendOnline(false);
      }

      // =====================================================
      // NLP Intelligence
      // Dedicated runtime health endpoint
      // =====================================================

      try {
        await api.get("/nlp/health");

        setNlpOnline(true);
      } catch (error) {
        console.error(
          "NLP health check failed:",
          error
        );

        setNlpOnline(false);
      }

      // =====================================================
      // Explainable Evidence Ledger
      // Successful query verifies persistence availability
      // =====================================================

      try {
        const ledger =
          await getEvidenceLedger({
            skip: 0,
            limit: 1,
          });

        setLedgerOnline(true);

        if (
          ledger?.total !== null &&
          ledger?.total !== undefined
        ) {
          setLedgerRecords(
            Number(ledger.total)
          );
        } else {
          setLedgerRecords(null);
        }
      } catch (error) {
        console.error(
          "Evidence Ledger health check failed:",
          error
        );

        setLedgerOnline(false);
        setLedgerRecords(null);
      }

      setLastChecked(new Date());
    } finally {
      setChecking(false);
    }
  };

  useEffect(() => {
    checkSystem();
  }, []);

  const platformOperational =
    backendOnline &&
    nlpOnline &&
    ledgerOnline;

  const getModuleStatus = (
    moduleType
  ) => {
    // Dedicated NLP runtime verification
    if (moduleType === "nlp") {
      const available =
        backendOnline &&
        nlpOnline;

      return {
        available,
        label: available
          ? "Runtime Verified"
          : "Unavailable",
      };
    }

    // Durable ledger is verified through
    // a real persistence query.
    if (moduleType === "eel") {
      const available =
        backendOnline &&
        ledgerOnline;

      return {
        available,
        label: available
          ? "Runtime Verified"
          : "Unavailable",
      };
    }

    // These capabilities are integrated into
    // the backend investigation pipeline, but
    // do not currently expose dedicated health
    // endpoints. Do not claim runtime verification.
    return {
      available: backendOnline,
      label: backendOnline
        ? "Integrated"
        : "Backend Offline",
    };
  };

  return (
    <div className="settings-page">
      {/* ===================================================
          HEADER
      ==================================================== */}

      <section className="settings-header">
        <div>
          <div className="settings-eyebrow">
            <Settings2 size={13} />

            PLATFORM CONTROL CENTER
          </div>

          <h1>
            Platform &amp; System
          </h1>

          <p>
            Monitor SecureSense AI platform
            capabilities, intelligence modules,
            persistence services and runtime
            availability.
          </p>
        </div>

        <button
          type="button"
          className="settings-refresh-button"
          onClick={checkSystem}
          disabled={checking}
        >
          <RefreshCw
            size={15}
            className={
              checking
                ? "settings-spinning"
                : ""
            }
          />

          {checking
            ? "Checking"
            : "Refresh Status"}
        </button>
      </section>

      {/* ===================================================
          PLATFORM STATUS
      ==================================================== */}

      <section className="settings-platform-banner">
        <div className="settings-platform-icon">
          {platformOperational ? (
            <ShieldCheck size={25} />
          ) : (
            <Shield size={25} />
          )}
        </div>

        <div className="settings-platform-copy">
          <span>
            SECURESENSE AI PLATFORM
          </span>

          <h2>
            {checking
              ? "Checking System Status"
              : platformOperational
              ? "Security Platform Operational"
              : "Platform Attention Required"}
          </h2>

          <p>
            Runtime status is derived from
            available SecureSense backend
            services and persistence checks.
          </p>
        </div>

        <StatusBadge
          available={platformOperational}
          label={
            checking
              ? "Checking"
              : platformOperational
              ? "Operational"
              : "Degraded"
          }
        />
      </section>

      {/* ===================================================
          RUNTIME SERVICES
      ==================================================== */}

      <section className="settings-section">
        <div className="settings-section-heading">
          <div>
            <span>
              RUNTIME STATUS
            </span>

            <h2>
              Platform Services
            </h2>

            <p>
              Live availability checks against
              implemented SecureSense services.
            </p>
          </div>

          <Activity size={18} />
        </div>

        <div className="settings-service-grid">
          {/* Backend API */}

          <article className="settings-service-card">
            <div className="settings-service-icon">
              <Server size={19} />
            </div>

            <div>
              <span>
                BACKEND API
              </span>

              <strong>
                SecureSense API
              </strong>

              <small>
                http://127.0.0.1:8000
              </small>
            </div>

            <StatusBadge
              available={backendOnline}
              label={
                backendOnline
                  ? "Runtime Verified"
                  : "Unavailable"
              }
            />
          </article>

          {/* NLP */}

          <article className="settings-service-card">
            <div className="settings-service-icon">
              <Brain size={19} />
            </div>

            <div>
              <span>
                MULTI-MODAL INTELLIGENCE
              </span>

              <strong>
                NLP Intelligence
              </strong>

              <small>
                /nlp/health
              </small>
            </div>

            <StatusBadge
              available={nlpOnline}
              label={
                nlpOnline
                  ? "Runtime Verified"
                  : "Unavailable"
              }
            />
          </article>

          {/* Evidence Ledger */}

          <article className="settings-service-card">
            <div className="settings-service-icon">
              <Database size={19} />
            </div>

            <div>
              <span>
                EVIDENCE PERSISTENCE
              </span>

              <strong>
                Durable Ledger
              </strong>

              <small>
                {ledgerRecords === null
                  ? "Evidence storage"
                  : `${ledgerRecords} persisted evidence records`}
              </small>
            </div>

            <StatusBadge
              available={ledgerOnline}
              label={
                ledgerOnline
                  ? "Runtime Verified"
                  : "Unavailable"
              }
            />
          </article>
        </div>

        {lastChecked && (
          <div className="settings-last-check">
            <CheckCircle2 size={13} />

            Last runtime check:{" "}
            {lastChecked.toLocaleString()}
          </div>
        )}
      </section>

      {/* ===================================================
          INTELLIGENCE MODULES
      ==================================================== */}

      <section className="settings-section">
        <div className="settings-section-heading">
          <div>
            <span>
              PLATFORM MODULES
            </span>

            <h2>
              SecureSense Modules
            </h2>

            <p>
              Intelligence capabilities integrated
              into the communication investigation
              pipeline.
            </p>
          </div>

          <Fingerprint size={18} />
        </div>

        <div className="settings-modules-grid">
          {MODULES.map((module) => {
            const Icon = module.icon;

            const moduleStatus =
              getModuleStatus(
                module.type
              );

            return (
              <article
                className="settings-module-card"
                key={module.name}
              >
                <div className="settings-module-top">
                  <div className="settings-module-icon">
                    <Icon size={18} />
                  </div>

                  <StatusBadge
                    available={
                      moduleStatus.available
                    }
                    label={
                      moduleStatus.label
                    }
                  />
                </div>

                <h3>
                  {module.name}
                </h3>

                <p>
                  {module.description}
                </p>
              </article>
            );
          })}
        </div>
      </section>

      {/* ===================================================
          SECURITY PIPELINE
      ==================================================== */}

      <section className="settings-section">
        <div className="settings-section-heading">
          <div>
            <span>
              INVESTIGATION PIPELINE
            </span>

            <h2>
              Security Architecture
            </h2>

            <p>
              Core processing stages used by
              SecureSense communication
              investigations.
            </p>
          </div>

          <ShieldCheck size={18} />
        </div>

        <div className="settings-pipeline">

  <div className="settings-pipeline-step">
    <span>01</span>
    <strong>Communication Ingestion</strong>
    <small>
      Emails • SMS • Website URLs • PDFs • Images • QR Codes • Voice Recordings
    </small>
  </div>

  <div className="settings-pipeline-arrow">→</div>

  <div className="settings-pipeline-step">
    <span>02</span>
    <strong>Multi-Modal Intelligence</strong>
    <small>
      NLP • Computer Vision • OCR • Voice • URL • Metadata
    </small>
  </div>

  <div className="settings-pipeline-arrow">→</div>

  <div className="settings-pipeline-step">
    <span>03</span>
    <strong>Trust Verification Engine</strong>
    <small>
      Authenticity Verification • Domain Validation • QR Verification • Metadata Consistency
    </small>
  </div>

  <div className="settings-pipeline-arrow">→</div>

  <div className="settings-pipeline-step">
    <span>04</span>
    <strong>Trust Intelligence Engine</strong>
    <small>
      Evidence Fusion • Risk Assessment • Explainable AI • Trust Decision
    </small>
  </div>

  <div className="settings-pipeline-arrow">→</div>

  <div className="settings-pipeline-step">
    <span>05</span>
    <strong>Financial Communication Passport (FCP)</strong>
    <small>
      Standardized Trust Profile
    </small>
  </div>

  <div className="settings-pipeline-arrow">→</div>

  <div className="settings-pipeline-step">
    <span>06</span>
    <strong>Securities Trust Graph (STG)</strong>
    <small>
      Campaign Correlation & Entity Relationships
    </small>
  </div>

  <div className="settings-pipeline-arrow">→</div>

  <div className="settings-pipeline-step">
    <span>07</span>
    <strong>Explainable Evidence Ledger (EEL)</strong>
    <small>
      Evidence Provenance & Investigation Records
    </small>
  </div>

</div>
      </section>

      {/* ===================================================
          PLATFORM INFORMATION
      ==================================================== */}

      <section className="settings-section">
        <div className="settings-section-heading">
          <div>
            <span>
              PLATFORM INFORMATION
            </span>

            <h2>
              Deployment Profile
            </h2>

            <p>
              Current frontend and backend
              deployment context for this
              SecureSense workspace.
            </p>
          </div>

          <Server size={18} />
        </div>

        <div className="settings-info-grid">
          <div>
            <span>
              Platform
            </span>

            <strong>
              SecureSense AI
            </strong>
          </div>

          <div>
            <span>
              API Endpoint
            </span>

            <strong>
              127.0.0.1:8000
            </strong>
          </div>

          <div>
            <span>
              Environment
            </span>

            <strong>
              Local Development
            </strong>
          </div>

          <div>
            <span>
              Evidence Persistence
            </span>

            <strong>
              {ledgerOnline
                ? "Durable"
                : "Unavailable"}
            </strong>
          </div>
        </div>
      </section>

      {/* ===================================================
          QUICK ACTIONS
      ==================================================== */}

      <section className="settings-actions">
        <div>
          <span>
            SECURESENSE OPERATIONS
          </span>

          <strong>
            Security Investigation Workspace
          </strong>

          <small>
            Start a new analysis or inspect recent
            persisted investigations.
          </small>
        </div>

        <div className="settings-action-buttons">
          <Link
            to="/upload"
            className="settings-secondary-button"
          >
            <Upload size={14} />

            New Investigation
          </Link>

          <Link
            to="/reports"
            className="settings-primary-button"
          >
            Investigation Reports

            <ExternalLink size={14} />
          </Link>
        </div>
      </section>
    </div>
  );
}