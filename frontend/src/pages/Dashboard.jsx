import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Brain,
  CheckCircle2,
  Clock3,
  Database,
  Eye,
  FileSearch,
  Globe2,
  Network,
  RefreshCw,
  Shield,
  ShieldCheck,
  Upload,
} from "lucide-react";

import api, {
  getCommunication,
  getEvidenceLedger,
  getUploadHistory,
} from "../services/api";

const RECENT_LIMIT = 5;

function normalizeRiskLevel(value) {
  const risk = String(value || "").trim().toLowerCase();

  if (risk === "high" || risk === "critical") return "high";
  if (risk === "medium" || risk === "moderate") return "medium";
  if (risk === "low") return "low";

  return "unknown";
}

function formatDate(value) {
  if (!value) return "Unknown";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  return date.toLocaleString();
}

function formatPercent(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "N/A";
  }

  return `${number.toFixed(2)}%`;
}

function riskClass(level) {
  return `dashboard-risk-${normalizeRiskLevel(level)}`;
}

function statusClass(status) {
  const normalized = String(status || "")
    .trim()
    .toLowerCase();

  if (normalized === "completed") {
    return "dashboard-status-completed";
  }

  if (normalized === "failed") {
    return "dashboard-status-failed";
  }

  return "dashboard-status-processing";
}

function StatCard({
  icon: Icon,
  label,
  value,
  description,
}) {
  return (
    <article className="dashboard-stat-card">
      <div className="dashboard-stat-icon">
        <Icon size={18} />
      </div>

      <div className="dashboard-stat-copy">
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{description}</small>
      </div>
    </article>
  );
}

export default function Dashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const [backendOnline, setBackendOnline] = useState(false);
  const [nlpOnline, setNlpOnline] = useState(false);
  const [ledgerOnline, setLedgerOnline] = useState(false);

  const [history, setHistory] = useState([]);
  const [recentInvestigations, setRecentInvestigations] =
    useState([]);

  const [ledgerTotal, setLedgerTotal] = useState(0);
  const [latestInvestigation, setLatestInvestigation] =
    useState(null);

  const loadDashboard = useCallback(async (manual = false) => {
    if (manual) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }

    setError("");

    /*
     * Run independent platform checks separately.
     * A single unavailable service should not prevent the
     * rest of the dashboard from loading.
     */

    const [
      backendResult,
      nlpResult,
      ledgerResult,
      historyResult,
    ] = await Promise.allSettled([
      api.get("/"),
      api.get("/nlp/health"),
      getEvidenceLedger({
        skip: 0,
        limit: 1,
      }),
      getUploadHistory(),
    ]);

    const backendAvailable =
      backendResult.status === "fulfilled";

    const nlpAvailable =
      nlpResult.status === "fulfilled";

    const ledgerAvailable =
      ledgerResult.status === "fulfilled";

    setBackendOnline(backendAvailable);
    setNlpOnline(nlpAvailable);
    setLedgerOnline(ledgerAvailable);

    if (ledgerAvailable) {
      const total = Number(
        ledgerResult.value?.total ?? 0
      );

      setLedgerTotal(
        Number.isFinite(total) ? total : 0
      );
    } else {
      setLedgerTotal(0);
    }

    if (historyResult.status !== "fulfilled") {
      setHistory([]);
      setRecentInvestigations([]);
      setLatestInvestigation(null);

      setError(
        "Recent investigation data could not be loaded."
      );

      setLoading(false);
      setRefreshing(false);
      return;
    }

    const rawHistory = Array.isArray(
      historyResult.value
    )
      ? historyResult.value
      : [];

    /*
     * Sort newest first instead of assuming backend ordering.
     */

    const sortedHistory = [...rawHistory].sort(
      (a, b) =>
        new Date(b.uploaded_at || 0).getTime() -
        new Date(a.uploaded_at || 0).getTime()
    );

    setHistory(sortedHistory);

    /*
     * Dashboard only needs a small operational window.
     * Fetch full analysis for the latest five records.
     */

    const latestHistory = sortedHistory.slice(
      0,
      RECENT_LIMIT
    );

    const investigationResults =
      await Promise.allSettled(
        latestHistory.map((item) =>
          getCommunication(
            item.communication_id
          )
        )
      );

    const resolved = investigationResults
      .map((result, index) => {
        if (result.status === "fulfilled") {
          return result.value;
        }

        /*
         * Preserve basic history information even if
         * one full communication lookup fails.
         */
        return latestHistory[index];
      })
      .filter(Boolean);

    setRecentInvestigations(resolved);

    const sortedResolved = [...resolved].sort(
      (a, b) =>
        new Date(b?.uploaded_at || 0).getTime() -
        new Date(a?.uploaded_at || 0).getTime()
    );

    setRecentInvestigations(sortedResolved);

    const latestCompleted =
      sortedResolved.find(
        (item) =>
          String(item?.status || "")
            .trim()
            .toLowerCase() === "completed"
      ) || null;

    setLatestInvestigation(latestCompleted);

    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  const platformOperational =
    backendOnline &&
    nlpOnline &&
    ledgerOnline;

  /*
   * Recent risk distribution is intentionally calculated
   * from the dashboard's five-investigation window.
   * It is NOT presented as all-time statistics.
   */
  
  const recentRisk = useMemo(() => {
    const result = {
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
    };

    recentInvestigations.forEach((item) => {
      const status = String(
        item?.status || ""
      )
        .trim()
        .toLowerCase();

      if (status !== "completed") {
        return;
      }

      const level = normalizeRiskLevel(
        item?.risk_level
      );

      result[level] += 1;
    });

    return result;
  }, [recentInvestigations]);

  const completedRecent = useMemo(
    () =>
      recentInvestigations.filter(
        (item) =>
          String(item.status || "")
            .toLowerCase() === "completed"
      ).length,
    [recentInvestigations]
  );

  const latestFusion =
    latestInvestigation?.multimodal_fusion;

  const latestNlp =
    latestInvestigation?.nlp_result;

  const latestVisual =
    latestInvestigation?.visual_result;

  const latestUrls =
    latestInvestigation?.url_results || [];

  const latestEvidence =
    latestInvestigation?.evidence_references;

  if (loading) {
    return (
      <div className="dashboard-page">
        <div className="dashboard-loading">
          <Activity size={24} />
          <strong>Loading Security Operations</strong>
          <span>
            Retrieving SecureSense platform intelligence...
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-page">
      {/* ==================================================
          HEADER
      =================================================== */}

      <section className="dashboard-header">
        <div>
          <div className="dashboard-eyebrow">
            <Shield size={13} />
            SECURITY OPERATIONS
          </div>

          <h1>SecureSense AI Investigation Workspace</h1>

          <p>
            Real-time operational visibility across recent
            SecureSense AI communication investigations,
            multi-modal intelligence and explainable evidence.
          </p>
        </div>

        <div className="dashboard-header-actions">
          <button
            type="button"
            className="dashboard-refresh-button"
            onClick={() => loadDashboard(true)}
            disabled={refreshing}
          >
            <RefreshCw
              size={14}
              className={
                refreshing
                  ? "dashboard-spinning"
                  : ""
              }
            />

            {refreshing
              ? "Refreshing"
              : "Refresh"}
          </button>

          <Link
            to="/upload"
            className="dashboard-investigate-button"
          >
            <Upload size={14} />
            New Investigation
          </Link>
        </div>
      </section>

      {/* ==================================================
          PLATFORM STATUS
      =================================================== */}

      <section className="dashboard-platform-banner">
        <div className="dashboard-platform-icon">
          {platformOperational ? (
            <ShieldCheck size={25} />
          ) : (
            <AlertTriangle size={25} />
          )}
        </div>

        <div className="dashboard-platform-copy">
          <span>Multi-Modal Explainable Trust Intelligence Platform</span>

          <h2>
            {platformOperational
              ? "SecureSense AI Operational"
              : "Platform Attention Required"}
          </h2>

          <p>
            Continuous real-time telemetry across the complete investigation architecture, actively monitoring Multi-Modal Intelligence, Trust Verification Engines, and Evidence Ledgers.
          </p>
        </div>

        <div className="dashboard-service-statuses">

        <span
        className={
          backendOnline
            ? "dashboard-service-online"
            : "dashboard-service-offline"
        }
      >
        <span />
        CI
      </span>
      <span
        className={
          nlpOnline
            ? "dashboard-service-online"
            : "dashboard-service-offline"
        }
      >
        <span />
        MMI
      </span>

      <span
        className={
          backendOnline
            ? "dashboard-service-online"
            : "dashboard-service-offline"
        }
      >
        <span />
        TVE
      </span>

      <span
        className={
          backendOnline
            ? "dashboard-service-online"
            : "dashboard-service-offline"
        }
      >
        <span />
        TIE
      </span>

      <span
        className={
          backendOnline
            ? "dashboard-service-online"
            : "dashboard-service-offline"
        }
      >
        <span />
        FCP
      </span>

      <span
        className={
          backendOnline
            ? "dashboard-service-online"
            : "dashboard-service-offline"
        }
      >
        <span />
        STG
      </span>

      <span
        className={
          ledgerOnline
            ? "dashboard-service-online"
            : "dashboard-service-offline"
        }
      >
        <span />
        EEL
      </span>
    </div>
      </section>

      {error && (
        <div className="dashboard-error">
          <AlertTriangle size={15} />
          {error}
        </div>
      )}

      {/* ==================================================
          OPERATIONAL METRICS
      =================================================== */}

      <section className="dashboard-stat-grid">
        <StatCard
          icon={FileSearch}
          label="Recent Investigations"
          value={recentInvestigations.length}
          description={`Latest ${RECENT_LIMIT} communication window`}
        />

        <StatCard
          icon={AlertTriangle}
          label="High Risk"
          value={recentRisk.high}
          description="High-risk recent investigations"
        />

        <StatCard
          icon={CheckCircle2}
          label="Completed"
          value={completedRecent}
          description="Completed in recent window"
        />

        <StatCard
          icon={Database}
          label="Evidence Records"
          value={ledgerTotal}
          description="Persisted explainable evidence"
        />
      </section>

{/* ==================================================
          INTELLIGENCE SNAPSHOT
      =================================================== */}

      {latestInvestigation && (
        <section className="dashboard-section">
          <div className="dashboard-section-heading">
            <div>
              <span>MULTI-MODAL INTELLIGENCE</span>
              <h2>Latest Intelligence Snapshot</h2>
              <p>
                Security signals generated by the latest
                investigation.
              </p>
            </div>

            <Activity size={18} />
          </div>

          <div className="dashboard-intelligence-grid">
            <article>
              <div className="dashboard-intelligence-icon">
                <Brain size={18} />
              </div>
              <span>NLP SECURITY</span>
              <strong>{latestNlp?.label || "Not Available"}</strong>
              <small>
                {latestNlp
                  ? `${formatPercent(latestNlp.confidence_percent)} confidence`
                  : "No NLP result"}
              </small>
            </article>

            <article>
              <div className="dashboard-intelligence-icon">
                <Eye size={18} />
              </div>
              <span>VISUAL INTELLIGENCE</span>
              <strong>{latestVisual?.label || "Not Available"}</strong>
              <small>
                {latestVisual
                  ? `${formatPercent(latestVisual.confidence_percent)} confidence`
                  : "No visual result"}
              </small>
            </article>

            <article>
              <div className="dashboard-intelligence-icon">
                <Activity size={18} />
              </div>
              <span>VOICE INTELLIGENCE</span>
              <strong>
                {latestInvestigation?.voice?.voice_authenticity?.prediction ||
                 latestInvestigation?.voice?.prediction ||
                 "Not Available"}
              </strong>
              <small>
                {latestInvestigation?.voice
                  ? `${formatPercent(
                      latestInvestigation.voice.voice_authenticity?.confidence ??
                      latestInvestigation.voice?.confidence
                    )} confidence`
                  : "No voice result"}
              </small>
            </article>

            <article>
              <div className="dashboard-intelligence-icon">
                <Globe2 size={18} />
              </div>
              <span>URL INTELLIGENCE</span>
              <strong>{latestUrls.length}</strong>
              <small>
                {latestUrls.length === 1 ? "URL analysed" : "URLs analysed"}
              </small>
            </article>

            <article>
              <div className="dashboard-intelligence-icon">
                <Database size={18} />
              </div>
              <span>EVIDENCE GENERATED</span>
              <strong>{latestEvidence?.evidence_ids?.length ?? 0}</strong>
              <small>Explainable evidence records</small>
            </article>
          </div> {/* <--- CLOSING GRID DIV HERE */}

          {/* MOVED OUTSIDE THE GRID */}
          <div className="dashboard-latest-actions">
            <Link
              to={`/analysis/${encodeURIComponent(
                latestInvestigation.communication_id
              )}`}
            >
              Open Full Investigation
              <ArrowRight size={13} />
            </Link>
          </div>
          
        </section>
      )}
      {/* ==================================================
          RECENT RISK OVERVIEW
      =================================================== */}

      <section className="dashboard-two-column">
        <div className="dashboard-section">
          <div className="dashboard-section-heading">
            <div>
              <span>RECENT RISK</span>
              <h2>Risk Distribution</h2>
              <p>
                Latest {RECENT_LIMIT} investigations only.
              </p>
            </div>

            <Shield size={18} />
          </div>

          <div className="dashboard-risk-overview">
            <div>
              <span>HIGH RISK</span>
              <strong>{recentRisk.high}</strong>
              <div className="dashboard-risk-line dashboard-line-high" />
            </div>

            <div>
              <span>MEDIUM RISK</span>
              <strong>{recentRisk.medium}</strong>
              <div className="dashboard-risk-line dashboard-line-medium" />
            </div>

            <div>
              <span>LOW RISK</span>
              <strong>{recentRisk.low}</strong>
              <div className="dashboard-risk-line dashboard-line-low" />
            </div>
          </div>
        </div>

        <div className="dashboard-section">
          <div className="dashboard-section-heading">
            <div>
              <span>TRUST INTELLIGENCE</span>
              <h2>Core Intelligence Modules</h2>
              <p>
                Integrated SecureSense AI investigation architecture.
              </p>
            </div>

            <Network size={18} />
          </div>

          <div className="dashboard-capability-list">
            <div>
              <Upload size={15} />
              <span>COMMUNICATION INGESTION (CI)</span>
              <strong>ACTIVE</strong>
            </div>

            <div>
              <Brain size={15} />
              <span>MULTI-MODAL INTELLIGENCE (MMI)</span>
              <strong>ACTIVE</strong>
            </div>

            <div>
              <ShieldCheck size={15} />
              <span>TRUST VERIFICATION ENGINE (TVE)</span>
              <strong>ACTIVE</strong>
            </div>

            <div>
              <Network size={15} />
              <span>TRUST INTELLIGENCE ENGINE (TIE)</span>
              <strong>ACTIVE</strong>
            </div>

            <div>
              <Shield size={15} />
              <span>FINANCIAL COMMUNICATION PASSPORT (FCP)</span>
              <strong>GENERATED</strong>
            </div>

            <div>
              <Network size={15} />
              <span>SECURITIES TRUST GRAPH (STG)</span>
              <strong>INTEGRATED</strong>
            </div>

            <div>
              <Database size={15} />
              <span>EXPLAINABLE EVIDENCE LEDGER (EEL)</span>
              <strong>PERSISTENT</strong>
            </div>
          </div>
        </div>
      </section>

      {/* ==================================================
          RECENT INVESTIGATIONS
      =================================================== */}

      <section className="dashboard-section">
        <div className="dashboard-section-heading">
          <div>
            <span>RECENT ACTIVITY</span>
            <h2>Recent Investigations</h2>
            <p>
              The latest communications processed by
              SecureSense AI.
            </p>
          </div>

          <FileSearch size={18} />
        </div>

        <div className="dashboard-recent-list">
          {recentInvestigations.length === 0 ? (
            <div className="dashboard-empty-row">
              No recent investigations.
            </div>
          ) : (
            recentInvestigations.map((item) => (
              <Link
                key={item.communication_id}
                to={`/analysis/${encodeURIComponent(
                  item.communication_id
                )}`}
                className="dashboard-recent-row"
              >
                <div className="dashboard-recent-file-icon">
                  <FileSearch size={15} />
                </div>

                <div className="dashboard-recent-identity">
                  <strong>
                    {item.filename ||
                      "Pasted Communication"}
                  </strong>

                  <small>
                    {item.communication_id}
                  </small>
                </div>

                <span className="dashboard-recent-type">
                  {item.document_type ||
                    item.file_type ||
                    "Unknown"}
                </span>

                <span
                  className={`dashboard-risk-badge ${riskClass(
                    item.risk_level
                  )}`}
                >
                  {item.risk_level || "Unknown"}
                </span>

                <span
                  className={`dashboard-status-badge ${statusClass(
                    item.status
                  )}`}
                >
                  {item.status || "Unknown"}
                </span>

                <ArrowRight
                  size={14}
                  className="dashboard-row-arrow"
                />
              </Link>
            ))
          )}
        </div>

        <div className="dashboard-view-reports">
          <Link to="/reports">
            View Investigation Reports
            <ArrowRight size={13} />
          </Link>
        </div>
      </section>
    </div>
  );
}