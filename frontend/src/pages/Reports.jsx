import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  BarChart3,
  FileText,
  Search,
  ShieldAlert,
  ShieldQuestion,
  Activity,
  ExternalLink,
  RefreshCw,
  FileSearch,
  Database,
  Download,
} from "lucide-react";

import {
  getUploadHistory,
  getCommunication,
  downloadSecurityReport,
} from "../services/api";

const REPORT_LIMIT = 10;

function formatScore(value) {
  if (value === null || value === undefined) {
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
    return "Unknown";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

function normalizeRisk(value) {
  const risk = String(value || "").toLowerCase();

  if (risk === "high") {
    return "High";
  }

  if (risk === "medium") {
    return "Medium";
  }

  if (risk === "low") {
    return "Low";
  }

  return "Unknown";
}

function riskClass(risk) {
  return `reports-risk-badge reports-risk-${String(
    risk || "unknown"
  ).toLowerCase()}`;
}

function getEvidenceCount(item) {
  return (
    item?.evidence_references?.evidence_ids?.length ||
    item?.passport?.evidence?.evidence_ids?.length ||
    0
  );
}

export default function Reports() {
  const [investigations, setInvestigations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [downloadingReport, setDownloadingReport] = useState(null);

  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");

  const loadReports = async (isRefresh = false) => {
    try {
      if (isRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError("");

      // =====================================================
      // 1. Load persisted upload history
      // =====================================================

      const history = await getUploadHistory();

      const historyRecords = Array.isArray(history)
        ? history
        : history?.items ||
          history?.records ||
          history?.history ||
          [];

      // =====================================================
      // 2. Sort history newest -> oldest BEFORE requesting
      //    full communication details.
      //
      //    This is important because Reports only needs the
      //    latest REPORT_LIMIT investigations.
      // =====================================================

      const recentHistory = [...historyRecords]
        .sort((a, b) => {
          const aTime = new Date(
            a?.uploaded_at || 0
          ).getTime();

          const bTime = new Date(
            b?.uploaded_at || 0
          ).getTime();

          return bTime - aTime;
        })
        .slice(0, REPORT_LIMIT);

      // =====================================================
      // 3. Fetch full intelligence ONLY for latest 10
      // =====================================================

      const detailedRecords = await Promise.all(
        recentHistory.map(async (item) => {
          try {
            const communicationId =
              item?.communication_id;

            if (!communicationId) {
              return item;
            }

            const full = await getCommunication(
              communicationId
            );

            return {
              ...item,
              ...full,
            };
          } catch (err) {
            console.error(
              "Unable to load investigation:",
              item?.communication_id,
              err
            );

            // Keep history record visible even if its
            // detailed communication fetch fails.
            return item;
          }
        })
      );

      // Preserve deterministic newest-first ordering.
      detailedRecords.sort((a, b) => {
        const aTime = new Date(
          a?.uploaded_at || 0
        ).getTime();

        const bTime = new Date(
          b?.uploaded_at || 0
        ).getTime();

        return bTime - aTime;
      });

      setInvestigations(detailedRecords);
    } catch (err) {
      console.error(
        "Failed to load reports:",
        err
      );

      setError(
        err?.response?.data?.detail ||
          "Unable to load SecureSense investigation reports."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleDownloadReport = async (
  communicationId
) => {
  if (!communicationId) {
    return;
  }

  try {
    setDownloadingReport(communicationId);

    await downloadSecurityReport(
      communicationId
    );
  } catch (err) {
    console.error(
      "Failed to download security report:",
      err
    );

    setError(
      err?.response?.data?.detail ||
        "Unable to download the security investigation report."
    );
  } finally {
    setDownloadingReport(null);
  }
};

  useEffect(() => {
    loadReports();
  }, []);

  // =========================================================
  // Statistics
  // All statistics describe ONLY the latest investigations
  // currently loaded into the report.
  // =========================================================

const statistics = useMemo(() => {
  const recent = investigations.length;

  const completed = investigations.filter(
    (item) =>
      String(item?.status || "").toLowerCase() ===
      "completed"
  ).length;

  const high = investigations.filter(
    (item) =>
      normalizeRisk(item?.risk_level) === "High"
  ).length;

  const medium = investigations.filter(
    (item) =>
      normalizeRisk(item?.risk_level) === "Medium"
  ).length;

  const low = investigations.filter(
    (item) =>
      normalizeRisk(item?.risk_level) === "Low"
  ).length;

  const threatsDetected = investigations.filter((item) => {
    const status = String(
      item?.status || ""
    ).toLowerCase();

    if (status !== "completed") {
      return false;
    }

    const decision = String(
      item?.multimodal_fusion?.decision ||
        item?.nlp?.label ||
        item?.nlp_result?.label ||
        ""
    )
      .trim()
      .toLowerCase();

    return (
      decision === "phishing" ||
      decision === "spam"
    );
  }).length;

  const evidenceRecords = investigations.reduce(
    (total, item) =>
      total + getEvidenceCount(item),
    0
  );

  return {
    recent,
    completed,
    high,
    medium,
    low,
    threatsDetected,
    evidenceRecords,
  };
}, [investigations]);

  // =========================================================
  // Search + filters
  // Operate only over the latest 10 investigations.
  // =========================================================

  const filteredInvestigations = useMemo(() => {
    const query = search.trim().toLowerCase();

    return investigations.filter((item) => {
      const risk = normalizeRisk(
        item?.risk_level
      );

      const status =
        item?.status || "Unknown";

      const matchesSearch =
        !query ||
        String(
          item?.communication_id || ""
        )
          .toLowerCase()
          .includes(query) ||
        String(item?.filename || "")
          .toLowerCase()
          .includes(query) ||
        String(item?.document_type || "")
          .toLowerCase()
          .includes(query) ||
        String(
          item?.multimodal_fusion?.decision ||
            item?.nlp?.label ||
            item?.nlp_result?.label ||
            ""
        )
          .toLowerCase()
          .includes(query);

      const matchesRisk =
        riskFilter === "All" ||
        risk === riskFilter;

      const matchesStatus =
        statusFilter === "All" ||
        String(status).toLowerCase() ===
          statusFilter.toLowerCase();

      return (
        matchesSearch &&
        matchesRisk &&
        matchesStatus
      );
    });
  }, [
    investigations,
    search,
    riskFilter,
    statusFilter,
  ]);

  // =========================================================
  // Loading
  // =========================================================

  if (loading) {
    return (
      <div className="reports-page">
        <div className="reports-loading">
          <div className="reports-loading-icon">
            <Activity size={22} />
          </div>

          <h2>
            Building Investigation Reports
          </h2>

          <p>
            SecureSense is loading the latest
            persisted communication intelligence
            and security assessments.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="reports-page">
      {/* =====================================================
          HEADER
      ====================================================== */}

      <section className="reports-header">
        <div>
          <div className="reports-eyebrow">
            <BarChart3 size={13} />
            SECURITY REPORTING
          </div>

          <h1>Investigation Reports</h1>

          <p>
            Review completed SecureSense investigations, risk classifications, explainable evidence, and downloadable security reports.
          </p>
        </div>

        <button
          type="button"
          className="reports-refresh-button"
          onClick={() => loadReports(true)}
          disabled={refreshing}
        >
          <RefreshCw
            size={15}
            className={
              refreshing
                ? "reports-spinning"
                : ""
            }
          />

          {refreshing
            ? "Refreshing"
            : "Refresh Reports"}
        </button>
      </section>

      {/* =====================================================
          ERROR
      ====================================================== */}

      {error && (
        <div className="reports-error">
          <ShieldAlert size={18} />

          <div>
            <strong>
              Reports unavailable
            </strong>

            <span>{error}</span>
          </div>
        </div>
      )}

      {/* =====================================================
          NON-DUPLICATED SUMMARY
      ====================================================== */}

      <section className="reports-summary-grid">
        <div className="reports-stat-card">
          <div className="reports-stat-icon">
            <FileText size={18} />
          </div>

          <div>
            <span>
              Recent Investigations
            </span>

            <strong>
              {statistics.recent}
            </strong>

            <small>
              Latest persisted analyses
            </small>
          </div>
        </div>

        <div className="reports-stat-card">
          <div className="reports-stat-icon">
            <ShieldAlert size={18} />
          </div>

          <div>
            <span>
              Threats Detected
            </span>

            <strong>
              {statistics.threatsDetected}
            </strong>

            <small>
              Recent security threats
            </small>
          </div>
        </div>

        <div className="reports-stat-card">
          <div className="reports-stat-icon">
            <Database size={18} />
          </div>

          <div>
            <span>
              Evidence Records
            </span>

            <strong>
              {statistics.evidenceRecords}
            </strong>

            <small>
              Evidence across recent cases
            </small>
          </div>
        </div>
      </section>

      {/* =====================================================
          SECURITY CLASSIFICATION
      ====================================================== */}

      <section className="reports-risk-overview">
        <div className="reports-section-heading">
          <div>
            <span className="reports-section-label">
              RISK INTELLIGENCE
            </span>

            <h2>
              Security Classification Overview
            </h2>

            <p>
              Distribution across the latest{" "}
              {statistics.recent} persisted
              investigations.
            </p>
          </div>

          <ShieldQuestion size={18} />
        </div>

        <div className="reports-risk-grid">
          <div className="reports-risk-item">
            <span>High Risk</span>

            <strong>
              {statistics.high}
            </strong>

            <div className="reports-risk-bar">
              <div
                className="reports-risk-fill reports-fill-high"
                style={{
                  width: `${
                    statistics.recent
                      ? (statistics.high /
                          statistics.recent) *
                        100
                      : 0
                  }%`,
                }}
              />
            </div>
          </div>

          <div className="reports-risk-item">
            <span>Medium Risk</span>

            <strong>
              {statistics.medium}
            </strong>

            <div className="reports-risk-bar">
              <div
                className="reports-risk-fill reports-fill-medium"
                style={{
                  width: `${
                    statistics.recent
                      ? (statistics.medium /
                          statistics.recent) *
                        100
                      : 0
                  }%`,
                }}
              />
            </div>
          </div>

          <div className="reports-risk-item">
            <span>Low Risk</span>

            <strong>
              {statistics.low}
            </strong>

            <div className="reports-risk-bar">
              <div
                className="reports-risk-fill reports-fill-low"
                style={{
                  width: `${
                    statistics.recent
                      ? (statistics.low /
                          statistics.recent) *
                        100
                      : 0
                  }%`,
                }}
              />
            </div>
          </div>

          <div className="reports-risk-item">
            <span>Completed</span>

            <strong>
              {statistics.completed}
            </strong>

            <div className="reports-risk-bar">
              <div
                className="reports-risk-fill reports-fill-completed"
                style={{
                  width: `${
                    statistics.recent
                      ? (statistics.completed /
                          statistics.recent) *
                        100
                      : 0
                  }%`,
                }}
              />
            </div>
          </div>
        </div>
      </section>

      {/* =====================================================
          RECENT INVESTIGATIONS
      ====================================================== */}

      <section className="reports-investigations">
        <div className="reports-section-heading">
          <div>
            <span className="reports-section-label">
              RECENT INVESTIGATIONS
            </span>

            <h2>
              Latest Security Investigations
            </h2>

            <p>
              The 10 most recent investigations, updated as new communications are analysed.
            </p>
          </div>

          <Database size={18} />
        </div>

        {/* =================================================
            TOOLBAR
        ================================================== */}

        <div className="reports-toolbar">
          <div className="reports-search">
            <Search size={16} />

            <input
              type="text"
              value={search}
              onChange={(event) =>
                setSearch(event.target.value)
              }
              placeholder="Search recent investigations..."
            />
          </div>

          <select
            value={riskFilter}
            onChange={(event) =>
              setRiskFilter(
                event.target.value
              )
            }
          >
            <option value="All">
              All risk levels
            </option>

            <option value="High">
              High Risk
            </option>

            <option value="Medium">
              Medium Risk
            </option>

            <option value="Low">
              Low Risk
            </option>

            <option value="Unknown">
              Unknown
            </option>
          </select>

          <select
            value={statusFilter}
            onChange={(event) =>
              setStatusFilter(
                event.target.value
              )
            }
          >
            <option value="All">
              All statuses
            </option>

            <option value="Completed">
              Completed
            </option>

            <option value="Failed">
              Failed
            </option>

            <option value="Processing">
              Processing
            </option>
          </select>
        </div>

        <div className="reports-result-count">
          Showing{" "}
          <strong>
            {filteredInvestigations.length}
          </strong>{" "}
          of{" "}
          <strong>
            {investigations.length}
          </strong>{" "}
          recent investigations
        </div>

        {/* =================================================
            EMPTY STATE
        ================================================== */}

        {filteredInvestigations.length === 0 ? (
          <div className="reports-empty">
            <FileSearch size={28} />

            <h3>
              No investigations found
            </h3>

            <p>
              No recent communications match
              the selected report filters.
            </p>
          </div>
        ) : (
          /* ===============================================
             TABLE
          ================================================ */

          <div className="reports-table-wrapper">
            <table className="reports-table">
              <thead>
                <tr>
                  <th>Investigation</th>
                  <th>Content Category</th>
                  <th>Risk</th>
                  <th>Trust Intelligence</th>
                  <th>Evidence</th>
                  <th>Status</th>
                  <th>Submitted</th>
                  <th />
                </tr>
              </thead>

              <tbody>
                {filteredInvestigations.map(
                  (item) => {
                    const risk =
                      normalizeRisk(
                        item?.risk_level
                      );

                    const decision =
                      item?.multimodal_fusion
                        ?.decision ||
                      item?.nlp_result?.label ||
                      "Unavailable";

                    const evidenceCount =
                      getEvidenceCount(item);

                    return (
                      <tr
                        key={
                          item.communication_id
                        }
                      >
                        {/* Investigation */}

                        <td>
                          <div className="reports-file-cell">
                            <div className="reports-file-icon">
                              <FileText
                                size={16}
                              />
                            </div>

                            <div>
                              <strong>
                                {item.filename ||
                                  "Communication"}
                              </strong>

                              <span>
                                {
                                  item.communication_id
                                }
                              </span>

                              <small>
                                {item.file_type ||
                                  "Unknown"}{" "}
                                ·{" "}
                                {item.document_type ||
                                  "Unclassified"}
                              </small>
                            </div>
                          </div>
                        </td>

                        {/* Classification */}

                        <td>
                          {item.document_type ||
                            "Unknown"}
                        </td>

                        {/* Risk */}

                        <td>
                          <span
                            className={riskClass(
                              risk
                            )}
                          >
                            {risk}
                          </span>

                          <small className="reports-risk-score">
                            {formatScore(
                              item.risk_score
                            )}
                          </small>
                        </td>

                        {/* AI Decision */}

                        <td>


                          <strong className="reports-decision">
                            {decision}
                          </strong>
<small>
  {
    item?.communication_intent
      ?.security_intent || "No CII"
  }
</small>
                          <small>
  {
    item?.multimodal_fusion
      ?.override_applied
      ? "Evidence Consensus Applied"
      : (
          item?.multimodal_fusion
            ?.agreement ||
          "No fusion state"
        )
  }
</small>
                        </td>

                        {/* Evidence */}

                        <td>
                          <strong>
                            {evidenceCount}
                          </strong>

                          <small>
                            records
                          </small>
                        </td>

                        {/* Status */}

                        <td>
                          <span
                            className={`reports-status reports-status-${String(
                              item.status ||
                                "unknown"
                            ).toLowerCase()}`}
                          >
                            {item.status ||
                              "Unknown"}
                          </span>
                        </td>

                        {/* Submitted */}

                        <td>
                          <span className="reports-date">
                            {formatDate(
                              item.uploaded_at
                            )}
                          </span>
                        </td>

                        {/* Open */}

                       <td>
  {item.communication_id && (
    <div className="reports-row-actions">
      <Link
        className="reports-open-button"
        to={`/analysis/${encodeURIComponent(
          item.communication_id
        )}`}
      >
        Open

        <ExternalLink size={13} />
      </Link>

      <button
        type="button"
        className="reports-download-button"
        onClick={() =>
          handleDownloadReport(
            item.communication_id
          )
        }
        disabled={
          downloadingReport ===
          item.communication_id
        }
        title="Download Security Report"
        aria-label={`Download security report for ${
          item.filename ||
          item.communication_id
        }`}
      >
        {downloadingReport ===
        item.communication_id ? (
          <RefreshCw
            size={14}
            className="reports-spinning"
          />
        ) : (
          <Download size={14} />
        )}

        PDF
      </button>
    </div>
  )}
</td>
                      </tr>
                    );
                  }
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}