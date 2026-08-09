import { useEffect, useMemo, useState } from "react";
import {
  Link,
  useParams,
} from "react-router-dom";

import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  BrainCircuit,
  CheckCircle2,
  Database,
  ExternalLink,
  FileText,
  GitBranch,
  Link2,
  Network,
  Search,
  Shield,
  ShieldCheck,
  ShieldQuestion,
  Users,
} from "lucide-react";

import { getCommunication } from "../services/api";


/* =========================================================
   Helpers
========================================================= */

function formatScore(value, digits = 2) {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return "N/A";
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "N/A";
  }

  return number.toFixed(digits);
}


function yesNo(value) {
  return value ? "Yes" : "No";
}


function getClassificationClass(classification) {
  const value = String(
    classification || ""
  ).toLowerCase();

  if (
    value.includes("trusted") ||
    value.includes("legitimate") ||
    value.includes("safe")
  ) {
    return "stg-status-good";
  }

  if (
    value.includes("malicious") ||
    value.includes("phishing") ||
    value.includes("high") ||
    value.includes("risky")
  ) {
    return "stg-status-danger";
  }

  if (
    value.includes("suspicious") ||
    value.includes("medium")
  ) {
    return "stg-status-warning";
  }

  return "stg-status-neutral";
}


function shortenIdentifier(value, length = 22) {
  if (!value) {
    return "N/A";
  }

  const stringValue = String(value);

  if (stringValue.length <= length) {
    return stringValue;
  }

  return `${stringValue.slice(
    0,
    Math.max(8, length - 8)
  )}...${stringValue.slice(-6)}`;
}


/* =========================================================
   Small Components
========================================================= */

function MetricCard({
  icon: Icon,
  label,
  value,
  subtext,
  tone = "default",
}) {
  return (
    <div className={`stg-metric-card stg-tone-${tone}`}>
      <div className="stg-metric-icon">
        <Icon size={18} />
      </div>

      <div className="stg-metric-content">
        <span className="stg-metric-label">
          {label}
        </span>

        <strong className="stg-metric-value">
          {value}
        </strong>

        {subtext && (
          <span className="stg-metric-subtext">
            {subtext}
          </span>
        )}
      </div>
    </div>
  );
}


function ReferenceChip({
  value,
  type,
}) {
  return (
    <div className="stg-reference-chip">
      <div className="stg-reference-chip-icon">
        {type === "ledger" ? (
          <Database size={14} />
        ) : (
          <ShieldCheck size={14} />
        )}
      </div>

      <div>
        <span>
          {type === "ledger"
            ? "Ledger ID"
            : "Evidence ID"}
        </span>

        <strong title={value}>
          {shortenIdentifier(value, 28)}
        </strong>
      </div>
    </div>
  );
}


function EmptyGraph({
  communicationId,
  classification,
}) {
  return (
    <div className="stg-graph-empty">
      <div className="stg-empty-visual">
        <div className="stg-empty-ring stg-empty-ring-one" />
        <div className="stg-empty-ring stg-empty-ring-two" />

        <div className="stg-empty-node stg-empty-node-main">
          <FileText size={24} />
        </div>

        <div className="stg-empty-node stg-empty-node-left">
          <Search size={15} />
        </div>

        <div className="stg-empty-node stg-empty-node-right">
          <ShieldQuestion size={15} />
        </div>

        <div className="stg-empty-line stg-empty-line-left" />
        <div className="stg-empty-line stg-empty-line-right" />
      </div>

      <h3>
  No graph relationships available
</h3>

<p>
  The communication was successfully analysed,
  but no entity relationships were returned
  for this Securities Trust Graph snapshot.
</p>

      <div className="stg-empty-meta">
        <span>
          <strong>Communication</strong>
          {shortenIdentifier(
            communicationId,
            26
          )}
        </span>

        <span>
          <strong>Graph Classification</strong>
          {classification || "Unknown"}
        </span>
      </div>
    </div>
  );
}
/* =========================================================
   Visual Trust Graph
   ========================================================= */

function TrustGraphCanvas({
  nodes,
  edges,
}) {
  const safeNodes = Array.isArray(nodes)
    ? nodes
    : [];

  const safeEdges = Array.isArray(edges)
    ? edges
    : [];

  if (
    safeNodes.length === 0 ||
    safeEdges.length === 0
  ) {
    return null;
  }

  const width = 1000;
  const height = 430;

  const centerX = width / 2;
  const centerY = height / 2;

  /*
   * Deterministic circular layout.
   * This keeps the graph stable between renders
   * without requiring another graph library.
   */
  const positionedNodes = safeNodes.map(
    (node, index) => {
      const angle =
        (2 * Math.PI * index) /
        Math.max(safeNodes.length, 1);

      const radius =
        safeNodes.length <= 2
          ? 210
          : Math.min(
              175,
              80 + safeNodes.length * 16
            );

      return {
        ...node,
        x:
          centerX +
          Math.cos(angle) * radius,

        y:
          centerY +
          Math.sin(angle) * radius,
      };
    }
  );

  const nodeMap = new Map(
    positionedNodes.map((node) => [
      node.node_id,
      node,
    ])
  );

  const getNodeLabel = (node) => {
    if (!node) {
      return "Unknown";
    }

    return (
      node.display_name ||
      node.value ||
      node.node_type ||
      "Entity"
    );
  };

  const getNodeType = (node) => {
    if (!node) {
      return "ENTITY";
    }

    return String(
      node.node_type ||
      "ENTITY"
    ).toUpperCase();
  };

  const getNodeTone = (node) => {
    const type = String(
      node?.node_type || ""
    ).toLowerCase();

    if (
      type.includes("url") ||
      type.includes("domain")
    ) {
      return "url";
    }

    if (
      type.includes("qr") ||
      type.includes("phone") ||
      type.includes("email")
    ) {
      return "identity";
    }

    if (
      type.includes("communication") ||
      type.includes("document")
    ) {
      return "communication";
    }

    return "entity";
  };

  return (
    <div className="stg-visual-graph">

      <svg
        className="stg-visual-graph-svg"
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label="Securities Trust Graph entity relationship visualization"
      >

        <defs>

          <marker
            id="stg-arrow"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto-start-reverse"
          >
            <path
              d="M 0 0 L 10 5 L 0 10 z"
              className="stg-edge-arrow"
            />
          </marker>

          <filter
            id="stg-node-shadow"
            x="-30%"
            y="-30%"
            width="160%"
            height="160%"
          >
            <feDropShadow
              dx="0"
              dy="3"
              stdDeviation="4"
              floodOpacity="0.12"
            />
          </filter>

        </defs>


        {/* =================================================
            Edges
            ================================================= */}

        <g className="stg-visual-edges">

          {safeEdges.map((edge) => {

            const source =
              nodeMap.get(
                edge.source_node_id
              );

            const target =
              nodeMap.get(
                edge.target_node_id
              );

            if (!source || !target) {
              return null;
            }

            const dx =
              target.x - source.x;

            const dy =
              target.y - source.y;

            const length =
              Math.sqrt(
                dx * dx +
                dy * dy
              ) || 1;

            /*
             * Keep relationship labels
             * away from the node borders.
             */
            const offset = 52;

            const startX =
              source.x +
              (dx / length) *
                offset;

            const startY =
              source.y +
              (dy / length) *
                offset;

            const endX =
              target.x -
              (dx / length) *
                offset;

            const endY =
              target.y -
              (dy / length) *
                offset;

            const labelX =
              (startX + endX) / 2;

            const labelY =
              (startY + endY) / 2;

            return (
              <g
                key={edge.edge_id}
                className="stg-visual-edge"
              >

                <line
                  x1={startX}
                  y1={startY}
                  x2={endX}
                  y2={endY}
                  markerEnd="url(#stg-arrow)"
                />

                <g
                  transform={`translate(${labelX}, ${labelY})`}
                >

                  <rect
                    x="-48"
                    y="-10"
                    width="96"
                    height="20"
                    rx="10"
                    className="stg-edge-label-bg"
                  />

                  <text
                    textAnchor="middle"
                    dominantBaseline="middle"
                    className="stg-edge-label"
                  >
                    {String(
                      edge.relationship ||
                      "RELATED"
                    ).replace(/_/g, " ")}
                  </text>

                </g>

              </g>
            );
          })}

        </g>


        {/* =================================================
            Nodes
            ================================================= */}

        <g className="stg-visual-nodes">

          {positionedNodes.map(
            (node) => {

              const tone =
                getNodeTone(node);

              const label =
                getNodeLabel(node);

              const type =
                getNodeType(node);

              const shortLabel =
                label.length > 28
                  ? `${label.slice(
                      0,
                      25
                    )}...`
                  : label;

              return (
                <g
                  key={node.node_id}
                  className={`stg-visual-node stg-node-${tone}`}
                  transform={`translate(${node.x}, ${node.y})`}
                >

                  <circle
                    r="45"
                    className="stg-node-circle"
                    filter="url(#stg-node-shadow)"
                  />

                  <circle
                    r="36"
                    className="stg-node-inner"
                  />

                  <text
                    y="-5"
                    textAnchor="middle"
                    className="stg-node-type"
                  >
                    {type}
                  </text>

                  <text
                    y="11"
                    textAnchor="middle"
                    className="stg-node-label"
                  >
                    {shortLabel}
                  </text>

                </g>
              );
            }
          )}

        </g>

      </svg>


      {/* ===================================================
          Graph Legend
          =================================================== */}

      <div className="stg-graph-legend">

        <span>
          <i className="stg-legend-dot stg-legend-communication" />
          Communication
        </span>

        <span>
          <i className="stg-legend-dot stg-legend-url" />
          URL / Domain
        </span>

        <span>
          <i className="stg-legend-dot stg-legend-identity" />
          Identity
        </span>

        <span>
          <i className="stg-legend-dot stg-legend-entity" />
          Entity
        </span>

      </div>

    </div>
  );
}

/* =========================================================
   Page
========================================================= */

export default function TrustGraph() {
  const { communicationId } = useParams();

  const [communication, setCommunication] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");


  /* -------------------------------------------------------
     Load communication
  ------------------------------------------------------- */

  useEffect(() => {
    let active = true;

    const loadTrustGraph = async () => {
      if (!communicationId) {
        if (active) {
          setError(
            "No communication ID was provided."
          );

          setLoading(false);
        }

        return;
      }

      try {
        setLoading(true);
        setError("");

        const data =
          await getCommunication(
            communicationId
          );

        if (active) {
          setCommunication(data);
        }
      } catch (err) {
        console.error(
          "Failed to load Securities Trust Graph:",
          err
        );

        if (active) {
          setError(
            err?.response?.data?.detail ||
              "Unable to load Securities Trust Graph data."
          );
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    };

    loadTrustGraph();

    return () => {
      active = false;
    };
  }, [communicationId]);


  /* -------------------------------------------------------
     Resolve STG
  ------------------------------------------------------- */

  const stg = useMemo(() => {
    return (
      communication?.passport
        ?.securities_trust_graph ||
      communication?.securities_trust_graph ||
      null
    );
  }, [communication]);


  /* -------------------------------------------------------
     Loading
  ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="stg-page">
        <div className="stg-state-card">
          <div className="stg-loader">
            <Network size={28} />
          </div>

          <span className="stg-eyebrow">
            SECURITIES TRUST GRAPH
          </span>

          <h2>
            Building trust intelligence view
          </h2>

          <p>
            Loading historical entity context,
            relationships and evidence provenance...
          </p>
        </div>
      </div>
    );
  }


  /* -------------------------------------------------------
     Missing ID / error
  ------------------------------------------------------- */

  if (error) {
    return (
      <div className="stg-page">
        <div className="stg-state-card">
          <div className="stg-state-icon stg-state-warning">
            <AlertTriangle size={26} />
          </div>

          <span className="stg-eyebrow">
            SECURITIES TRUST GRAPH
          </span>

          <h2>
            Graph intelligence unavailable
          </h2>

          <p>{error}</p>

          <Link
            to={
              communicationId
                ? `/analysis/${encodeURIComponent(
                    communicationId
                  )}`
                : "/analysis"
            }
            className="stg-primary-button"
          >
            <ArrowLeft size={15} />
            Return to Investigation
          </Link>
        </div>
      </div>
    );
  }


  /* -------------------------------------------------------
     No STG
  ------------------------------------------------------- */

  if (!stg) {
    return (
      <div className="stg-page">
        <div className="stg-state-card">
          <div className="stg-state-icon">
            <ShieldQuestion size={26} />
          </div>

          <span className="stg-eyebrow">
            SECURITIES TRUST GRAPH
          </span>

          <h2>
            No graph context available
          </h2>

          <p>
            SecureSense AI did not return a
            Securities Trust Graph snapshot for
            this communication.
          </p>

          <Link
            to={`/analysis/${encodeURIComponent(
              communicationId
            )}`}
            className="stg-primary-button"
          >
            <ArrowLeft size={15} />
            Return to Investigation
          </Link>
        </div>
      </div>
    );
  }


  /* -------------------------------------------------------
     STG fields
  ------------------------------------------------------- */

  const relationship =
    stg.relationship_context || {};

  const contexts =
    Array.isArray(relationship.contexts)
      ? relationship.contexts
      : [];

  const graphNodes =
  Array.isArray(stg.nodes)
    ? stg.nodes
    : [];

const graphEdges =
  Array.isArray(stg.edges)
    ? stg.edges
    : [];

  const evidenceIds =
    Array.isArray(stg.evidence_ids)
      ? stg.evidence_ids
      : [];

  const ledgerIds =
    Array.isArray(stg.ledger_ids)
      ? stg.ledger_ids
      : [];

  const relationshipEvidenceIds =
    Array.isArray(
      relationship.evidence_ids
    )
      ? relationship.evidence_ids
      : [];

  const relationshipLedgerIds =
    Array.isArray(
      relationship.ledger_ids
    )
      ? relationship.ledger_ids
      : [];

  const entitiesAnalysed =
    stg.entities_analysed ?? 0;

  const relationshipSignals =
    relationship.total_signals ?? 0;

  const graphHasRelationships =
  graphNodes.length > 0 &&
  graphEdges.length > 0;

  const classification =
    stg.classification || "Unknown";

  const communicationRisk =
    communication?.risk_score;

  const communicationRiskLevel =
    communication?.risk_level || "Unknown";


  return (
    <div className="stg-page">

      {/* ===================================================
          Header
      =================================================== */}

      <section className="stg-header">
        <div>
          <div className="stg-header-label">
            <Network size={13} />

            SECURITIES TRUST GRAPH (STG)
          </div>

          <h1>
            Historical Entity Trust Intelligence
          </h1>

          <p className="stg-header-description">
            Historical trust intelligence derived from previously observed entities, relationship analysis and explainable SecureSense evidence.
          </p>

          <div className="stg-header-meta">
            <span>
    Communication&nbsp;

    <strong>
        {communication?.communication_id}
    </strong>
</span>

            <span>•</span>

            <span>
              {communication?.filename ||
                "Text Communication"}
            </span>

            <span>•</span>

            <span>
    {communication?.document_type ||
        communication?.file_type ||
        "Unknown"}
</span>
          </div>
        </div>

        <div className="stg-header-actions">
          <div
            className={`stg-classification-badge ${getClassificationClass(
              classification
            )}`}
          >
            <ShieldCheck size={14} />

            {classification}
          </div>

          <Link
            to={`/analysis/${encodeURIComponent(
              communicationId
            )}`}
            className="stg-secondary-button"
          >
            <ArrowLeft size={14} />
            Investigation
          </Link>
        </div>
      </section>


      {/* ===================================================
          Intelligence Summary
      =================================================== */}

      <section className="stg-summary-panel">
        <div className="stg-summary-primary">
          <div className="stg-summary-icon">
            <Network size={26} />
          </div>

          <div>
            <span className="stg-eyebrow">
              TRUST INTELLIGENCE ENGINE
            </span>

            <h2>
              {classification}
            </h2>

            <p>
              {stg.reputation_available
                ? "Historical reputation intelligence is available for this communication."
                : "No historical entity reputation was available for this communication."}
            </p>
          </div>
        </div>

        <div className="stg-summary-stats">
          <div>
            <span>Graph Risk</span>
            <strong>
              {formatScore(
                stg.graph_risk_score
              )}
            </strong>
          </div>

          <div>
            <span>Graph Trust</span>
            <strong>
              {formatScore(
                stg.graph_trust_score
              )}
            </strong>
          </div>
        </div>
      </section>

      {/* ===================================================
          Metrics
      =================================================== */}

      <section className="stg-metrics-grid">
        <MetricCard
          icon={Database}
          label="STG Status"
          value={
            stg.available
              ? "Available"
              : "Unavailable"
          }
          subtext="Graph processing state"
          tone={
            stg.available
              ? "good"
              : "neutral"
          }
        />

        <MetricCard
          icon={Users}
          label="Entities Analysed"
          value={entitiesAnalysed}
          subtext="Supported extracted entities"
        />

        <MetricCard
          icon={Activity}
          label="Reputation"
          value={
            stg.reputation_available
              ? "Available"
              : "Unavailable"
          }
          subtext="Historical reputation context"
          tone={
            stg.reputation_available
              ? "good"
              : "neutral"
          }
        />

        <MetricCard
          icon={GitBranch}
          label="Relationship Signals"
          value={relationshipSignals}
          subtext="Graph-derived signals"
        />
      </section>


      {/* ===================================================
          Graph Visualization
      =================================================== */}

      <section className="stg-section-card">
        <div className="stg-section-heading">
          <div>
            <span className="stg-eyebrow">
              SECURITIES TRUST GRAPH
            </span>

            <h2>
              Entity Relationship Graph
            </h2>
          </div>

          <Network size={18} />
        </div>

        <div className="stg-graph-meta-row">
          <span>
            <strong>
              {entitiesAnalysed}
            </strong>{" "}
            entities
          </span>

          <span>
  <strong>
    {relationship.contexts_analysed ??
      contexts.length}
  </strong>{" "}
  relationship contexts
</span>

          <span>
            <strong>
              {relationshipSignals}
            </strong>{" "}
            signals
          </span>
        </div>

        {!graphHasRelationships ? (
  <EmptyGraph
    communicationId={
      communicationId
    }
    classification={
      classification
    }
  />
) : (
  <>

    <TrustGraphCanvas
      nodes={graphNodes}
      edges={graphEdges}
    />

  </>
)}

        {relationship.summary && (
          <div className="stg-graph-summary">
            <Activity size={15} />

            <div>
              <strong>
                Relationship Analysis
              </strong>

              <p>
                {relationship.summary}
              </p>
            </div>
          </div>
        )}
      </section>


      {/* ===================================================
          Graph Assessment
      =================================================== */}

      <section className="stg-section-card">
        <div className="stg-section-heading">
          <div>
            <span className="stg-eyebrow">
              TRUST INTELLIGENCE ENGINE
            </span>

            <h2>
              Graph Assessment
            </h2>
          </div>

          <ShieldCheck size={18} />
        </div>

        <div className="stg-assessment-grid">
          <div className="stg-assessment-item">
            <span>STG Available</span>
            <strong>
              {yesNo(stg.available)}
            </strong>
          </div>

          <div className="stg-assessment-item">
            <span>
              Reputation Available
            </span>
            <strong>
              {yesNo(
                stg.reputation_available
              )}
            </strong>
          </div>

          <div className="stg-assessment-item">
            <span>Classification</span>
            <strong>
              {classification}
            </strong>
          </div>

          <div className="stg-assessment-item">
            <span>Graph Risk Score</span>
            <strong>
              {formatScore(
                stg.graph_risk_score
              )}
            </strong>
          </div>

          <div className="stg-assessment-item">
            <span>Graph Trust Score</span>
            <strong>
              {formatScore(
                stg.graph_trust_score
              )}
            </strong>
          </div>
        </div>

        {stg.summary && (
          <div className="stg-assessment-summary">
            <ShieldQuestion size={17} />

            <div>
              <span>Graph Context</span>

              <p>{stg.summary}</p>
            </div>
          </div>
        )}
      </section>


      {/* ===================================================
          Evidence Provenance
      =================================================== */}

      <section className="stg-section-card">
        <div className="stg-section-heading">
          <div>
            <span className="stg-eyebrow">
              EXPLAINABLE EVIDENCE
            </span>

            <h2>
              Graph Evidence Provenance
            </h2>
          </div>

          <Database size={18} />
        </div>

        <div className="stg-evidence-counts">
          <div>
            <strong>
              {evidenceIds.length}
            </strong>

            <span>Evidence Records</span>
          </div>

          <div>
            <strong>
              {ledgerIds.length}
            </strong>

            <span>Ledger References</span>
          </div>

          <div>
            <strong>
              {
                relationshipEvidenceIds.length
              }
            </strong>

            <span>
              Relationship Evidence
            </span>
          </div>
        </div>

        {evidenceIds.length > 0 ||
        ledgerIds.length > 0 ? (
          <div className="stg-reference-grid">
            {evidenceIds.map((id) => (
              <ReferenceChip
                key={id}
                value={id}
                type="evidence"
              />
            ))}

            {ledgerIds.map((id) => (
              <ReferenceChip
                key={id}
                value={id}
                type="ledger"
              />
            ))}
          </div>
        ) : (
          <div className="stg-empty-evidence">
            No STG evidence references were
            recorded.
          </div>
        )}

        {(relationshipEvidenceIds.length >
          0 ||
          relationshipLedgerIds.length >
            0) && (
          <div className="stg-relationship-evidence">
            <h3>
              Relationship-Specific Provenance
            </h3>

            <div className="stg-reference-grid">
              {relationshipEvidenceIds.map(
                (id) => (
                  <ReferenceChip
                    key={id}
                    value={id}
                    type="evidence"
                  />
                )
              )}

              {relationshipLedgerIds.map(
                (id) => (
                  <ReferenceChip
                    key={id}
                    value={id}
                    type="ledger"
                  />
                )
              )}
            </div>
          </div>
        )}
      </section>


      {/* ===================================================
          Bottom Navigation
      =================================================== */}

      <section className="stg-footer-navigation">
        <div className="stg-footer-brand">
          <div>
            <Network size={18} />
          </div>

          <span>
            <strong>
              SecureSense Securities Trust Graph (STG)
            </strong>
            Historical trust intelligence for explainable financial communication investigations.
          </span>
        </div>

        <div className="stg-footer-actions">
          <Link
            to={`/analysis/${encodeURIComponent(
              communicationId
            )}`}
            className="stg-secondary-button"
          >
            <ArrowLeft size={14} />
            Investigation
          </Link>

          <Link
            to={`/passport/${encodeURIComponent(
              communicationId
            )}`}
            className="stg-secondary-button"
          >
            <ShieldCheck size={14} />
            Passport
          </Link>

          <Link
            to={`/ledger/${encodeURIComponent(
              communicationId
            )}`}
            className="stg-primary-button"
          >
            Evidence Ledger
            <ExternalLink size={14} />
          </Link>
        </div>
      </section>
    </div>
  );
}