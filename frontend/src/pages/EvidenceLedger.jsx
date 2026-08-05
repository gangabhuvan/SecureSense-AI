import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Brain,
  ChevronDown,
  ChevronUp,
  Database,
  Eye,
  FileSearch,
  Search,
  ShieldCheck,
} from "lucide-react";

import { getEvidenceLedger } from "../services/api";


/* =========================================================
   Formatting helpers
   ========================================================= */

function formatPercent(value) {
  if (value === null || value === undefined) {
    return "—";
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "—";
  }

  return `${(number * 100).toFixed(2)}%`;
}


function formatRisk(value) {
  if (value === null || value === undefined) {
    return "—";
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "—";
  }

  return `${number.toFixed(2)}%`;
}


function formatNumber(value, digits = 4) {
  if (value === null || value === undefined) {
    return "—";
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return String(value);
  }

  return number
    .toFixed(digits)
    .replace(/0+$/, "")
    .replace(/\.$/, "");
}


function formatMilliseconds(value) {
  if (value === null || value === undefined) {
    return "—";
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "—";
  }

  if (number >= 1000) {
    return `${(number / 1000).toFixed(2)} s`;
  }

  return `${number.toFixed(2)} ms`;
}


function formatDate(value) {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}


function displayValue(value) {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return "—";
  }

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  if (Array.isArray(value)) {
    return value.length > 0
      ? value.join(", ")
      : "—";
  }

  if (typeof value === "object") {
    return JSON.stringify(value);
  }

  return String(value);
}


function humanize(value) {
  return String(value || "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) =>
      letter.toUpperCase()
    );
}


function getRiskTone(riskScore) {
  const risk = Number(riskScore ?? 0);

  if (risk >= 70) {
    return {
      background: "#FEE2E2",
      color: "#B91C1C",
      border: "#FECACA",
    };
  }

  if (risk >= 30) {
    return {
      background: "#FEF3C7",
      color: "#92400E",
      border: "#FDE68A",
    };
  }

  return {
    background: "#DCFCE7",
    color: "#166534",
    border: "#BBF7D0",
  };
}


function getModuleIcon(module) {
  const normalized = String(
    module || ""
  ).toLowerCase();

  if (normalized.includes("nlp")) {
    return <Brain size={18} />;
  }

  if (
    normalized.includes("visual") ||
    normalized.includes("vision")
  ) {
    return <Eye size={18} />;
  }

  if (normalized.includes("url")) {
    return <ShieldCheck size={18} />;
  }
  if (
    normalized.includes("voice")
  ) {
    return <ShieldCheck size={18} />;
  }

  if (
    normalized.includes("communication") ||
    normalized.includes("intent")
  ) {
    return <Brain size={18} />;
  }
  return <FileSearch size={18} />;
}


/* =========================================================
   Reusable detail components
   ========================================================= */

function DetailItem({
  label,
  value,
  mono = false,
}) {
  return (
  <div
    style={{
      minWidth: 0,
      overflow: "hidden",
    }}
  >
      <div style={labelStyle}>
        {label}
      </div>

      <div
        style={{
          ...valueStyle,
          overflowWrap: "anywhere",
          wordBreak: "normal",
          ...(mono
            ? {
                fontFamily:
                  "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
                fontSize: "13px",
                overflowWrap: "anywhere",
                wordBreak: "break-word",
              }
            : {}),
        }}
      >
        {displayValue(value)}
      </div>
    </div>
  );
}


function EmptyEvidence({ children }) {
  return (
    <div
      style={{
        padding: "14px",
        borderRadius: "9px",
        background: "#F8FAFC",
        border: "1px dashed #CBD5E1",
        color: "#64748B",
        fontSize: "13px",
      }}
    >
      {children}
    </div>
  );
}


/* =========================================================
   NLP Explainability
   ========================================================= */

function NLPExplanation({ nlp }) {
  if (!nlp) {
    return null;
  }

  const tokens = Array.isArray(
    nlp.top_tokens
  )
    ? nlp.top_tokens
    : [];

  return (
    <div style={detailBoxStyle}>
      <h4 style={detailHeadingStyle}>
        <Brain size={18} />
        NLP Explainability
      </h4>

      <div style={detailGridStyle}>
        <DetailItem
          label="Method"
          value={nlp.method}
        />

        <DetailItem
          label="Target Label"
          value={nlp.target_label}
        />

        <DetailItem
          label="Target Probability"
          value={formatPercent(
            nlp.target_probability
          )}
        />

        <DetailItem
          label="IG Steps"
          value={nlp.steps}
        />

        <DetailItem
          label="Token Count"
          value={nlp.token_count}
        />

        <DetailItem
          label="Baseline"
          value={
            nlp.baseline ||
            nlp.baseline_type
          }
        />
      </div>

      {tokens.length > 0 ? (
        <>
          <div
            style={{
              ...labelStyle,
              marginTop: "20px",
              marginBottom: "10px",
            }}
          >
            Most Influential Tokens
          </div>

          <div
            style={{
              overflowX: "auto",
            }}
          >
            <table style={tableStyle}>
              <thead>
                <tr>
                  <th style={thStyle}>
                    Token
                  </th>

                  <th style={thStyle}>
                    Index
                  </th>

                  <th style={thStyle}>
                    Attribution
                  </th>

                  <th style={thStyle}>
                    Strength
                  </th>

                  <th style={thStyle}>
                    Direction
                  </th>
                </tr>
              </thead>

              <tbody>
                {tokens
                  .slice(0, 15)
                  .map((token, index) => {
                    const direction =
                      token.direction ||
                      "unknown";

                    const supports =
                      direction ===
                        "supports_target" ||
                      direction ===
                        "supports";

                    return (
                      <tr
                        key={`${token.token}-${index}`}
                      >
                        <td style={tdStyle}>
                          <strong>
                            {token.token}
                          </strong>
                        </td>

                        <td style={tdStyle}>
                          {token.index ??
                            token.token_index ??
                            "—"}
                        </td>

                        <td style={tdStyle}>
                          {formatNumber(
                            token.attribution ??
                              token.attribution_value ??
                              token.score,
                            6
                          )}
                        </td>

                        <td style={tdStyle}>
                          {formatNumber(
                            token.normalized_strength ??
                              token.strength,
                            4
                          )}
                        </td>

                        <td style={tdStyle}>
                          <span
                            style={{
                              ...directionBadgeStyle,
                              background:
                                supports
                                  ? "#FEE2E2"
                                  : "#E0F2FE",
                              color:
                                supports
                                  ? "#991B1B"
                                  : "#075985",
                            }}
                          >
                            {humanize(
                              direction
                            )}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          </div>
        </>
      ) : (
        <div style={{ marginTop: "16px" }}>
          <EmptyEvidence>
            No token attribution records were
            supplied for this evidence.
          </EmptyEvidence>
        </div>
      )}
    </div>
  );
}


/* =========================================================
   Visual Explainability
   ========================================================= */

function VisualExplanation({ visual }) {
  if (!visual) {
    return null;
  }

  const point =
    visual.max_attention_point || {};

  const normalizedX =
    point.normalized_x ??
    visual.max_attention_x_normalized;

  const normalizedY =
    point.normalized_y ??
    visual.max_attention_y_normalized;

  return (
    <div style={detailBoxStyle}>
      <h4 style={detailHeadingStyle}>
        <Eye size={18} />
        Visual Explainability
      </h4>

      <div style={detailGridStyle}>
        <DetailItem
          label="Method"
          value={visual.method}
        />

        <DetailItem
          label="Target Label"
          value={visual.target_label}
        />

        <DetailItem
          label="Target Probability"
          value={formatPercent(
            visual.target_probability
          )}
        />

        <DetailItem
          label="Target Layer"
          value={visual.target_layer}
        />

        <DetailItem
          label="Mean Attention"
          value={formatNumber(
            visual.mean_attention
          )}
        />

        <DetailItem
          label="Max Attention"
          value={formatNumber(
            visual.max_attention
          )}
        />

        <DetailItem
          label="High Attention Ratio"
          value={formatPercent(
            visual.high_attention_ratio
          )}
        />

        <DetailItem
          label="Image Dimensions"
          value={
            visual.image_width &&
            visual.image_height
              ? `${visual.image_width} × ${visual.image_height}`
              : "—"
          }
        />

        <DetailItem
          label="Attention X"
          value={
            point.x ??
            visual.max_attention_x
          }
        />

        <DetailItem
          label="Attention Y"
          value={
            point.y ??
            visual.max_attention_y
          }
        />

        <DetailItem
          label="Normalized X"
          value={formatNumber(
            normalizedX
          )}
        />

        <DetailItem
          label="Normalized Y"
          value={formatNumber(
            normalizedY
          )}
        />
      </div>
    </div>
  );
}


/* =========================================================
   URL feature contribution evidence
   ========================================================= */

function FeatureEvidence({
  features,
}) {
  if (!Array.isArray(features)) {
    return null;
  }

  if (features.length === 0) {
    return null;
  }

  return (
    <div style={detailBoxStyle}>
      <h4 style={detailHeadingStyle}>
        <ShieldCheck size={18} />
        Feature Contribution Evidence
      </h4>

      <div style={{ overflowX: "auto" }}>
        <table style={tableStyle}>
          <thead>
            <tr>
              <th style={thStyle}>
                Feature
              </th>

              <th style={thStyle}>
                Value
              </th>

              <th style={thStyle}>
                Contribution
              </th>

              <th style={thStyle}>
                Direction
              </th>

              <th style={thStyle}>
                Strength
              </th>
            </tr>
          </thead>

          <tbody>
            {features.map(
              (feature, index) => (
                <tr
                  key={`${feature.feature}-${index}`}
                >
                  <td style={tdStyle}>
                    <strong>
                      {feature.feature}
                    </strong>
                  </td>

                  <td style={tdStyle}>
                    {displayValue(
                      feature.value
                    )}
                  </td>

                  <td style={tdStyle}>
                    {formatNumber(
                      feature.contribution ??
                        feature.shap_value,
                      6
                    )}
                  </td>

                  <td style={tdStyle}>
                    <span
                      style={{
                        ...directionBadgeStyle,
                        background:
                          feature.direction ===
                          "phishing"
                            ? "#FEE2E2"
                            : feature.direction ===
                              "legitimate"
                            ? "#DCFCE7"
                            : "#F1F5F9",
                        color:
                          feature.direction ===
                          "phishing"
                            ? "#991B1B"
                            : feature.direction ===
                              "legitimate"
                            ? "#166534"
                            : "#475569",
                      }}
                    >
                      {humanize(
                        feature.direction
                      )}
                    </span>
                  </td>

                  <td style={tdStyle}>
                    {formatNumber(
                      feature.strength,
                      6
                    )}
                  </td>
                </tr>
              )
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}


/* =========================================================
   Model / inference metadata
   ========================================================= */

function ModelTelemetry({
  evidence,
  model,
}) {
  const supporting =
    evidence.supporting_data || {};

  const probabilities =
    supporting.probabilities ||
    evidence.probabilities ||
    {};

  const probabilityEntries =
    Object.entries(probabilities);

  const inferenceTime =
    supporting.inference_time_ms ??
    evidence.inference_time_ms ??
    model.inference_time_ms;

  const hasModelData =
    Object.keys(model).length > 0 ||
    probabilityEntries.length > 0 ||
    inferenceTime !== undefined;

  if (!hasModelData) {
    return null;
  }

  return (
    <div style={detailBoxStyle}>
      <h4 style={detailHeadingStyle}>
        <Database size={18} />
        Model & Inference Telemetry
      </h4>

      <div style={detailGridStyle}>
        <DetailItem
          label="Module"
          value={model.module}
        />

        <DetailItem
          label="Model Type"
          value={model.model_type}
        />

        <DetailItem
          label="Model File"
          value={model.model_file}
          mono
        />

        <DetailItem
          label="Model Version"
          value={model.model_version}
        />

        <DetailItem
          label="Feature Count"
          value={model.feature_count}
        />

        <DetailItem
          label="Input Size"
          value={
            Array.isArray(
              model.input_size
            )
              ? model.input_size.join(
                  " × "
                )
              : model.input_size
          }
        />

        <DetailItem
          label="Decision Threshold"
          value={formatNumber(
            evidence.decision_threshold ??
              model.decision_threshold,
            6
          )}
        />

        <DetailItem
          label="Inference Time"
          value={formatMilliseconds(
            inferenceTime
          )}
        />
      </div>

      {probabilityEntries.length >
        0 && (
        <>
          <div
            style={{
              ...labelStyle,
              marginTop: "20px",
              marginBottom: "10px",
            }}
          >
            Class Probabilities
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns:
                "repeat(auto-fit, minmax(150px, 1fr))",
              gap: "10px",
            }}
          >
            {probabilityEntries.map(
              ([label, value]) => (
                <div
                  key={label}
                  style={{
                    padding: "12px",
                    borderRadius: "9px",
                    background: "#FFFFFF",
                    border:
                      "1px solid #E2E8F0",
                  }}
                >
                  <div
                    style={labelStyle}
                  >
                    {humanize(label)}
                  </div>

                  <div
                    style={{
                      ...valueStyle,
                      fontSize: "16px",
                    }}
                  >
                    {formatProbabilityPercent(
                      value
                    )}
                  </div>
                </div>
              )
            )}
          </div>
        </>
      )}
    </div>
  );
}

function formatProbabilityPercent(value) {
  if (value === null || value === undefined) {
    return "—";
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "—";
  }

  return `${number.toFixed(4).replace(/0+$/, "").replace(/\.$/, "")}%`;
}

/* =========================================================
   Complete extracted feature vector
   ========================================================= */

function ExtractedFeatureVector({
  supporting,
}) {
  const possibleFeatureObjects = [
    supporting.features,
    supporting.feature_values,
    supporting.extracted_features,
    supporting.url_features,
  ];

  const featureObject =
    possibleFeatureObjects.find(
      (value) =>
        value &&
        typeof value === "object" &&
        !Array.isArray(value)
    );

  if (!featureObject) {
    return null;
  }

  const entries =
    Object.entries(featureObject);

  if (entries.length === 0) {
    return null;
  }

  return (
    <div style={detailBoxStyle}>
      <h4 style={detailHeadingStyle}>
        <FileSearch size={18} />
        Complete Extracted Feature Vector
      </h4>

      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "repeat(auto-fit, minmax(190px, 1fr))",
          gap: "10px",
        }}
      >
        {entries.map(
          ([key, value]) => (
            <div
              key={key}
              style={{
                padding: "12px",
                borderRadius: "9px",
                background: "#FFFFFF",
                border:
                  "1px solid #E2E8F0",
              }}
            >
              <div style={labelStyle}>
                {humanize(key)}
              </div>

              <div
                style={{
                  ...valueStyle,
                  wordBreak: "break-word",
                }}
              >
                {displayValue(value)}
              </div>
            </div>
          )
        )}
      </div>
    </div>
  );
}


/* =========================================================
   Evidence Details
   ========================================================= */

function EvidenceDetails({ entry }) {
  const evidence =
    entry.evidence || {};

  const nlp =
    evidence.nlp_explanation;

  const visual =
    evidence.visual_explanation;

  const features =
    Array.isArray(evidence.explanation)
      ? evidence.explanation
      : [];

  const model =
    evidence.model_info || {};

  const supporting =
    evidence.supporting_data || {};

  return (
    <div
      style={{
        marginTop: "18px",
        paddingTop: "18px",
        borderTop:
          "1px solid #E2E8F0",
      }}
    >
      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "repeat(auto-fit, minmax(220px, 1fr))",
          gap: "16px",
        }}
      >
        <DetailItem
          label="Evidence Type"
          value={entry.evidence_type}
        />

        <DetailItem
          label="Module"
          value={entry.module}
        />

        <DetailItem
          label="Model"
          value={model.model_type}
        />

        <DetailItem
          label="Model File"
          value={model.model_file}
          mono
        />

        <DetailItem
          label="Input Reference"
          value={
            evidence.input_reference
          }
          mono
        />

        <DetailItem
          label="Prediction"
          value={entry.prediction}
        />

        <DetailItem
          label="Confidence"
          value={formatPercent(
            entry.confidence
          )}
        />

        <DetailItem
          label="Risk Score"
          value={formatRisk(
            entry.risk_score
          )}
        />
      </div>

      <ModelTelemetry
        evidence={evidence}
        model={model}
      />

      <NLPExplanation nlp={nlp} />

      <VisualExplanation
        visual={visual}
      />

      <FeatureEvidence
        features={features}
      />

      <ExtractedFeatureVector
        supporting={supporting}
      />

      {Object.keys(supporting).length >
        0 && (
        <details
          style={{
            marginTop: "18px",
          }}
        >
          <summary
            style={{
              cursor: "pointer",
              color: "#334155",
              fontWeight: 700,
              fontSize: "14px",
            }}
          >
            Raw Supporting Data
          </summary>

          <pre
            style={{
              marginTop: "12px",
              padding: "16px",
              borderRadius: "10px",
              background: "#0F172A",
              color: "#E2E8F0",
              overflowX: "auto",
              maxHeight: "420px",
              fontSize: "12px",
              lineHeight: 1.6,
              whiteSpace: "pre-wrap",
              overflowWrap: "anywhere",
            }}
          >
            {JSON.stringify(
              supporting,
              null,
              2
            )}
          </pre>
        </details>
      )}
    </div>
  );
}


/* =========================================================
   Evidence Card
   ========================================================= */

function EvidenceCard({ entry }) {
  const [expanded, setExpanded] =
    useState(false);

  const tone = getRiskTone(
    entry.risk_score
  );

  return (
    <div
      style={{
        background: "#FFFFFF",
        border:
          "1px solid #E2E8F0",
        borderRadius: "14px",
        padding: "20px",
        boxShadow:
          "0 1px 3px rgba(15, 23, 42, 0.06)",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent:
            "space-between",
          gap: "18px",
          flexWrap: "wrap",
        }}
      >
        <div
          style={{
            display: "flex",
            gap: "12px",
            minWidth: 0,
          }}
        >
          <div
            style={{
              width: "40px",
              height: "40px",
              borderRadius: "10px",
              background: "#EEF2FF",
              color: "#4338CA",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexShrink: 0,
            }}
          >
            {getModuleIcon(
              entry.module
            )}
          </div>

          <div style={{ minWidth: 0 }}>
            <h3
              style={{
                margin: 0,
                color: "#0F172A",
                fontSize: "17px",
              }}
            >
              {entry.module ||
                "Evidence Record"}
            </h3>

            <div
              style={{
                marginTop: "5px",
                color: "#64748B",
                fontSize: "13px",
                overflowWrap: "anywhere",
                wordBreak: "break-word",
              }}
            >
              {entry.communication_id}
            </div>
          </div>
        </div>

        <span
          style={{
            alignSelf:
              "flex-start",
            padding: "6px 10px",
            borderRadius: "999px",
            background:
              tone.background,
            color: tone.color,
            border: `1px solid ${tone.border}`,
            fontSize: "13px",
            fontWeight: 700,
          }}
        >
          Risk{" "}
          {formatRisk(
            entry.risk_score
          )}
        </span>
      </div>

      <div
  style={{
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(min(100%, 220px), 1fr))",
    columnGap: "28px",
    rowGap: "18px",
    marginTop: "20px",
    alignItems: "start",
  }}
>
        <DetailItem
          label="Prediction"
          value={entry.prediction}
        />

        <DetailItem
          label="Confidence"
          value={formatPercent(
            entry.confidence
          )}
        />

        <DetailItem
          label="Evidence Type"
          value={entry.evidence_type}
        />

        <DetailItem
          label="Evidence ID"
          value={entry.evidence_id}
          mono
        />

        <DetailItem
          label="Ledger ID"
          value={entry.ledger_id}
          mono
        />

        <DetailItem
          label="Recorded"
          value={formatDate(
            entry.recorded_at
          )}
        />
      </div>

      <button
        type="button"
        onClick={() =>
          setExpanded(
            (value) => !value
          )
        }
        style={{
          marginTop: "18px",
          border: "none",
          background:
            "transparent",
          color: "#4F46E5",
          fontWeight: 700,
          cursor: "pointer",
          padding: 0,
          display: "flex",
          alignItems: "center",
          gap: "6px",
        }}
      >
        {expanded ? (
          <>
            Hide evidence
            <ChevronUp size={17} />
          </>
        ) : (
          <>
            Inspect evidence
            <ChevronDown
              size={17}
            />
          </>
        )}
      </button>

      {expanded && (
        <EvidenceDetails
          entry={entry}
        />
      )}
    </div>
  );
}


/* =========================================================
   Main Page
   ========================================================= */

export default function EvidenceLedger() {
  const [entries, setEntries] =
    useState([]);

  const [total, setTotal] =
    useState(0);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  const [search, setSearch] =
    useState("");

  const [
    moduleFilter,
    setModuleFilter,
  ] = useState("All");

  useEffect(() => {
    let active = true;

    async function loadLedger() {
      try {
        setLoading(true);
        setError("");

        const data =
          await getEvidenceLedger({
            skip: 0,
            limit: 100,
          });

        if (!active) {
          return;
        }

        const records =
          Array.isArray(
            data?.entries
          )
            ? data.entries
            : [];

        setEntries(records);

        setTotal(
          Number(
            data?.total ??
              records.length
          )
        );
      } catch (err) {
        if (!active) {
          return;
        }

        console.error(
          "Failed to load evidence ledger:",
          err
        );

        setError(
          err?.response?.data
            ?.detail ||
            "Unable to load the Explainable Evidence Ledger."
        );
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    }

    loadLedger();

    return () => {
      active = false;
    };
  }, []);

  const modules = useMemo(
    () => [
      "All",
      ...Array.from(
        new Set(
          entries
            .map(
              (entry) =>
                entry.module
            )
            .filter(Boolean)
        )
      ),
    ],
    [entries]
  );

  const filteredEntries =
    useMemo(() => {
      const query = search
        .trim()
        .toLowerCase();

      return entries.filter(
        (entry) => {
          const moduleMatches =
            moduleFilter ===
              "All" ||
            entry.module ===
              moduleFilter;

          if (!moduleMatches) {
            return false;
          }

          if (!query) {
            return true;
          }

          const searchable = [
            entry.communication_id,
            entry.ledger_id,
            entry.evidence_id,
            entry.module,
            entry.evidence_type,
            entry.prediction,
          ]
            .filter(Boolean)
            .join(" ")
            .toLowerCase();

          return searchable.includes(
            query
          );
        }
      );
    }, [
      entries,
      moduleFilter,
      search,
    ]);

  const highRiskCount =
    useMemo(
      () =>
        entries.filter(
          (entry) =>
            Number(
              entry.risk_score ??
                0
            ) >= 70
        ).length,
      [entries]
    );

  const communicationCount =
    useMemo(() => {
      return new Set(
        entries
          .map(
            (entry) =>
              entry.communication_id
          )
          .filter(Boolean)
      ).size;
    }, [entries]);

  const moduleCount =
    Math.max(
      modules.length - 1,
      0
    );

  return (
    <div
      style={{
        maxWidth: "1400px",
        margin: "0 auto",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent:
            "space-between",
          gap: "20px",
          alignItems:
            "center",
          flexWrap: "wrap",
        }}
      >
        <div
  style={{
    minWidth: 0,
    flex: "1 1 600px",
  }}
>
  <h1
    style={{
      margin: 0,
      color: "#0F172A",
      fontSize: "clamp(32px, 4vw, 56px)",
      lineHeight: 1.08,
      fontWeight: 800,
      letterSpacing: "-0.03em",
    }}
  >
    Explainable Evidence Ledger
  </h1>

  <p
    style={{
      margin: "12px 0 0",
      color: "#64748B",
      maxWidth: "900px",
      fontSize: "16px",
      lineHeight: 1.55,
    }}
  >
    Durable, independently inspectable evidence generated by the
    SecureSense AI intelligence pipeline.
  </p>
</div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            background: "#ECFDF5",
            color: "#047857",
            border:
              "1px solid #A7F3D0",
            borderRadius: "999px",
            padding: "8px 12px",
            fontWeight: 700,
            fontSize: "13px",
          }}
        >
          <Database size={16} />
          Durable Ledger
        </div>
      </div>

      {/* Summary */}

      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "repeat(auto-fit, minmax(190px, 1fr))",
          gap: "16px",
          marginTop: "24px",
        }}
      >
        <div style={statCardStyle}>
          <div style={labelStyle}>
            Total Evidence
          </div>

          <div style={statValueStyle}>
            {total}
          </div>
        </div>

        <div style={statCardStyle}>
          <div style={labelStyle}>
            Communications
          </div>

          <div style={statValueStyle}>
            {communicationCount}
          </div>
        </div>

        <div style={statCardStyle}>
          <div style={labelStyle}>
            Intelligence Modules
          </div>

          <div style={statValueStyle}>
            {moduleCount}
          </div>
        </div>

        <div style={statCardStyle}>
          <div style={labelStyle}>
            High-Risk Evidence
          </div>

          <div style={statValueStyle}>
            {highRiskCount}
          </div>
        </div>
      </div>

      {/* Search / filter */}

      <div
        style={{
          display: "flex",
          gap: "12px",
          flexWrap: "wrap",
          marginTop: "24px",
          marginBottom: "20px",
        }}
      >
        <div
          style={{
            position: "relative",
            flex: "1 1 320px",
          }}
        >
          <Search
            size={18}
            style={{
              position:
                "absolute",
              left: "12px",
              top: "50%",
              transform:
                "translateY(-50%)",
              color: "#94A3B8",
            }}
          />

          <input
            value={search}
            onChange={(event) =>
              setSearch(
                event.target.value
              )
            }
            placeholder="Search communication, ledger, evidence, module..."
            style={{
              width: "100%",
              boxSizing:
                "border-box",
              padding:
                "11px 12px 11px 40px",
              borderRadius: "10px",
              border:
                "1px solid #CBD5E1",
              outline: "none",
              fontSize: "14px",
            }}
          />
        </div>

        <select
          value={moduleFilter}
          onChange={(event) =>
            setModuleFilter(
              event.target.value
            )
          }
          style={{
            padding:
              "10px 14px",
            borderRadius: "10px",
            border:
              "1px solid #CBD5E1",
            background: "#FFFFFF",
            color: "#334155",
            minWidth: "210px",
          }}
        >
          {modules.map(
            (module) => (
              <option
                key={module}
                value={module}
              >
                {module === "All"
                  ? "All Modules"
                  : module}
              </option>
            )
          )}
        </select>
      </div>

      {/* States */}

      {loading && (
        <div
          style={
            messageCardStyle
          }
        >
          <Database size={22} />
          Loading durable
          evidence ledger...
        </div>
      )}

      {!loading && error && (
        <div
          style={{
            ...messageCardStyle,
            color: "#B91C1C",
            background:
              "#FEF2F2",
            borderColor:
              "#FECACA",
          }}
        >
          <AlertTriangle
            size={22}
          />
          {error}
        </div>
      )}

      {!loading &&
        !error &&
        filteredEntries.length ===
          0 && (
          <div
            style={
              messageCardStyle
            }
          >
            <FileSearch
              size={22}
            />
            No evidence records
            match the current
            filters.
          </div>
        )}

      {!loading &&
        !error &&
        filteredEntries.length >
          0 && (
          <div
            style={{
              display: "grid",
              gap: "16px",
            }}
          >
            {filteredEntries.map(
              (entry) => (
                <EvidenceCard
                  key={
                    entry.ledger_id
                  }
                  entry={entry}
                />
              )
            )}
          </div>
        )}
    </div>
  );
}


/* =========================================================
   Styles
   ========================================================= */

const labelStyle = {
  color: "#64748B",
  fontSize: "12px",
  fontWeight: 700,
  textTransform: "uppercase",
  letterSpacing: "0.04em",
};

const valueStyle = {
  marginTop: "5px",
  color: "#0F172A",
  fontSize: "14px",
  fontWeight: 600,
};

const statCardStyle = {
  background: "#FFFFFF",
  border: "1px solid #E2E8F0",
  borderRadius: "12px",
  padding: "18px",
};

const statValueStyle = {
  marginTop: "7px",
  fontSize: "27px",
  fontWeight: 800,
  color: "#0F172A",
};

const messageCardStyle = {
  display: "flex",
  alignItems: "center",
  gap: "10px",
  padding: "22px",
  border: "1px solid #E2E8F0",
  borderRadius: "12px",
  background: "#FFFFFF",
  color: "#475569",
};

const detailBoxStyle = {
  marginTop: "18px",
  padding: "16px",
  borderRadius: "10px",
  background: "#F8FAFC",
  border: "1px solid #E2E8F0",
};

const detailHeadingStyle = {
  margin: "0 0 14px",
  display: "flex",
  alignItems: "center",
  gap: "8px",
  color: "#1E293B",
};

const detailGridStyle = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit, minmax(200px, 1fr))",
  gap: "16px",
};

const tableStyle = {
  width: "100%",
  borderCollapse: "collapse",
  fontSize: "13px",
};

const thStyle = {
  textAlign: "left",
  padding: "10px",
  borderBottom:
    "1px solid #CBD5E1",
  color: "#475569",
  whiteSpace: "nowrap",
};

const tdStyle = {
  padding: "10px",
  borderBottom:
    "1px solid #E2E8F0",
  color: "#334155",
  verticalAlign: "middle",
};

const directionBadgeStyle = {
  display: "inline-block",
  padding: "4px 7px",
  borderRadius: "999px",
  fontSize: "11px",
  fontWeight: 700,
  whiteSpace: "nowrap",
};