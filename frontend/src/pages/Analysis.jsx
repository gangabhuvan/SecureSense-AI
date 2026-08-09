import { useEffect, useMemo, useState } from "react";
import {
  Link,
  useLocation,
  useParams,
} from "react-router-dom";

import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BrainCircuit,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock3,
  Eye,
  FileSearch,
  Fingerprint,
  Gauge,
  Globe2,
  LoaderCircle,
  Network,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Tags,
  TextSearch,
  Timer,
  Workflow,
} from "lucide-react";

import { getCommunication } from "../services/api";


/* =========================================================
   Helpers
   ========================================================= */

const number = (value, fallback = null) => {
  const parsed = Number(value);

  return Number.isFinite(parsed)
    ? parsed
    : fallback;
};


const percent = (value) => {
  const parsed = number(value);

  if (parsed === null) {
    return "N/A";
  }

  return `${parsed.toFixed(
    parsed >= 99 ? 4 : 2
  )}%`;
};


const score = (value) => {
  const parsed = number(value);

  if (parsed === null) {
    return "N/A";
  }

  return parsed.toFixed(
    parsed >= 99 ? 4 : 2
  );
};


const formatMilliseconds = (value) => {
  const parsed = number(value);

  if (parsed === null) {
    return "N/A";
  }

  if (parsed >= 1000) {
    return `${(parsed / 1000).toFixed(2)} s`;
  }

  return `${parsed.toFixed(0)} ms`;
};


const formatSeconds = (value) => {
  const parsed = number(value);

  if (parsed === null) {
    return "N/A";
  }

  return `${parsed.toFixed(2)} s`;
};


const normalizeRisk = (risk) =>
  String(
    risk || "Unknown"
  ).toLowerCase();


const statusClass = (value) => {
  const normalized = String(
    value || ""
  ).toLowerCase();

  if (
    normalized.includes("high") ||
    normalized.includes("phishing") ||
    normalized.includes("malicious") ||
    normalized.includes("danger")
  ) {
    return "danger";
  }

  if (
    normalized.includes("medium") ||
    normalized.includes("spam") ||
    normalized.includes("conflict") ||
    normalized.includes("warning")
  ) {
    return "warning";
  }

  if (
    normalized.includes("low") ||
    normalized.includes("legitimate") ||
    normalized.includes("safe") ||
    normalized.includes("verified") ||
    normalized.includes("completed")
  ) {
    return "safe";
  }

  return "neutral";
};


const asArray = (value) =>
  Array.isArray(value)
    ? value
    : [];


const humanizeEntityType = (value) =>
  String(value || "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (character) =>
      character.toUpperCase()
    );


const getEntityGroups = (entities) => {
  if (
    !entities ||
    typeof entities !== "object"
  ) {
    return [];
  }

  return Object.entries(entities)
    .map(([type, values]) => ({
      type,
      label: humanizeEntityType(type),
      values: asArray(values),
    }))
    .filter(
      (group) =>
        group.values.length > 0
    );
};


const directionClass = (direction) => {
  const normalized = String(
    direction || ""
  ).toLowerCase();

  if (
    normalized.includes("phishing") ||
    normalized.includes("malicious")
  ) {
    return "danger";
  }

  if (
    normalized.includes("legitimate") ||
    normalized.includes("safe")
  ) {
    return "safe";
  }

  return "neutral";
};


/* =========================================================
   Metric Card
   ========================================================= */

function MetricCard({
  icon: Icon,
  label,
  value,
  detail,
  tone = "neutral",
}) {
  return (
    <div
      className={`investigation-metric ${tone}`}
    >
      <div className="investigation-metric-icon">
        <Icon size={19} />
      </div>

      <div>
        <span>{label}</span>

        <strong>
          {value ?? "N/A"}
        </strong>

        {detail && (
          <small>{detail}</small>
        )}
      </div>
    </div>
  );
}


/* =========================================================
   Intelligence Module Card
   ========================================================= */

function ModuleCard({
  icon: Icon,
  title,
  subtitle,
  status,
  confidence,
  risk,
  latency,
  unavailableText,
  intent,
}) {
  const available =
    status !== null &&
    status !== undefined &&
    status !== "";

  return (
    <div className="security-module-card">

      <div className="module-card-header">
        <div className="module-icon">
          <Icon size={20} />
        </div>

        <div>
          <h3>{title}</h3>
          <p>{subtitle}</p>
        </div>
      </div>

      {available ? (
        <>
          <div
            className={`module-verdict ${statusClass(
              status
            )}`}
          >
            {status}
          </div>

          <div className="module-stat-grid">

            {intent && (
              <div>
                <span>Security Intent</span>
                <strong>{intent}</strong>
              </div>
            )}

            <div>
              <span>Confidence</span>
              <strong>
                {percent(confidence)}
              </strong>
            </div>

            <div>
              <span>Risk</span>
              <strong>
                {score(risk)}
              </strong>
            </div>

          </div>

          {latency != null && (
            <div className="module-latency">
              <Clock3 size={13} />

              <span>
                Inference{" "}
                {formatMilliseconds(
                  latency
                )}
              </span>
            </div>
          )}
        </>
      ) : (
        <div className="module-unavailable">
          <ShieldQuestion size={18} />

          <span>
            {unavailableText ||
              "This intelligence modality was not available."}
          </span>
        </div>
      )}

    </div>
  );
}


/* =========================================================
   Expandable Technical Evidence
   ========================================================= */

function TechnicalEvidence({
  analysis,
  nlp,
  visual,
  urls,
  modules,
  fusion,
}) {
  const [expanded, setExpanded] =
    useState(false);

  const entityGroups =
    getEntityGroups(
      analysis.entities
    );


  const aiManipulationFindings =
    asArray(
      analysis.passport
        ?.ai_manipulation_findings
    );

  const explainableEvidence =
    asArray(
      analysis.passport
        ?.explainable_evidence
    );

  const nlpProbabilities =
    nlp?.probabilities &&
      typeof nlp.probabilities ===
      "object"
      ? Object.entries(
        nlp.probabilities
      )
      : [];

  const hasOcr =
    analysis.ocr_status ||
    analysis.extracted_text;

  const hasTechnicalEvidence =
    hasOcr ||
    entityGroups.length > 0 ||
    nlpProbabilities.length > 0 ||
    urls.length > 0 ||
    aiManipulationFindings.length >
    0 ||
    explainableEvidence.length > 0 ||
    analysis.processing_time != null;

  if (!hasTechnicalEvidence) {
    return null;
  }

  return (
    <section className="investigation-section technical-evidence-section">

      <button
        type="button"
        className="technical-evidence-toggle"
        onClick={() =>
          setExpanded(
            (current) => !current
          )
        }
        aria-expanded={expanded}
      >
        <div className="technical-toggle-heading">

          <div className="technical-toggle-icon">
            <Workflow size={20} />
          </div>

          <div>
            <span>
              TECHNICAL EVIDENCE
            </span>

            <h2>
              Investigation Details
            </h2>

            <p>
              Inspect OCR, extracted
              entities, model probabilities,
              explainability and processing
              telemetry.
            </p>
          </div>

        </div>

        {expanded ? (
          <ChevronUp size={20} />
        ) : (
          <ChevronDown size={20} />
        )}
      </button>


      {expanded && (
        <div className="technical-evidence-content">


          {/* ===============================================
              Pipeline Summary
              =============================================== */}

          <div className="technical-block">

            <div className="technical-block-heading">
              <Timer size={18} />

              <div>
                <span>
                  PIPELINE TELEMETRY
                </span>

                <h3>
                  Processing Summary
                </h3>
              </div>
            </div>


            <div className="technical-stat-grid">

              <div>
                <span>
                  Total Processing
                </span>

                <strong>
                  {formatSeconds(
                    analysis.processing_time
                  )}
                </strong>
              </div>


              <div>
                <span>
                  Modules Executed
                </span>

                <strong>
                  {modules.length}
                </strong>
              </div>


              <div>
                <span>
                  NLP Inference
                </span>

                <strong>
                  {formatMilliseconds(
                    nlp?.inference_time_ms
                  )}
                </strong>
              </div>


              <div>
                <span>
                  Visual Inference
                </span>

                <strong>
                  {formatMilliseconds(
                    visual
                      ?.inference_time_ms
                  )}
                </strong>
              </div>
              {
                fusion?.voice_summary && (

                  <div>

                    <span>
                      Voice Authenticity
                    </span>

                    <strong>
                      {
                        fusion.voice_summary
                      }
                    </strong>

                  </div>

                )
              }
            </div>

          </div>


          {/* ===============================================
              OCR
              =============================================== */}

          {hasOcr && (
            <div className="technical-block">

              <div className="technical-block-heading">
                <TextSearch size={18} />

                <div>
                  <span>
                    CONTENT EXTRACTION
                  </span>

                  <h3>
                    OCR & Extracted Text
                  </h3>
                </div>
              </div>


              <div className="ocr-status-row">

                <span>
                  OCR Status
                </span>

                <strong
                  className={`technical-status ${statusClass(
                    analysis.ocr_status
                  )}`}
                >
                  {analysis.ocr_status ||
                    "Unavailable"}
                </strong>

              </div>


              {analysis.extracted_text ? (
                <div className="extracted-text-box">
                  {
                    analysis.extracted_text
                  }
                </div>
              ) : (
                <div className="technical-empty">
                  No extracted text was
                  returned for this
                  communication.
                </div>
              )}

            </div>
          )}


          {/* ===============================================
              Extracted Entities
              =============================================== */}

          {entityGroups.length > 0 && (
            <div className="technical-block">

              <div className="technical-block-heading">
                <Tags size={18} />

                <div>
                  <span>
                    ENTITY EXTRACTION
                  </span>

                  <h3>
                    Detected Security
                    Entities
                  </h3>
                </div>
              </div>


              <div className="entity-group-grid">

                {entityGroups.map(
                  (group) => (
                    <div
                      className="entity-group-card"
                      key={group.type}
                    >
                      <div className="entity-group-title">
                        <span>
                          {group.label}
                        </span>

                        <strong>
                          {
                            group.values
                              .length
                          }
                        </strong>
                      </div>


                      <div className="entity-chip-list">

                        {group.values.map(
                          (
                            entity,
                            index
                          ) => (
                            <span
                              className="entity-chip"
                              key={`${group.type}-${entity}-${index}`}
                            >
                              {String(
                                entity
                              )}
                            </span>
                          )
                        )}

                      </div>

                    </div>
                  )
                )}

              </div>

            </div>
          )}


          {/* ===============================================
              NLP Probabilities
              =============================================== */}

          {nlpProbabilities.length >
            0 && (
              <div className="technical-block">

                <div className="technical-block-heading">
                  <BrainCircuit
                    size={18}
                  />

                  <div>
                    <span>
                      NLP EXPLAINABILITY
                    </span>

                    <h3>
                      Classification
                      Probabilities
                    </h3>
                  </div>
                </div>


                <div className="probability-grid">

                  {nlpProbabilities.map(
                    ([
                      label,
                      probability,
                    ]) => (
                      <div
                        className="probability-card"
                        key={label}
                      >
                        <span>
                          {label}
                        </span>

                        <strong>
                          {percent(
                            probability
                          )}
                        </strong>

                        <div className="probability-track">
                          <div
                            className={`probability-fill ${statusClass(
                              label
                            )}`}
                            style={{
                              width: `${Math.min(
                                100,
                                Math.max(
                                  0,
                                  number(
                                    probability,
                                    0
                                  )
                                )
                              )}%`,
                            }}
                          />
                        </div>

                      </div>
                    )
                  )}

                </div>

              </div>
            )}


          {/* ===============================================
              URL Intelligence / TreeSHAP
              =============================================== */}

          {urls.length > 0 && (
            <div className="technical-block">

              <div className="technical-block-heading">
                <Globe2 size={18} />

                <div>
                  <span>
                    URL EXPLAINABILITY
                  </span>

                  <h3>
                    TreeSHAP Intelligence
                  </h3>
                </div>
              </div>


              <div className="technical-url-list">

                {urls.map(
                  (
                    urlResult,
                    urlIndex
                  ) => {

                    const explanation =
                      asArray(
                        urlResult
                          ?.explanation
                      );

                    const modelInfo =
                      urlResult
                        ?.model_info ||
                      {};

                    return (
                      <div
                        className="technical-url-card"
                        key={
                          urlResult.url ||
                          urlResult
                            .input_url ||
                          urlIndex
                        }
                      >

                        <div className="technical-url-header">

                          <div>
                            <span>
                              URL
                            </span>

                            <strong>
                              {urlResult.url ||
                                urlResult
                                  .input_url ||
                                `URL ${urlIndex +
                                1
                                }`}
                            </strong>
                          </div>


                          <div
                            className={`technical-url-verdict ${statusClass(
                              urlResult.label ||
                              urlResult.prediction
                            )}`}
                          >
                            {urlResult.label ||
                              urlResult
                                .prediction ||
                              "Analyzed"}
                          </div>

                        </div>


                        <div className="technical-url-stats">

                          <div>
                            <span>
                              Confidence
                            </span>

                            <strong>
                              {percent(
                                urlResult
                                  .confidence_percent ??
                                (
                                  urlResult
                                    .confidence !=
                                    null
                                    ? urlResult
                                      .confidence <=
                                      1
                                      ? urlResult
                                        .confidence *
                                      100
                                      : urlResult
                                        .confidence
                                    : null
                                )
                              )}
                            </strong>
                          </div>


                          <div>
                            <span>
                              Risk
                            </span>

                            <strong>
                              {score(
                                urlResult
                                  .risk_score
                              )}
                            </strong>
                          </div>


                          <div>
                            <span>
                              Model
                            </span>

                            <strong>
                              {modelInfo
                                .model_type ||
                                "XGBoost"}
                            </strong>
                          </div>


                          <div>
                            <span>
                              Features
                            </span>

                            <strong>
                              {modelInfo
                                .feature_count ??
                                "N/A"}
                            </strong>
                          </div>


                          <div>
                            <span>
                              Inference
                            </span>

                            <strong>
                              {formatMilliseconds(
                                urlResult
                                  .inference_time_ms
                              )}
                            </strong>
                          </div>
                          {
                            urlResult?.passport?.verification
                              ?.official_domain !== undefined && (

                              <>

                                <div>

                                  <span>
                                    Official Domain
                                  </span>

                                  <strong>
                                    {
                                      urlResult.passport
                                        .verification
                                        .official_domain
                                        ? "Yes"
                                        : "No"
                                    }
                                  </strong>

                                </div>

                                {
                                  urlResult.passport
                                    .verification
                                    .official_provider && (

                                    <div>

                                      <span>
                                        Provider
                                      </span>

                                      <strong>
                                        {
                                          urlResult.passport
                                            .verification
                                            .official_provider
                                        }
                                      </strong>

                                    </div>

                                  )
                                }

                                {
                                  urlResult.passport
                                    .verification
                                    .registered_domain && (

                                    <div>

                                      <span>
                                        Registered Domain
                                      </span>

                                      <strong>
                                        {
                                          urlResult.passport
                                            .verification
                                            .registered_domain
                                        }
                                      </strong>

                                    </div>

                                  )
                                }

                              </>

                            )
                          }
                        </div>


                        {explanation.length >
                          0 ? (
                          <div className="shap-explanation">

                            <div className="shap-heading">
                              <span>
                                TOP FEATURE
                                CONTRIBUTIONS
                              </span>

                              <small>
                                Direction shows
                                how each feature
                                influenced the
                                URL prediction.
                              </small>
                            </div>


                            <div className="shap-feature-list">

                              {explanation.map(
                                (
                                  feature,
                                  featureIndex
                                ) => {

                                  const strength =
                                    Math.abs(
                                      number(
                                        feature
                                          .strength ??
                                        feature
                                          .shap_value,
                                        0
                                      )
                                    );

                                  const maxStrength =
                                    Math.max(
                                      ...explanation.map(
                                        (
                                          item
                                        ) =>
                                          Math.abs(
                                            number(
                                              item
                                                .strength ??
                                              item
                                                .shap_value,
                                              0
                                            )
                                          )
                                      ),
                                      1
                                    );

                                  const width =
                                    Math.min(
                                      100,
                                      (
                                        strength /
                                        maxStrength
                                      ) *
                                      100
                                    );

                                  const direction =
                                    feature.direction ||
                                    (
                                      number(
                                        feature
                                          .shap_value,
                                        0
                                      ) >= 0
                                        ? "phishing"
                                        : "legitimate"
                                    );

                                  return (
                                    <div
                                      className="shap-feature-row"
                                      key={`${feature.feature}-${featureIndex}`}
                                    >
                                      {/* Feature */}
                                      <div className="shap-feature-main">
                                        <span className="shap-field-label">
                                          Feature
                                        </span>

                                        <strong className="shap-feature-title">
                                          {humanizeEntityType(
                                            feature.feature
                                          )}
                                        </strong>

                                        <div className="shap-feature-value">
                                          <span>Value</span>

                                          <strong>
                                            {String(
                                              feature.value ?? "N/A"
                                            )}
                                          </strong>
                                        </div>
                                      </div>

                                      {/* Contribution */}
                                      <div className="shap-contribution">
                                        <span className="shap-field-label">
                                          Contribution
                                        </span>

                                        <div className="shap-contribution-value">
                                          {strength.toFixed(4)}
                                        </div>

                                        <div
                                          className="shap-track"
                                          aria-hidden="true"
                                        >
                                          <div
                                            className={`shap-fill ${directionClass(
                                              direction
                                            )}`}
                                            style={{
                                              width: `${width}%`,
                                            }}
                                          />
                                        </div>
                                      </div>

                                      {/* Direction */}
                                      <div className="shap-direction-column">
                                        <span className="shap-field-label">
                                          Direction
                                        </span>

                                        <div
                                          className={`shap-direction ${directionClass(
                                            direction
                                          )}`}
                                        >
                                          {direction}
                                        </div>
                                      </div>
                                    </div>
                                  );
                                }
                              )}

                            </div>

                          </div>
                        ) : (
                          <div className="technical-empty">
                            No URL feature
                            explanation was
                            returned.
                          </div>
                        )}

                      </div>
                    );
                  }
                )}

              </div>

            </div>
          )}

          {aiManipulationFindings.length >
            0 && (
              <div className="technical-block">

                <div className="technical-block-heading">
                  <ScanSearch size={18} />

                  <div>
                    <span>
                      AI MANIPULATION
                    </span>

                    <h3>
                      Manipulation Findings
                    </h3>
                  </div>
                </div>


                <div className="raw-finding-list">
                  {aiManipulationFindings.map(
                    (
                      finding,
                      index
                    ) => (
                      <pre
                        key={index}
                        className="raw-finding-card"
                      >
                        {typeof finding ===
                          "string"
                          ? finding
                          : JSON.stringify(
                            finding,
                            null,
                            2
                          )}
                      </pre>
                    )
                  )}
                </div>

              </div>
            )}


          {explainableEvidence.length >
            0 && (
              <div className="technical-block">

                <div className="technical-block-heading">
                  <ShieldCheck
                    size={18}
                  />

                  <div>
                    <span>
                      EXPLAINABLE EVIDENCE
                    </span>

                    <h3>
                      Additional Evidence
                    </h3>
                  </div>
                </div>


                <div className="raw-finding-list">
                  {explainableEvidence.map(
                    (
                      evidence,
                      index
                    ) => (
                      <pre
                        key={index}
                        className="raw-finding-card"
                      >
                        {typeof evidence ===
                          "string"
                          ? evidence
                          : JSON.stringify(
                            evidence,
                            null,
                            2
                          )}
                      </pre>
                    )
                  )}
                </div>

              </div>
            )}

        </div>
      )}

    </section>
  );
}


/* =========================================================
   Analysis Page
   ========================================================= */

export default function Analysis() {

  const { communicationId } =
    useParams();

  const location =
    useLocation();

  /*
   * Upload.jsx may pass the complete real-time backend
   * response while navigating here. We can display that
   * immediately, then refresh from the durable persisted
   * communication endpoint.
   */
  const navigationResult =
    location.state?.analysisResult ||
    null;


  const [analysis, setAnalysis] =
    useState(null);

  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState("");


  /* =======================================================
     Load Investigation
     ======================================================= */

  useEffect(() => {

    if (!communicationId) {
      setAnalysis(null);
      setLoading(false);
      setError("");
      return;
    }

    let active = true;


    const immediateAnalysis =
      navigationResult?.analysis &&
        navigationResult?.upload
          ?.communication_id ===
        communicationId
        ? {
          ...navigationResult.analysis,

          communication_id:
            navigationResult.upload
              .communication_id,

          filename:
            navigationResult.upload
              .filename,

          file_type:
            navigationResult.upload
              .file_type,

          status:
            navigationResult.upload
              .status,

          uploaded_at:
            navigationResult.upload
              .uploaded_at,

          processing_time:
            navigationResult
              .processing_time,
        }
        : null;


    if (immediateAnalysis) {
      setAnalysis(
        immediateAnalysis
      );
    }


    const loadCommunication =
      async () => {

        try {

          setLoading(
            !immediateAnalysis
          );

          setError("");

          const data =
            await getCommunication(
              communicationId
            );

          if (
            active &&
            data
          ) {
            setAnalysis(data);
          }

        } catch (err) {

          console.error(
            "Unable to load communication analysis:",
            err
          );

          if (
            active &&
            !immediateAnalysis
          ) {
            setError(
              err?.response?.data
                ?.detail ||
              err?.message ||
              "Unable to load communication analysis."
            );
          }

        } finally {

          if (active) {
            setLoading(false);
          }

        }
      };


    loadCommunication();


    return () => {
      active = false;
    };

  }, [
    communicationId,
    navigationResult,
  ]);


  /* =======================================================
     Normalize Backend Investigation Data
     ======================================================= */

  const derived =
    useMemo(() => {

      if (!analysis) {
        return null;
      }


      const fusion =
        analysis.multimodal_fusion ||
        null;


      const nlp =
        analysis.nlp_result ||
        analysis.nlp ||
        null;


      const visual =
        analysis.visual_result ||
        analysis.visual ||
        null;


      const urls =
        asArray(
          analysis.url_results ||
          analysis.urls
        );
      const qr =
        analysis.qr ||
        null;

      const passport =
        analysis.passport ||
        null;


      const stg =
        analysis.securities_trust_graph ||
        passport
          ?.securities_trust_graph ||
        null;


      const evidence =
  analysis.evidence_references ||
  analysis.evidence ||
  passport?.evidence ||
{};

const modules =
  asArray(
    evidence?.modules
  );


      const decision =
        fusion?.decision ||
        (
          analysis.risk_level ===
            "High"
            ? "High Risk"
            : analysis.risk_level ||
            "Unknown"
        );


      return {
        fusion,
        nlp,
        visual,
        urls,
        qr,
        passport,
        stg,
        evidence,
        modules,
        decision,
      };

    }, [analysis]);


  /* =======================================================
     No Investigation Selected
     ======================================================= */

  if (!communicationId) {

    return (
      <div className="investigation-empty-page">

        <div className="investigation-empty-icon">
          <ScanSearch size={34} />
        </div>

        <h1>
          Security Investigations
        </h1>

        <p>
          Analyze a communication or open a
          previous investigation to inspect its
          complete SecureSense security
          intelligence.
        </p>

        <Link
          to="/upload"
          className="investigation-primary-link"
        >
          Analyze Communication

          <ArrowRight size={17} />
        </Link>

      </div>
    );
  }


  /* =======================================================
     Loading
     ======================================================= */

  if (
    loading &&
    !analysis
  ) {

    return (
      <div className="investigation-loading">

        <LoaderCircle
          size={32}
          className="processing-spinner"
        />

        <h2>
          Loading investigation
        </h2>

        <p>
          {communicationId}
        </p>

      </div>
    );
  }


  /* =======================================================
     Error
     ======================================================= */

  if (
    error &&
    !analysis
  ) {

    return (
      <div className="investigation-error-page">

        <AlertTriangle
          size={32}
        />

        <h2>
          Investigation unavailable
        </h2>

        <p>{error}</p>

        <Link to="/upload">
          Return to communications
        </Link>

      </div>
    );
  }


  if (
    !analysis ||
    !derived
  ) {
    return null;
  }


  /* =======================================================
     Investigation Data
     ======================================================= */

  const {
    fusion,
    nlp,
    visual,
    urls,
    qr,
    passport,
    stg,
    modules,
    decision,
  } = derived;


  const riskTone =
    normalizeRisk(
      analysis.risk_level
    );


  const decisionTone =
    statusClass(
      decision
    );

  const trustedHosting =
    fusion?.trusted_hosting_platform === true;

const recommendation =
    trustedHosting
        ? (
            "The communication is hosted on an official trusted platform that supports user-generated content. " +
            "Verify the sender before submitting personal information, opening shared documents, or completing forms."
        )
        : (
            passport?.recommended_action ||
            (
                riskTone === "high"
                    ? "Do not perform sensitive actions until this communication has been independently verified."
                    : "Review the available security evidence before taking sensitive financial action."
            )
        );


  /* =======================================================
     Render Investigation Console
     ======================================================= */

  return (
    <div className="investigation-page">


      {/* ===================================================
          Investigation Header
          =================================================== */}

      <section className="investigation-header">

        <div>

          <div className="investigation-eyebrow">
            <FileSearch size={15} />

            SECURITY INVESTIGATION
          </div>


          <h1>
            {analysis.filename ||
              "Communication Analysis"}
          </h1>


          <div className="investigation-meta">

            <span>
              {analysis.communication_id ||
                communicationId}
            </span>


            {analysis.file_type && (
              <>
                <span className="meta-separator">
                  •
                </span>

                <span>
                  {String(
                    analysis.file_type
                  ).toUpperCase()}
                </span>
              </>
            )}


            {analysis.document_type && (
              <>
                <span className="meta-separator">•</span>

                <span>
                  {analysis.document_type}
                </span>
              </>
            )}

          </div>

        </div>


<div className="investigation-header-actions">

    <Link
        to="/upload"
        className="investigation-primary-link"
    >
        New Investigation
        <ArrowRight size={16} />
    </Link>

    <div
        className={`investigation-status ${
            analysis.status === "Completed"
                ? "completed"
                : ""
        }`}
    >
        <CheckCircle2 size={16} />
        {analysis.status || "Analyzed"}
    </div>

</div>

      </section>


      {/* ===================================================
          Final Security Verdict
          =================================================== */}

      <section
        className={`final-verdict-card ${riskTone}`}
      >

        <div className="verdict-main">

          <div
            className={`verdict-shield ${decisionTone}`}
          >

            {riskTone === "high" ? (
              <ShieldAlert size={34} />
            ) : (
              <ShieldCheck size={34} />
            )}

          </div>


          <div>

            <span className="verdict-label">
              FINAL SECURITY ASSESSMENT
            </span>


            <h2>
              {String(
                analysis.risk_level ||
                "Unknown"
              ).toUpperCase()}{" "}
              RISK
            </h2>


            <div
              className={`decision-badge ${decisionTone}`}
            >
              {decision}
            </div>

          </div>

        </div>


        <div className="verdict-scores">

          <div>
            <span>Risk Score</span>

            <strong>
              {percent(
                analysis.risk_score
              )}
            </strong>
          </div>


          <div>
            <span>Confidence</span>

            <strong>
              {percent(
                analysis.confidence
              )}
            </strong>
          </div>


          <div>
            <span>Trust Score</span>

            <strong>
              {passport?.trust_score !=
                null
                ? score(
                  passport.trust_score
                )
                : "N/A"}
            </strong>
          </div>

        </div>

      </section>


      {/* ===================================================
          Recommended Action
          =================================================== */}

      <section
        className={`recommended-action ${riskTone}`}
      >

        <AlertTriangle size={21} />

        <div>

          <span>
            RECOMMENDED ACTION
          </span>

          <strong>
            {recommendation}
          </strong>

        </div>

      </section>


      {/* ===================================================
          Investigation Metrics
          =================================================== */}

      <section className="investigation-metrics-grid">

        <MetricCard
          icon={Gauge}
          label="Risk Level"
          value={
            analysis.risk_level ||
            "Unknown"
          }
          detail={`${score(
            analysis.risk_score
          )} / 100`}
          tone={statusClass(
            analysis.risk_level
          )}
        />


        <MetricCard
          icon={Activity}
          label="Model Agreement"
          value={
            fusion?.agreement ||
            "N/A"
          }
          detail={
            fusion?.dominant_modality
              ? `Dominant: ${fusion.dominant_modality}`
              : "No dominant modality"
          }
          tone={statusClass(
            fusion?.agreement
          )}
        />


        <MetricCard
          icon={Network}
          label="Trust Graph"
          value={
            stg?.reputation_available
              ? stg.classification ||
              "Available"
              : "No Reputation"
          }
          detail={`${stg?.entities_analysed ??
            0
            } entities analysed`}
          tone={
            stg?.reputation_available
              ? statusClass(
                stg.classification
              )
              : "neutral"
          }
        />

      </section>


      {/* ===================================================
          Multimodal AI Intelligence
          =================================================== */}

      <section className="investigation-section">

        <div className="investigation-section-heading">

          <div>

            <span>
              AI SECURITY SIGNALS
            </span>

            <h2>
              Multimodal Intelligence
            </h2>

          </div>


          {fusion?.agreement && (
            <div
              className={`agreement-pill ${statusClass(
                fusion.agreement
              )}`}
            >
              {fusion.agreement}
            </div>
          )}

        </div>


        <div className="module-grid">

          <ModuleCard
            icon={BrainCircuit}
            title="NLP Intelligence"
            subtitle="DistilBERT + Integrated Gradients"
            status={nlp?.label}
            confidence={
              nlp?.confidence_percent ??
              (
                nlp?.confidence != null
                  ? nlp.confidence *
                  100
                  : null
              )
            }
            risk={
              nlp?.risk_score
            }
            latency={
              nlp?.inference_time_ms
            }
            unavailableText="No analysable text signal was available."
          />


          <ModuleCard
            icon={Eye}
            title="Visual Intelligence"
            subtitle="ConvNeXt-Tiny + Grad-CAM"
            status={visual?.label}
            confidence={
              visual
                ?.confidence_percent ??
              (
                visual?.confidence !=
                  null
                  ? visual.confidence *
                  100
                  : null
              )
            }
            risk={
              visual?.risk_score
            }
            latency={
              visual
                ?.inference_time_ms
            }
            unavailableText="Visual intelligence was not applicable to this communication."
          />

          <ModuleCard
            icon={Fingerprint}
            title="Voice Intelligence"
            subtitle="Whisper Base + Spectra-AASIST3"

            status={
              fusion?.voice_label ??
              null
            }

            confidence={
              fusion?.voice_confidence ??
              null
            }

            risk={
              fusion?.voice_risk ??
              null
            }

            latency={null}

            unavailableText={
              "Voice authenticity analysis was not applicable to this communication."
            }
          />


          <ModuleCard
            icon={Globe2}
            title="URL Intelligence"
            subtitle="XGBoost + TreeSHAP"
            status={
              urls.length > 0
                ? (
                  urls[0]?.label ||
                  urls[0]
                    ?.prediction ||
                  "Analyzed"
                )
                : null
            }
            confidence={
              urls.length > 0
                ? (
                  urls[0]
                    ?.confidence_percent ??
                  (
                    urls[0]
                      ?.confidence !=
                      null
                      ? (
                        urls[0]
                          .confidence <=
                          1
                          ? urls[0]
                            .confidence *
                          100
                          : urls[0]
                            .confidence
                      )
                      : null
                  )
                )
                : null
            }
            risk={
              urls.length > 0
                ? urls[0]
                  ?.risk_score
                : null
            }
            latency={
              urls.length > 0
                ? urls[0]
                  ?.inference_time_ms
                : null
            }
            unavailableText="No analysed URLs were detected in this communication."
          />

        </div>


        {urls.length > 1 && (

          <div className="url-results">

            <h3>
              Analysed URLs (
              {urls.length})
            </h3>


            {urls.map(
              (
                urlResult,
                index
              ) => (

                <div
                  className="url-result-row"
                  key={
                    urlResult.url ||
                    urlResult.input_url ||
                    index
                  }
                >

                  <Globe2
                    size={16}
                  />


                  <span>
                    {urlResult.url ||
                      urlResult
                        .input_url ||
                      `URL ${index + 1
                      }`}
                  </span>


                  <strong>
                    {urlResult.label ||
                      urlResult
                        .prediction ||
                      "Analyzed"}
                  </strong>


                  <small>
                    Risk{" "}
                    {score(
                      urlResult
                        .risk_score
                    )}
                  </small>

                </div>

              )
            )}

          </div>

        )}
        {
          qr?.available && (

            <div className="url-results">

              <h3>
                QR Intelligence ({qr.count})
              </h3>

              {
                qr.codes.map(
                  (
                    code,
                    index,
                  ) => (

                    <div
                      className="url-result-row"
                      key={index}
                    >

                      <ScanSearch
                        size={16}
                      />

                      <div
                        style={{
                          flex: 1,
                        }}
                      >

                        <div>

                          <small>
                            {code.type}
                          </small>

                          <span>
                            {code.decoded_data}
                          </span>

                        </div>

                        {
                          code.url_analysis && (

                            <small>

                              Risk{" "}
                              {
                                score(
                                  code.url_analysis
                                    .risk_score
                                )
                              }

                              {" • "}

                              Confidence{" "}
                              {
                                percent(
                                  code.url_analysis
                                    .confidence_percent
                                )
                              }

                            </small>

                          )
                        }

                      </div>

                      <div
                        className={`technical-url-verdict ${statusClass(
                          code.url_analysis?.label
                        )}`}
                      >

                        {
                          code.url_analysis?.label ??
                          code.type
                        }

                      </div>

                    </div>
                  )
                )
              }

            </div>

          )
        }

      </section>


      {/* ===================================================
          NEW — Technical Evidence
          =================================================== */}

      <TechnicalEvidence
        analysis={analysis}
        nlp={nlp}
        visual={visual}
        urls={urls}
        modules={modules}
        fusion={fusion}
      />


      {/* ===================================================
    Trust Intelligence Destinations
    =================================================== */}

<section className="trust-destinations-grid">

  {/* =================================================
      Securities Trust Graph
      ================================================= */}

  <div className="investigation-section trust-destination-card">

    <div className="investigation-section-heading">

      <div>

        <span>
          TRUST INTELLIGENCE
        </span>

        <h2>
          Securities Trust Graph (STG)
        </h2>

      </div>

      <Network size={22} />

    </div>

    <p className="context-note">
      Explore entity relationships, reputation signals,
      and historical trust intelligence associated with
      this investigation.
    </p>

    <Link
      className="investigation-secondary-link"
      to={`/trust-graph/${encodeURIComponent(
        analysis.communication_id ||
        communicationId
      )}`}
    >
      Explore Trust Graph

      <ArrowRight size={16} />
    </Link>

  </div>


  {/* =================================================
      Financial Communication Passport
      ================================================= */}

  <div className="investigation-section trust-destination-card">

    <div className="investigation-section-heading">

      <div>

        <span>
          TRUST PROFILE
        </span>

        <h2>
          Financial Communication Passport (FCP)
        </h2>

      </div>

      <Fingerprint size={22} />

    </div>

    <p className="context-note">
      View the complete trust and authenticity profile
      generated for this communication.
    </p>

    <Link
      className="investigation-secondary-link"
      to={`/passport/${encodeURIComponent(
        analysis.communication_id ||
        communicationId
      )}`}
    >
      Open Full Passport

      <ArrowRight size={16} />
    </Link>

  </div>


  {/* =================================================
      Explainable Evidence Ledger
      ================================================= */}

  <div className="investigation-section trust-destination-card">

    <div className="investigation-section-heading">

      <div>

        <span>
          AUDITABILITY
        </span>

        <h2>
          Explainable Evidence Ledger (EEL)
        </h2>

      </div>

      <ShieldCheck size={22} />

    </div>

    <p className="context-note">
      Inspect the evidence references and investigation
      trail supporting this security assessment.
    </p>

    <Link
      className="investigation-secondary-link"
      to={`/ledger/${encodeURIComponent(
        analysis.communication_id ||
        communicationId
      )}`}
    >
      Inspect Evidence Ledger

      <ArrowRight size={16} />
    </Link>

  </div>

</section>

    </div>
  );
}