import { useCallback, useEffect, useMemo, useState } from "react";
import { useDropzone } from "react-dropzone";
import { useNavigate } from "react-router-dom";
import {
    AlertTriangle,
    CheckCircle2,
    File,
    FileImage,
    FileText,
    LoaderCircle,
    ShieldCheck,
    UploadCloud,
    X,
} from "lucide-react";

import {
    uploadCommunication,
    getUploadHistory,
} from "../services/api";

const MAX_FILE_SIZE = 15 * 1024 * 1024;

const supportedExtensions = [
    ".pdf",
    ".docx",
    ".txt",
    ".jpg",
    ".jpeg",
    ".png",
    ".wav",
    ".mp3",
    ".m4a",
    ".flac",
    ".ogg",
];

const formatBytes = (bytes = 0) => {
    if (!bytes) return "0 KB";

    const units = ["B", "KB", "MB", "GB"];
    const index = Math.min(
        Math.floor(Math.log(bytes) / Math.log(1024)),
        units.length - 1
    );

    return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 2)} ${
        units[index]
    }`;
};

const getFileExtension = (filename = "") => {
    const index = filename.lastIndexOf(".");
    return index >= 0 ? filename.slice(index).toLowerCase() : "";
};

const getFileIcon = (filename = "") => {
    const extension = getFileExtension(filename);

    if ([".jpg", ".jpeg", ".png"].includes(extension)) {
        return FileImage;
    }

    if ([".pdf", ".docx", ".txt"].includes(extension)) {
        return FileText;
    }

    return File;
};

export default function Upload() {
    const navigate = useNavigate();
    const [investigationMode, setInvestigationMode] =
        useState("file");

    const [textInput, setTextInput] =
        useState("");

    const [selectedFile, setSelectedFile] = useState(null);
    const [uploading, setUploading] = useState(false);
    const [history, setHistory] = useState([]);
    const [error, setError] = useState("");
    const [completedResult, setCompletedResult] = useState(null);

    const [processingStep, setProcessingStep] = useState(0);

    const processingSteps = useMemo(
    () => [
        "Communication Ingestion",

        "Multi-Modal Intelligence",

        "Trust Verification Engine",

        "Trust Intelligence Engine",

        "Generating Financial Communication Passport (FCP)",

        "Building Securities Trust Graph (STG)",

        "Recording Explainable Evidence Ledger (EEL)",
    ],
    []
);

    const loadHistory = async () => {
        try {
            const data = await getUploadHistory();
            setHistory(Array.isArray(data) ? data.slice(0, 5) : []);
        } catch (historyError) {
            console.error("Failed to load upload history:", historyError);
        }
    };

    useEffect(() => {
        loadHistory();
    }, []);

    useEffect(() => {
        if (!uploading) {
            setProcessingStep(0);
            return undefined;
        }

        const interval = window.setInterval(() => {
            setProcessingStep((current) => {
                if (current >= processingSteps.length - 1) {
                    return current;
                }

                return current + 1;
            });
        }, 3500);

        return () => window.clearInterval(interval);
    }, [uploading, processingSteps.length]);

    const validateFile = (file) => {
        const extension = getFileExtension(file.name);

        if (!supportedExtensions.includes(extension)) {
            return "Unsupported file type. Use PDF, DOCX, TXT, JPG, JPEG or PNG.";
        }

        if (file.size > MAX_FILE_SIZE) {
            return "File is too large. Maximum supported size is 15 MB.";
        }

        return "";
    };

    const onDrop = useCallback((acceptedFiles, rejectedFiles) => {
        setError("");
        setCompletedResult(null);

        if (rejectedFiles.length > 0) {
            setSelectedFile(null);
            setError(
                "This file could not be accepted. Please choose a supported communication file."
            );
            return;
        }

        if (acceptedFiles.length === 0) {
            return;
        }

        const file = acceptedFiles[0];
        const validationError = validateFile(file);

        if (validationError) {
            setSelectedFile(null);
            setError(validationError);
            return;
        }

        setSelectedFile(file);
    }, []);

    const {
        getRootProps,
        getInputProps,
        isDragActive,
        open,
    } = useDropzone({
        onDrop,
        multiple: false,
        noClick: true,
        noKeyboard: true,
        maxSize: MAX_FILE_SIZE,
    });

    const clearSelectedFile = () => {
        if (uploading) return;
        setSelectedFile(null);

        setCompletedResult(null);

        setError("");
    };

    const clearText = () => {
        if (uploading) return;

        setTextInput("");

        setCompletedResult(null);

        setError("");
    };

    

    const handleUpload = async () => {

    if (uploading) return;

    if (
        investigationMode === "file" &&
        !selectedFile
    ) {
        return;
    }

    if (
        investigationMode === "text" &&
        !textInput.trim()
    ) {
        return;
    }

    try {

        setUploading(true);

        setError("");

        setCompletedResult(null);

        setProcessingStep(0);

        const result =
            await uploadCommunication({

                file:
                    investigationMode === "file"
                        ? selectedFile
                        : null,

                text:
                    investigationMode === "text"
                        ? textInput
                        : "",

            });

        const communicationId =
            result?.upload?.communication_id ||
            result?.communication_id;

        if (!communicationId) {

            throw new Error(
                "SecureSense completed the request but no communication ID was returned."
            );

        }

        setCompletedResult(result);

        if (investigationMode === "text") {
            setTextInput("");
        }

        await loadHistory();

        navigate(
            `/analysis/${communicationId}`,
            {
                state: {
                    analysisResult: result,
                },
            }
        );

    }

    catch (uploadError) {

        console.error(
            "SecureSense analysis failed:",
            uploadError
        );

        const detail =
            uploadError?.response?.data?.detail;

        setError(

            typeof detail === "string"

                ? detail

                : "SecureSense could not complete the analysis. Please verify the backend is running and try again."

        );

    }

    finally {

        setUploading(false);

    }

};

    const SelectedFileIcon = selectedFile
        ? getFileIcon(selectedFile.name)
        : File;

    return (
        <div className="secure-upload-page">
            <section className="upload-hero">
                <div className="upload-hero-copy">
                    <div className="eyebrow">
                        <ShieldCheck size={16} />
                        SECURESENSE INTELLIGENCE
                    </div>

                    <h1>Analyze a Communication</h1>

                    <p>
                        Upload a suspicious financial communication for
                        multimodal security analysis, explainable evidence,
                        trust intelligence and communication-level risk
                        assessment.
                    </p>
                </div>

                <div className="engine-status">
                    <span className="status-dot" />

                    <div>
                        <strong>Multi-Modal Intelligence</strong>
                        <span>Ready</span>
                    </div>
                </div>
            </section>

            <section className="intelligence-strip">

    <div>
        <span>NLP</span>
        <strong>DistilBERT + Integrated Gradients</strong>
    </div>

    <div>
        <span>VISION</span>
        <strong>ConvNeXt + Grad-CAM++</strong>
    </div>

    <div>
        <span>VOICE</span>
        <strong>Whisper Base + Spectra-AASIST3</strong>
    </div>

    <div>
        <span>URL</span>
        <strong>XGBoost + TreeSHAP</strong>
    </div>

    <div>
        <span>REASONING</span>
        <strong>CII + OCR + STG + EEL + FCP</strong>
    </div>

</section>

            <section className="analysis-workspace">
                <div className="workspace-header">
                    <div>
                        <h2>New Security Investigation</h2>
                        <p>
                            Select one communication to begin real-time
                            analysis.
                        </p>
                    </div>

                    <div className="investigation-mode-selector">

    <button
        type="button"
        className={
            investigationMode === "file"
                ? "mode-button active"
                : "mode-button"
        }
        onClick={() => {
            setInvestigationMode("file");
            clearText();
        }}
    >
        Upload File
    </button>

    <button
        type="button"
        className={
            investigationMode === "text"
                ? "mode-button active"
                : "mode-button"
        }
        onClick={() => {
            setInvestigationMode("text");
            clearSelectedFile();
        }}
    >
        Analyze Text
    </button>

</div>

                    <div className="privacy-badge">
                        <ShieldCheck size={17} />
                        Auditable analysis
                    </div>
                </div>

                {investigationMode === "file" ? (
                    <div
                        {...getRootProps()}
                        className={`secure-dropzone ${
                            isDragActive ? "drag-active" : ""
                        } ${selectedFile ? "has-file" : ""}`}
                    >
                        <input {...getInputProps()} />

                        {!selectedFile ? (
                            <>
                                <div className="drop-icon">
                                    <UploadCloud size={32} />
                                </div>

                                <h3>
                                    {isDragActive
                                        ? "Drop communication to analyze"
                                        : "Drop a suspicious communication here"}
                                </h3>

                                <p>
                                    PDF, DOCX, TXT, JPG, JPEG, PNG, WAV, MP3, M4A, FLAC or OGG · Maximum 15 MB
                                </p>

                                <button
                                    type="button"
                                    className="secondary-button"
                                    onClick={(event) => {
                                        event.stopPropagation();
                                        open();
                                    }}
                                >
                                    Browse files
                                </button>
                            </>
                        ) : (
                            <div className="selected-file-card">
                                <div className="selected-file-icon">
                                    <SelectedFileIcon size={28} />
                                </div>

                                <div className="selected-file-info">
                                    <span>READY FOR ANALYSIS</span>
                                    <strong>{selectedFile.name}</strong>

                                    <p>
                                        {formatBytes(selectedFile.size)}
                                        {" · "}
                                        {getFileExtension(selectedFile.name)
                                            .replace(".", "")
                                            .toUpperCase()}
                                    </p>
                                </div>

                                <button
                                    type="button"
                                    className="remove-file-button"
                                    onClick={(event) => {
                                        event.stopPropagation();
                                        clearSelectedFile();
                                    }}
                                    disabled={uploading}
                                >
                                    <X size={20} />
                                </button>
                            </div>
                        )}
                    </div>
                ) : (
                    <div className="secure-text-input">
                        <textarea
                            className="communication-textarea"
                            spellCheck={false}

                            autoComplete="off"
                            placeholder="Paste an email, SMS, WhatsApp message, social media post or any communication here..."
                            value={textInput}
                            onChange={(e) => setTextInput(e.target.value)}
                            rows={12}
                        />
                    </div>
                )}

                {error && (
                    <div className="analysis-error">
                        <AlertTriangle size={19} />
                        <span>{error}</span>
                    </div>
                )}

                {(
                    (
                        investigationMode === "file" &&
                        selectedFile
                    ) ||
                    (
                        investigationMode === "text" &&
                        textInput.trim()
                    )
                ) &&
                !uploading && (
                    <div className="analysis-actions">
                        <div>
                            <strong>Ready to investigate</strong>
                            <span>
                                SecureSense will automatically execute the complete investigation workflow and generate the Financial Communication Passport (FCP), Securities Trust Graph (STG), and Explainable Evidence Ledger (EEL).
                            </span>
                        </div>

                        <button
                            type="button"
                            className="primary-analysis-button"
                            onClick={handleUpload}
                        >
                            <ShieldCheck size={19} />
                            Analyze Communication
                        </button>
                    </div>
                )}

                {uploading && (
                    <div className="processing-panel">
                        <div className="processing-heading">
                            <LoaderCircle
                                className="processing-spinner"
                                size={25}
                            />

                            <div>
                                <h3>SecureSense AI is investigating</h3>
                                <p>
                                    Do not close this page while the
                                    communication is being analyzed.
                                </p>
                            </div>
                        </div>

                        <div className="processing-progress">
                            <div
                                className="processing-progress-fill"
                                style={{
                                    width: `${
                                        ((processingStep + 1) /
                                            processingSteps.length) *
                                        100
                                    }%`,
                                }}
                            />
                        </div>

                        <div className="processing-steps">
                            {processingSteps.map((step, index) => (
                                <div
                                    key={step}
                                    className={`processing-step ${
                                        index < processingStep
                                            ? "completed"
                                            : ""
                                    } ${
                                        index === processingStep
                                            ? "active"
                                            : ""
                                    }`}
                                >
                                    {index < processingStep ? (
                                        <CheckCircle2 size={17} />
                                    ) : index === processingStep ? (
                                        <LoaderCircle
                                            size={17}
                                            className="processing-spinner"
                                        />
                                    ) : (
                                        <span className="step-circle" />
                                    )}

                                    {step}
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {completedResult && !uploading && (
                    <div className="completed-banner">
                        <CheckCircle2 size={20} />
                        Analysis completed successfully.
                    </div>
                )}
            </section>

            <section className="recent-investigations">
                <div className="section-heading-row">
                    <div>
                        <h2>Recent Investigations</h2>
                        <p>
                            Previously submitted communications.
                        </p>
                    </div>
                </div>

                {history.length === 0 ? (
                    <div className="empty-history">
                        No previous investigations are available.
                    </div>
                ) : (
                    <div className="history-list">
                        {history.map((item) => {
                            const HistoryIcon = getFileIcon(
                                item.filename
                            );

                            return (
                                <button
                                    type="button"
                                    className="history-row"
                                    key={item.communication_id}
                                    onClick={() =>
                                        navigate(
                                            `/analysis/${item.communication_id}`
                                        )
                                    }
                                >
                                    <div className="history-file-icon">
                                        <HistoryIcon size={20} />
                                    </div>

                                    <div className="history-main">
                                        <strong>{item.filename}</strong>
                                        <span>
                                            {item.communication_id}
                                        </span>
                                    </div>

                                    <div className="history-type">
                                        {(
                                            item.file_type ||
                                            item.filetype ||
                                            "Unknown"
                                        ).toUpperCase()}
                                    </div>

                                    <div
                                        className={`history-status ${
                                            item.status === "Completed"
                                                ? "success"
                                                : "neutral"
                                        }`}
                                    >
                                        {item.status}
                                    </div>
                                </button>
                            );
                        })}
                    </div>
                )}
            </section>
        </div>
    );
}