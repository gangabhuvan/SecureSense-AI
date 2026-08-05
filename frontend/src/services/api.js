import axios from "axios";

const api = axios.create({
    baseURL: "http://127.0.0.1:8000",
    headers: {
        "Content-Type": "application/json",
    },
});

export default api;

export const uploadCommunication = async ({
    file = null,
    text = "",
}) => {

    const formData = new FormData();

    if (file) {
        formData.append("file", file);
    }

    if (text && text.trim()) {
        formData.append(
            "text",
            text.trim()
        );
    }

    const response = await api.post(
        "/upload/",
        formData,
        {
            headers: {
                "Content-Type":
                    "multipart/form-data",
            },
        }
    );

    return response.data;
};

export const getUploadHistory = async () => {
    const response = await api.get("/upload/history");
    return response.data;
};

export const getCommunication = async (communicationId) => {
    const response = await api.get(
        `/upload/${encodeURIComponent(communicationId)}`
    );

    return response.data;
};
// ==========================================================
// Explainable Evidence Ledger
// ==========================================================

export const getEvidenceLedger = async ({
    skip = 0,
    limit = 100,
    communicationId = null,
    module = null,
} = {}) => {
    const params = {
        skip,
        limit,
    };

    if (communicationId) {
        params.communication_id = communicationId;
    }

    if (module) {
        params.module = module;
    }

    const response = await api.get("/ledger", {
        params,
    });

    return response.data;
};


export const getCommunicationEvidence = async (
    communicationId
) => {
    const response = await api.get(
        `/ledger/communication/${encodeURIComponent(
            communicationId
        )}`
    );

    return response.data;
};


export const getEvidenceByLedgerId = async (
    ledgerId
) => {
    const response = await api.get(
        `/ledger/${encodeURIComponent(ledgerId)}`
    );

    return response.data;
};
// ==========================================================
// Security Investigation Reports
// ==========================================================

export const downloadSecurityReport = async (communicationId) => {
    const response = await api.get(
        `/reports/${encodeURIComponent(communicationId)}/pdf`,
        {
            responseType: "blob",
        }
    );

    const blob = new Blob(
        [response.data],
        {
            type: "application/pdf",
        }
    );

    const url = window.URL.createObjectURL(blob);

    const link = document.createElement("a");

    link.href = url;
    link.download =
        `SecureSense_AI_Security_Report_${communicationId}.pdf`;

    document.body.appendChild(link);

    link.click();

    document.body.removeChild(link);

    window.URL.revokeObjectURL(url);
};