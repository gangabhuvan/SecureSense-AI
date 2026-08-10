import axios from "axios";


const api = axios.create({
    baseURL: "http://127.0.0.1:8000",
    headers: {
        "Content-Type": "application/json",
    },
});


// ==========================================================
// JWT Authentication - Request Interceptor
// ==========================================================

api.interceptors.request.use(
    (config) => {

        const token =
            localStorage.getItem(
                "access_token"
            );

        if (token) {

            config.headers.Authorization =
                `Bearer ${token}`;

        }

        return config;
    },

    (error) =>
        Promise.reject(error)
);


// ==========================================================
// JWT Authentication - Response Interceptor
// ==========================================================

api.interceptors.response.use(

    (response) =>
        response,

    async (error) => {

        const originalRequest =
            error.config;

        // --------------------------------------------------
        // No response / network error
        // --------------------------------------------------

        if (!error.response) {

            return Promise.reject(error);

        }

        // --------------------------------------------------
        // Only attempt token refresh for 401 responses.
        //
        // Do not attempt refresh for:
        // - login
        // - register
        // - refresh itself
        //
        // Otherwise an invalid login could accidentally
        // trigger the refresh flow.
        // --------------------------------------------------

        const isAuthenticationEndpoint =
            originalRequest?.url?.includes(
                "/auth/login"
            ) ||
            originalRequest?.url?.includes(
                "/auth/register"
            ) ||
            originalRequest?.url?.includes(
                "/auth/refresh"
            );

        if (
            error.response.status === 401 &&
            !originalRequest?._retry &&
            !isAuthenticationEndpoint
        ) {

            originalRequest._retry = true;

            const refreshToken =
                localStorage.getItem(
                    "refresh_token"
                );

            // ------------------------------------------------
            // No refresh token
            // ------------------------------------------------

            if (!refreshToken) {

                localStorage.removeItem(
                    "access_token"
                );

                localStorage.removeItem(
                    "refresh_token"
                );

                window.location.href =
                    "/login";

                return Promise.reject(error);
            }

            try {

                // --------------------------------------------
                // Request a new access token.
                //
                // Use axios directly rather than "api" so
                // this request does not pass through the
                // authentication interceptor again.
                // --------------------------------------------

                const refreshResponse =
                    await axios.post(
                        `${api.defaults.baseURL}/auth/refresh`,
                        {
                            refresh_token:
                                refreshToken,
                        },
                        {
                            headers: {
                                "Content-Type":
                                    "application/json",
                            },
                        }
                    );

                const newAccessToken =
                    refreshResponse.data
                        .access_token;

                const newRefreshToken =
                    refreshResponse.data
                        .refresh_token;

                // --------------------------------------------
                // Store the new tokens
                // --------------------------------------------

                localStorage.setItem(
                    "access_token",
                    newAccessToken
                );

                localStorage.setItem(
                    "refresh_token",
                    newRefreshToken
                );

                // --------------------------------------------
                // Update the original failed request
                // --------------------------------------------

                originalRequest.headers =
                    originalRequest.headers || {};

                originalRequest.headers.Authorization =
                    `Bearer ${newAccessToken}`;

                // --------------------------------------------
                // Retry the original request
                // --------------------------------------------

                return api(
                    originalRequest
                );

            } catch (refreshError) {

                // --------------------------------------------
                // Refresh token is invalid/expired.
                //
                // Now, and only now, log the user out.
                // --------------------------------------------

                localStorage.removeItem(
                    "access_token"
                );

                localStorage.removeItem(
                    "refresh_token"
                );

                window.location.href =
                    "/login";

                return Promise.reject(
                    refreshError
                );
            }
        }

        return Promise.reject(error);
    }
);


// ==========================================================
// Authentication
// ==========================================================

export const registerUser = async (
    userData
) => {

    const response = await api.post(
        "/auth/register",
        userData
    );

    return response.data;
};


export const loginUser = async (
    credentials
) => {

    const response = await api.post(
        "/auth/login",
        credentials
    );

    // Store access token
    localStorage.setItem(
        "access_token",
        response.data.access_token
    );

    // Store refresh token
    localStorage.setItem(
        "refresh_token",
        response.data.refresh_token
    );

    return response.data;
};


export const getCurrentUser = async () => {

    const response = await api.get(
        "/auth/me"
    );

    return response.data;
};


export const logoutUser = () => {

    localStorage.removeItem(
        "access_token"
    );

    localStorage.removeItem(
        "refresh_token"
    );
};


// ==========================================================
// Upload
// ==========================================================

export const uploadCommunication = async ({
    file = null,
    text = "",
}) => {

    const formData = new FormData();

    if (file) {

        formData.append(
            "file",
            file
        );

    }

    if (
        text &&
        text.trim()
    ) {

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

    const response = await api.get(
        "/upload/history"
    );

    return response.data;
};


export const getCommunication = async (
    communicationId
) => {

    const response = await api.get(
        `/upload/${encodeURIComponent(
            communicationId
        )}`
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

        params.communication_id =
            communicationId;

    }

    if (module) {

        params.module =
            module;

    }

    const response = await api.get(
        "/ledger",
        {
            params,
        }
    );

    return response.data;
};


export const getCommunicationEvidence =
    async (
        communicationId
    ) => {

        const response =
            await api.get(
                `/ledger/communication/${encodeURIComponent(
                    communicationId
                )}`
            );

        return response.data;
    };


export const getEvidenceByLedgerId =
    async (
        ledgerId
    ) => {

        const response =
            await api.get(
                `/ledger/${encodeURIComponent(
                    ledgerId
                )}`
            );

        return response.data;
    };


// ==========================================================
// Reports
// ==========================================================

export const downloadSecurityReport =
    async (
        communicationId
    ) => {

        const response =
            await api.get(
                `/reports/${encodeURIComponent(
                    communicationId
                )}/pdf`,
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

        const url =
            window.URL.createObjectURL(
                blob
            );

        const link =
            document.createElement("a");

        link.href = url;

        link.download =
            `SecureSense_AI_Security_Report_${communicationId}.pdf`;

        document.body.appendChild(link);

        link.click();

        document.body.removeChild(link);

        window.URL.revokeObjectURL(
            url
        );
    };


// ==========================================================
// Export API Client
// ==========================================================

export default api;