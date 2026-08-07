import { Navigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";

import { useAuth } from "../context/AuthContext";

export default function ProtectedRoute({ children }) {

    const {
        loading,
        isAuthenticated,
    } = useAuth();

    if (loading) {
        return (
            <div
                style={{
                    display: "flex",
                    justifyContent: "center",
                    alignItems: "center",
                    height: "100vh",
                    fontSize: "18px",
                }}
            >
                <div className="app-loading">
                    <ShieldCheck size={42} />
                    <h2>SecureSense AI</h2>
                    <p>Loading Investigation Workspace...</p>
                </div>
            </div>
        );
    }

    if (!isAuthenticated) {
        return (
            <Navigate
                to="/login"
                replace
            />
        );
    }

    return children;
}