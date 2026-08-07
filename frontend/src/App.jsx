import {
    BrowserRouter,
    Navigate,
    Route,
    Routes,
} from "react-router-dom";

import MainLayout from "./layouts/MainLayout";

import Dashboard from "./pages/Dashboard";
import Upload from "./pages/Upload";
import Analysis from "./pages/Analysis";
import Passport from "./pages/Passport";
import TrustGraph from "./pages/TrustGraph";
import EvidenceLedger from "./pages/EvidenceLedger";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import NotFound from "./pages/NotFound";

import Landing from "./pages/Landing";
import Login from "./pages/Login";
import Register from "./pages/Register";

import ProtectedRoute from "./components/ProtectedRoute";

function App() {

    return (

        <BrowserRouter>

            <Routes>

                {/* ================================================
                    Public Pages
                ================================================= */}

                <Route
                    path="/"
                    element={<Landing />}
                />

                <Route
                    path="/login"
                    element={<Login />}
                />

                <Route
                    path="/register"
                    element={<Register />}
                />

                {/* ================================================
                    Protected SecureSense Platform
                ================================================= */}

                <Route
                    path="/dashboard"
                    element={
                        <ProtectedRoute>
                            <MainLayout />
                        </ProtectedRoute>
                    }
                >

                    <Route
                        index
                        element={<Dashboard />}
                    />

                </Route>

                <Route
                    path="/upload"
                    element={
                        <ProtectedRoute>
                            <MainLayout />
                        </ProtectedRoute>
                    }
                >
                    <Route
                        index
                        element={<Upload />}
                    />
                </Route>

                <Route
                    path="/analysis"
                    element={
                        <ProtectedRoute>
                            <MainLayout />
                        </ProtectedRoute>
                    }
                >
                    <Route
                        index
                        element={<Analysis />}
                    />

                    <Route
                        path=":communicationId"
                        element={<Analysis />}
                    />
                </Route>

                <Route
                    path="/passport"
                    element={
                        <ProtectedRoute>
                            <MainLayout />
                        </ProtectedRoute>
                    }
                >
                    <Route
                        index
                        element={<Passport />}
                    />

                    <Route
                        path=":communicationId"
                        element={<Passport />}
                    />
                </Route>

                <Route
                    path="/trust-graph"
                    element={
                        <ProtectedRoute>
                            <MainLayout />
                        </ProtectedRoute>
                    }
                >
                    <Route
                        index
                        element={<TrustGraph />}
                    />

                    <Route
                        path=":communicationId"
                        element={<TrustGraph />}
                    />
                </Route>

                <Route
                    path="/ledger"
                    element={
                        <ProtectedRoute>
                            <MainLayout />
                        </ProtectedRoute>
                    }
                >
                    <Route
                        index
                        element={<EvidenceLedger />}
                    />

                    <Route
                        path=":communicationId"
                        element={<EvidenceLedger />}
                    />
                </Route>

                <Route
                    path="/reports"
                    element={
                        <ProtectedRoute>
                            <MainLayout />
                        </ProtectedRoute>
                    }
                >
                    <Route
                        index
                        element={<Reports />}
                    />

                    <Route
                        path=":communicationId"
                        element={<Reports />}
                    />
                </Route>

                <Route
                    path="/settings"
                    element={
                        <ProtectedRoute>
                            <MainLayout />
                        </ProtectedRoute>
                    }
                >
                    <Route
                        index
                        element={<Settings />}
                    />
                </Route>

                <Route
                    path="/investigate"
                    element={
                        <Navigate
                            to="/upload"
                            replace
                        />
                    }
                />

                {/* ================================================
                    Unknown Route
                ================================================= */}

                <Route
                    path="*"
                    element={<NotFound />}
                />

            </Routes>

        </BrowserRouter>

    );

}

export default App;