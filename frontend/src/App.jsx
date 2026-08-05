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


function App() {
  return (
    <BrowserRouter>
      <Routes>

        {/* =================================================
            Main SecureSense Application
            ================================================= */}

        <Route
          path="/"
          element={<MainLayout />}
        >

          {/* Dashboard */}
          <Route
            index
            element={<Dashboard />}
          />


          {/* ===============================================
              Real-Time Communication Analysis
              =============================================== */}

          <Route
            path="upload"
            element={<Upload />}
          />


          {/* Analysis landing page */}
          <Route
            path="analysis"
            element={<Analysis />}
          />

          {/* Individual investigation */}
          <Route
            path="analysis/:communicationId"
            element={<Analysis />}
          />


          {/* ===============================================
              Financial Communication Passport
              =============================================== */}

          <Route
            path="passport"
            element={<Passport />}
          />

          <Route
            path="passport/:communicationId"
            element={<Passport />}
          />


          {/* ===============================================
              Securities Trust Graph
              =============================================== */}

          <Route
            path="trust-graph"
            element={<TrustGraph />}
          />

          <Route
            path="trust-graph/:communicationId"
            element={<TrustGraph />}
          />


          {/* ===============================================
              Explainable Evidence Ledger
              =============================================== */}

          <Route
            path="ledger"
            element={<EvidenceLedger />}
          />

          <Route
            path="ledger/:communicationId"
            element={<EvidenceLedger />}
          />


          {/* ===============================================
              Reports
              =============================================== */}

          <Route
    path="reports"
    element={<Reports />}
/>

<Route
    path="reports/:communicationId"
    element={<Reports />}
/>


          {/* ===============================================
              Platform Settings
              =============================================== */}

          <Route
            path="settings"
            element={<Settings />}
          />


          {/* ===============================================
              Compatibility / Convenience Routes
              =============================================== */}

          <Route
            path="investigate"
            element={
              <Navigate
                to="/upload"
                replace
              />
            }
          />

        </Route>


        {/* =================================================
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