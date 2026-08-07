import React from "react";
import { Link } from "react-router-dom";
import {
    ShieldCheck,
    ArrowRight,
    Upload,
    ScanSearch,
    Database,
    Network,
    FileBadge2,
    Menu,
    Bot,
    Shield,
    Eye,
    BrainCircuit,
    LayoutDashboard
} from "lucide-react";

export default function Landing() {
    return (
        <div className="landing-page">
            {/* =====================================================
                NAVIGATION
            ====================================================== */}
            <header className="landing-navbar">
                <div className="landing-container">
                    <div className="landing-navbar-content">
                        <Link to="/" className="landing-brand">
                            <div className="landing-brand-icon">
                                <ShieldCheck size={24} />
                            </div>
                            <div>
                                <div className="landing-brand-title">
                                    SecureSense AI
                                </div>
                                <div className="landing-brand-subtitle">
                                    Multi-Modal Explainable Trust Intelligence Platform
                                </div>
                            </div>
                        </Link>
                        <nav className="landing-nav-links">
                            <a href="#why">Why Us</a>
                            <a href="#platform">Capabilities</a>
                            <a href="#workflow">Workflow</a>
                            
                        </nav>
                        <div className="landing-navbar-actions">
                            <Link to="/login" className="landing-login-button">
                                Sign In
                            </Link>
                            <Link to="/register" className="landing-primary-button">
                                Create Account
                            </Link>
                        </div>
                        <button className="landing-mobile-menu">
                            <Menu size={24} />
                        </button>
                    </div>
                </div>
            </header>

            {/* =====================================================
                HERO
            ====================================================== */}
            <section className="landing-hero">
                <div className="landing-container">
                    <div className="landing-hero-grid">
                        <div className="landing-hero-content">
                            <h1>
                                Investigate Financial Communications
                                <span>
                                    Before You Trust Them.
                                </span>
                            </h1>
                            <p>
                                SecureSense AI is a Multi-Modal Explainable Trust Intelligence Platform that investigates, verifies, and explains the authenticity and security of financial communications across emails, SMS, website URLs, PDFs, QR codes, images, and voice recordings using evidence-driven artificial intelligence.
                            </p>

                            {/* THE SECURESENSE DIFFERENCE */}
                            <div className="landing-differentiator" style={{
                                padding: '1.25rem',
                                backgroundColor: 'var(--bg-muted, rgba(59, 130, 246, 0.1))',
                                borderLeft: '4px solid var(--primary-color, #3b82f6)',
                                borderRadius: '0.375rem',
                                margin: '1.5rem 0',
                                fontSize: '0.95rem',
                                lineHeight: '1.6'
                            }}>
                                <strong>Unlike conventional cybersecurity platforms,</strong> SecureSense AI not only detects phishing, impersonation, fraudulent websites, voice-based scams, and AI-assisted financial fraud, but also verifies the authenticity of legitimate financial communications before they are trusted.
                            </div>

                            <div className="landing-hero-actions">
                                <Link to="/register" className="landing-primary-button landing-large-button">
                                    Get Started
                                    <ArrowRight size={18} />
                                </Link>
                                <Link to="/login" className="landing-secondary-button landing-large-button">
                                    Sign In
                                </Link>
                            </div>
                        </div>

                        {/* HERO PANEL -> INVESTIGATION WORKSPACE */}
                        <div className="landing-hero-panel">
                            <div className="landing-panel-header">
                                Investigation Workspace
                            </div>
                            <div className="landing-dashboard-preview">
                                <div className="dashboard-status-bar">
                                    <span className="status-indicator"></span>
                                    System Status: Operational
                                </div>
                                <div className="dashboard-stats-grid">
                                    <div className="dashboard-stat-card">
                                        <span className="stat-value">7</span>
                                        <span className="stat-label">Supported Modalities</span>
                                    </div>
                                    <div className="dashboard-stat-card">
                                        <span className="stat-value">6</span>
                                        <span className="stat-label">Core Modules</span>
                                    </div>
                                    <div className="dashboard-stat-card">
                                        <span className="stat-value text-success">100%</span>
                                        <span className="stat-label">Explainable Evidence</span>
                                    </div>
                                    <div className="dashboard-stat-card">
    <span className="stat-value text-success">Verified</span>
    <span className="stat-label">Trust Decisions</span>
</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* =====================================================
                WHY SECURESENSE AI IS DIFFERENT
            ====================================================== */}
            <section id="why" className="landing-section landing-section-muted">
                <div className="landing-container">
                    <div className="landing-section-header">
                        <span>Why SecureSense AI is Different</span>
                        <h2>Beyond Standard Threat Detection</h2>
                        <p>
                            We combine advanced AI-driven threat detection with rigorous authenticity verification, culminating in a continuous, explainable trust architecture.
                        </p>
                    </div>
                    <div className="landing-values">
                        <div className="landing-value">
                            <Bot size={32} className="text-primary mb-4" />
                            <h3>Detects Financial Communication Threats</h3>
                            <ul className="value-list">
                                <li>Impersonation</li>
                                <li>Phishing</li>
                                <li>Fraudulent Websites</li>
                                <li>Voice-Based Scams</li>
                                <li>Fraud Campaigns</li>
                                <li>AI-Generated Financial Communications</li>
                            </ul>
                        </div>
                        <div className="landing-value">
                            <Shield size={32} className="text-primary mb-4" />
                            <h3>Verifies Authenticity</h3>
                            <ul className="value-list">
                                <li>Official Domain Verification</li>
                                <li>Authenticity Verification</li>
                                <li>Communication Consistency</li>
                                <li>Metadata Validation</li>
                            </ul>
                        </div>
                        <div className="landing-value">
                            <Eye size={32} className="text-primary mb-4" />
                            <h3>Multi-Modal Explainable Trust Intelligence</h3>
                            <ul className="value-list">
                                <li>Financial Communication Passport (FCP)</li>
                                <li>Securities Trust Graph (STG)</li>
                                <li>Explainable Evidence Ledger (EEL)</li>
                                <li>Unified Trust Dashboard</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </section>

            {/* =====================================================
                PLATFORM CAPABILITIES
            ====================================================== */}
            <section id="platform" className="landing-section">
                <div className="landing-container">
                    <div className="landing-section-header">
                        <span>Platform Capabilities</span>
                        <h2>A Unified Security Investigation Platform</h2>
                        <p>
                            SecureSense AI's core architecture processes, extracts, verifies, and scores financial communications in a continuous intelligence pipeline.
                        </p>
                    </div>
                    <div className="auth-feature-grid">
                        <article className="auth-feature">
                            <div className="auth-feature-icon">
                                <Upload size={28} />
                            </div>
                            <h3>Communication Ingestion</h3>
                            <p>
                                Securely submit and normalize emails, SMS, website URLs, PDFs, images, QR codes, and voice recordings for immediate investigation.
                            </p>
                        </article>
                        <article className="auth-feature">
                            <div className="auth-feature-icon">
                                <ScanSearch size={28} />
                            </div>
                            <h3>Multi-Modal Intelligence Layer</h3>
                            <p>
                                Extracts intelligence using NLP, OCR, URL Intelligence, QR Intelligence, Voice Intelligence, and Metadata Analysis.
                            </p>
                        </article>
                        <article className="auth-feature">
                            <div className="auth-feature-icon">
                                <ShieldCheck size={28} />
                            </div>
                            <h3>Trust Verification Engine</h3>
                            <p>
                                Actively verifies source authenticity via official domain checks, structural consistency, metadata forensics, and QR validation.
                            </p>
                        </article>
                        <article className="auth-feature">
                            <div className="auth-feature-icon">
                                <BrainCircuit size={28} />
                            </div>
                            <h3>Trust Intelligence Engine</h3>
                            <p>
                                Fuses verified multi-modal evidence into unified trust scores, risk assessments, explainable AI reasoning, and the Financial Communication Passport (FCP), Securities Trust Graph (STG), and Explainable Evidence Ledger (EEL).
                            </p>
                        </article>
                    </div>
                </div>
            </section>

            {/* =====================================================
                INVESTIGATION WORKFLOW
            ====================================================== */}
            <section id="workflow" className="landing-section landing-section-muted">
                <div className="landing-container">
                    <div className="landing-section-header">
                        <span>Investigation Workflow</span>
                        <h2>From Communication to Trusted Decision</h2>
                        <p>
                            Every investigation progresses through dedicated modules while maintaining a continuous explainable evidence trail.
                        </p>
                    </div>
           
                
                   <h3 className="workflow-modules-title">
    Integrated Security Modules
</h3>
                    <div className="landing-modules-grid">

                        <div className="landing-module-card">
                            <div className="module-card-header">
                                <Upload size={24} />
                                <h3>Communication Ingestion</h3>
                            </div>
                            <div className="module-card-body compact-body">
                                <strong>Supports</strong>
                                <ul className="compact-list">
                                    <li>Emails</li>
                                    <li>SMS</li>
                                    <li>Website URLs</li>
                                    <li>PDFs</li>
                                    <li>Images</li>
                                    <li>QR Codes</li>
                                    <li>Voice Recordings</li>
                                </ul>
                            </div>
                        </div>

                        <div className="landing-module-card">
                            <div className="module-card-header">
                                <ScanSearch size={24} />
                                <h3>Multi-Modal Intelligence</h3>
                            </div>
                            <div className="module-card-body compact-body">
                                <strong>Features</strong>
                                <ul className="compact-list">
                                    <li>Multimodal AI</li>
                                    <li>NLP & OCR</li>
                                    <li>URL Intelligence</li>
                                    <li>QR Intelligence</li>
                                    <li>Voice Intelligence</li>
                                </ul>
                            </div>
                        </div>

                        <div className="landing-module-card">
                            <div className="module-card-header">
                                <FileBadge2 size={24} />
                                <h3>Financial Communication Passport (FCP)</h3>
                            </div>
                            <div className="module-card-body compact-body">
                                <strong>Consolidates</strong>
                                <ul className="compact-list">
                                    <li>Authenticity Score</li>
                                    <li>Explainability</li>
                                    <li>Risk Assessment</li>
                                    <li>Investigation Findings</li>
                                </ul>
                            </div>
                        </div>

                        <div className="landing-module-card">
                            <div className="module-card-header">
                                <Network size={24} />
                                <h3>Securities Trust Graph (STG)</h3>
                            </div>
                            <div className="module-card-body compact-body">
                                <strong>Visualizes</strong>
                                <ul className="compact-list">
                                    <li>Communication Relationships</li>
                                    <li>Domain Relationships</li>
                                    <li>Entity Connections</li>
                                    <li>Contextual Risk Intelligence</li>
                                    <li>Evidence Provenance</li>
                                </ul>
                            </div>
                        </div>

                        <div className="landing-module-card">
                            <div className="module-card-header">
                                <Database size={24} />
                                <h3>Explainable Evidence Ledger (EEL)</h3>
                            </div>
                            <div className="module-card-body compact-body">
                                <strong>Maintains</strong>
                                <ul className="compact-list">
                                    <li>Persistent Records</li>
                                    <li>Auditable Trails</li>
                                    <li>Explainable Evidence</li>
                                    <li>Investigation Logs</li>
                                </ul>
                            </div>
                        </div>

                        <div className="landing-module-card">
                            <div className="module-card-header">
                                <LayoutDashboard size={24} />
                                <h3>Unified Trust Dashboard</h3>
                            </div>
                            <div className="module-card-body compact-body">
                                <strong>Centralizes</strong>
                                <ul className="compact-list">
                                    <li>Financial Communication Passport</li>
                                    <li>Securities Trust Graph</li>
                                    <li>Explainable Evidence Ledger</li>
                                    <li>Security Recommendations</li>
                                    <li>Downloadable Investigation Reports</li>
                                </ul>
                            </div>
                        </div>

                    </div>
            </div>
</section>

            {/* =====================================================
                CALL TO ACTION
            ====================================================== */}
            <section className="landing-cta">
                <div className="landing-container">
                    <h2>Start Your First Investigation</h2>
                    <p>
                        Create an account and analyze financial communications through a complete explainable workflow.
                    </p>
                    <div className="landing-hero-actions">
                        <Link to="/register" className="landing-primary-button landing-large-button">
                            Create Account
                        </Link>
                        <Link to="/login" className="landing-secondary-button landing-large-button">
                            Sign In
                        </Link>
                    </div>
                </div>
            </section>

            {/* =====================================================
                FOOTER
            ====================================================== */}
            <footer className="landing-footer">
                <div className="landing-container">
                    <div className="landing-footer-grid">
                        <div className="footer-brand-col">
    <h3>SecureSense AI</h3>
    <p>
        Multi-Modal Explainable Trust Intelligence Platform protecting India's securities market through AI-powered communication investigation, authenticity verification, and explainable decision intelligence.
    </p>
    <span className="footer-version">Version 1.0</span>
</div>
                        <div className="footer-col">
                            <strong>Platform</strong>
                            <ul>
    <li>
        <Link to="/dashboard">Unified Trust Dashboard</Link>
    </li>

    <li>
        <Link to="/upload">Communication Ingestion</Link>
    </li>

    <li>
        <Link to="/analysis">Investigation Workspace</Link>
    </li>

    <li>
        <Link to="/reports">Security Reports</Link>
    </li>

    <li>
        <Link to="/settings">Platform Settings</Link>
    </li>
</ul>
                        </div>
                        <div className="footer-col">
                            <strong>Modules</strong>
                            <ul>

    <li>
        <Link to="/upload">
            Communication Ingestion
        </Link>
    </li>

    <li>
        <Link to="/analysis">
            Multi-Modal Intelligence
        </Link>
    </li>

    <li>
        <Link to="/passport">
            Financial Communication Passport (FCP)
        </Link>
    </li>

    <li>
        <Link to="/trustgraph">
            Securities Trust Graph (STG)
        </Link>
    </li>

    <li>
        <Link to="/evidenceledger">
            Explainable Evidence Ledger (EEL)
        </Link>
    </li>

    <li>
        <Link to="/dashboard">
            Unified Trust Dashboard
        </Link>
    </li>

</ul>
                        </div>
                        <div className="footer-col">
                            <strong>Built For</strong>
                            <ul>
                                <li>Retail Investors</li>
                                <li>Stock Brokers</li>
                                <li>Depositories</li>
                                <li>Listed Companies</li>
                                <li>Banks & FinTech</li>
                                <li>Market Regulators</li>
                                <li>General Users</li>
                            </ul>

                            <strong style={{ marginTop: "36px", display: "block" }}>
        Account
    </strong>

    <ul>
        <li><Link to="/login">Login</Link></li>
        <li><Link to="/register">Register</Link></li>
    </ul>
</div>
                    </div>
                    <div className="landing-footer-bottom">
                        © 2026 SecureSense AI. All Rights Reserved.
                    </div>
                </div>
            </footer>
        </div>
    );
}