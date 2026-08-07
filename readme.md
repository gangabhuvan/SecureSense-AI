<div align="center">

<img src="frontend/public/favicon.svg" alt="SecureSense AI Logo" width="90">

# SecureSense AI

### Multi-Modal Explainable Trust Intelligence Platform

### **Investigate Financial Communications Before You Trust Them.**

<p align="center">

SecureSense AI is a Multi-Modal Explainable Trust Intelligence Platform that investigates, verifies, and explains the authenticity and security of financial communications across emails, SMS, website URLs, PDFs, QR codes, images, and voice recordings using evidence-driven artificial intelligence.

</p>

---

### 🚀 Built for the SEBI Hackathon

*Protecting the securities market through explainable AI, trust intelligence, and multi-modal communication investigation.*

</div>

---

# 🌍 Overview

Financial fraud is no longer limited to suspicious emails or fake websites.

Modern financial attacks span multiple communication channels, including:

- 📧 Emails
- 💬 SMS & Messaging Platforms
- 🌐 Website URLs
- 📄 PDF Documents
- 🖼️ Images
- 🎙️ Voice Recordings
- 🔳 QR Codes

Each communication provides only a partial view of risk.

Traditional phishing detectors operate independently, making isolated predictions without understanding context, verifying authenticity, or explaining *why* a communication should or should not be trusted.

**SecureSense AI** addresses this challenge by introducing a **Multi-Modal Explainable Trust Intelligence Platform** that unifies AI-based security analysis, trust verification, explainability, and evidence-driven reasoning into a single investigation workflow.

Instead of producing isolated predictions, SecureSense AI correlates evidence from multiple AI models, contextual intelligence, and trust verification mechanisms to generate a unified, transparent, and explainable trust assessment.

---

# 🎯 Problem Statement

Financial communication fraud has evolved beyond simple phishing emails.

Attackers increasingly exploit:

- AI-generated phishing campaigns
- Impersonation attacks
- Fraudulent websites
- Fake investment communications
- Voice cloning
- QR-code scams
- User-generated cloud platforms
- Multi-stage social engineering

Existing detection systems typically focus on **one communication modality** or **one machine learning model**, resulting in fragmented security decisions with limited explainability.

This creates several critical challenges:

- Lack of unified trust assessment
- Limited explainability
- Poor cross-modal reasoning
- Inability to correlate evidence
- Difficulty auditing AI decisions
- No persistent security evidence for investigators

---

# 💡 Our Vision

SecureSense AI redefines communication security by moving beyond isolated predictions toward **Explainable Trust Intelligence**.

Rather than asking:

> "Is this phishing?"

SecureSense AI answers:

> **"Can this communication be trusted, and what evidence supports that conclusion?"**

Every investigation combines:

- Multi-modal AI intelligence
- Context-aware reasoning
- Authenticity verification
- Explainable AI
- Evidence correlation
- Trust graph analysis
- Auditable evidence storage

The result is a transparent, evidence-backed trust assessment instead of a black-box prediction.

---

# ✨ Core Innovations

SecureSense AI introduces several novel architectural components that work together as a unified trust intelligence ecosystem.

---

## 🧠 Multi-Modal Intelligence

Instead of relying on a single detector, SecureSense AI analyses communications across multiple modalities.

Supported modalities include:

- Text
- URLs
- Documents
- Images
- QR Codes
- Voice
- OCR Extracted Content

Each modality is analysed using specialized AI models before being fused into a single explainable security decision.

---

## 🧭 Communication Intent Intelligence (CII)

Communication Intent Intelligence determines **why** a communication exists before evaluating its security.

Rather than only detecting phishing, CII identifies semantic intent such as:

- Banking
- Investment
- KYC Verification
- General Announcement
- Payment Requests
- Customer Support
- Unknown Context

This enables SecureSense AI to understand communication purpose alongside security risk.

---

## 📄 Optical Content Extraction (OCE)

OCE intelligently extracts structured information from uploaded documents and images.

Capabilities include:

- OCR
- Entity Extraction
- URL Detection
- QR Detection
- Document Context Classification

This allows visual communications to enter the same investigation pipeline as textual content.

---

## 🌐 Securities Trust Graph (STG)

The Securities Trust Graph models historical trust relationships between observed entities.

Instead of treating every communication independently, STG provides contextual trust intelligence by analysing:

- Domains
- Organizations
- Financial Institutions
- Government Agencies
- Historical Security Evidence

This enables entity-level trust reasoning beyond individual communications.

---

## 📘 Explainable Evidence Ledger (EEL)

Every AI prediction generated by SecureSense AI is permanently transformed into explainable evidence.

Unlike conventional AI systems that return only predictions, SecureSense AI records:

- Model used
- Prediction
- Confidence
- Risk Score
- Feature Contributions
- Explainability Output
- Timestamp
- Evidence Metadata

This creates a transparent audit trail for every investigation.

---

## 🛂 Financial Communication Passport (FCP)

Every investigation produces a **Financial Communication Passport**.

The passport consolidates:

- Communication identity
- Security assessment
- Threat indicators
- Trust verification
- Sender profile
- AI findings
- Evidence references
- Recommended actions

Instead of reading multiple reports, investigators receive a single standardized trust profile.

---

# 🏗️ High-Level Architecture

```text
                              SecureSense AI

                     Communication Investigation

                                  │
                                  ▼

                  Multi-Modal Intelligence Layer

         ┌───────────────────────────────────────────────┐
         │ NLP │ URL │ Visual │ Voice │ OCR │ QR │ CII │
         └───────────────────────────────────────────────┘

                                  │
                                  ▼

                Trust Verification Engine (TVE)

                                  │
                                  ▼

                Trust Intelligence Engine (TIE)

                                  │
               ┌──────────────────┴──────────────────┐
               ▼                                     ▼

     Securities Trust Graph (STG)    Financial Communication Passport (FCP)

               └──────────────────┬──────────────────┘
                                  ▼

             Explainable Evidence Ledger (EEL)

                                  │
                                  ▼

               Unified Security Investigation
```

---

# 🔬 End-to-End Investigation Pipeline

Every investigation follows the same explainable workflow.

```
Communication
        │
        ▼
Communication Selection
        │
        ▼
Optical Content Extraction (OCE)
        │
        ▼
Multi-Modal Intelligence
        │
        ▼
Trust Verification
        │
        ▼
Trust Intelligence Engine
        │
        ▼
Evidence Fusion
        │
        ▼
Financial Communication Passport
        │
        ▼
Explainable Evidence Ledger
        │
        ▼
Unified Investigation Dashboard
```

---

# 🌐 Supported Communication Modalities

| Communication Type | Supported |
|--------------------|-----------|
| 📧 Emails | ✅ |
| 💬 Text Messages | ✅ |
| 🌐 Website URLs | ✅ |
| 📄 PDF Documents | ✅ |
| 🖼️ Images | ✅ |
| 🔳 QR Codes | ✅ |
| 🎙️ Voice Recordings | ✅ |

---
# 🤖 Artificial Intelligence Models

SecureSense AI integrates multiple specialized AI models, each designed to analyse a different communication modality. Rather than relying on a single prediction, every model contributes explainable evidence that is fused into a unified trust assessment.

> **Repository Note**
>
> All pre-trained AI models required by SecureSense AI are included in this repository. No additional model training is required before running the application.

| Intelligence Module | AI Model | Purpose | Explainability |
|---------------------|----------|---------|----------------|
| 📝 NLP Intelligence | DistilBERT | Detect phishing, spam and legitimate communications | Integrated Gradients |
| 🌐 URL Intelligence | XGBoost (17-Feature Model) | Analyse website URLs for phishing risk | TreeSHAP |
| 🖼️ Visual Intelligence | ConvNeXt-Tiny | Detect phishing from screenshots, posters and images | Grad-CAM |
| 🎙️ Voice Intelligence | Whisper Base + Spectra-AASIST3 | Speech transcription and AI-generated voice fraud detection | Confidence Analysis |
| 🧠 Communication Intent Intelligence (CII) | SentenceTransformer (all-MiniLM-L6-v2) | Understand communication purpose and security intent | Semantic Evidence |
| 📄 Optical Content Extraction (OCE) | EasyOCR + PDFPlumber + OpenCV | Extract structured information from documents and images | OCR Evidence |

---

# ⚙️ Platform Modules

SecureSense AI consists of multiple interconnected modules that together perform a complete financial communication investigation.

---

## 📝 NLP Intelligence

Analyses textual communications using a fine-tuned DistilBERT model.

### Responsibilities

- Phishing Detection
- Spam Detection
- Legitimate Communication Classification
- Confidence Estimation
- Explainability using Integrated Gradients

---

## 🌐 URL Intelligence

Investigates embedded or standalone URLs using a production XGBoost phishing detection model.

### Capabilities

- URL Feature Extraction
- Domain Intelligence
- DNS Verification
- WHOIS Analysis
- Risk Scoring
- TreeSHAP Explainability

---

## 🖼️ Visual Intelligence

Analyses uploaded screenshots and images to detect phishing indicators.

### Capabilities

- Visual Phishing Detection
- Website Screenshot Analysis
- Login Page Analysis
- Explainability using Grad-CAM

---

## 🎙️ Voice Intelligence

Detects AI-generated or manipulated voice recordings.

### Pipeline

Voice Recording

↓

Speech Transcription

↓

Authenticity Verification

↓

Deepfake Detection

↓

Voice Risk Assessment

---

## 📄 Optical Content Extraction (OCE)

Extracts structured evidence from uploaded documents.

### Supported Formats

- PDF
- PNG
- JPG
- JPEG

### Extracted Information

- OCR Text
- URLs
- QR Codes
- Financial Entities
- Contact Information
- Structured Metadata

---

## 🧭 Communication Intent Intelligence (CII)

CII identifies the semantic purpose of a communication before security analysis.

Rather than only asking:

> "Is this phishing?"

CII asks:

> "What is this communication attempting to do?"

Detected contexts include:

- Banking
- Investments
- KYC
- Customer Support
- Payment Requests
- General Announcement
- Unknown

This contextual understanding improves downstream trust reasoning.

---

## 🔍 Trust Verification Engine (TVE)

The Trust Verification Engine validates the authenticity of entities discovered during investigation.

Capabilities include:

- Domain Verification
- Organization Verification
- Trusted Hosting Detection
- Government Domain Recognition
- Official Platform Recognition
- User-Generated Content Detection

---

## 🧠 Trust Intelligence Engine (TIE)

The Trust Intelligence Engine performs evidence-driven reasoning across all AI modules.

Responsibilities include:

- Cross-Modal Evidence Correlation
- Risk Fusion
- Conflict Resolution
- Security Reasoning
- Final Trust Assessment

Rather than averaging predictions, TIE preserves the strongest explainable security evidence while maintaining complete traceability.

---

## 🌐 Securities Trust Graph (STG)

The Securities Trust Graph stores historical trust intelligence for observed entities.

Each investigation enriches the graph with explainable security evidence.

Tracked entities include:

- Domains
- Organizations
- Financial Institutions
- Government Agencies
- Email Addresses
- Phone Numbers

STG enables SecureSense AI to reason beyond a single communication by incorporating historical trust context.

---

## 📘 Explainable Evidence Ledger (EEL)

Every prediction generated during an investigation becomes a permanent explainable evidence record.

Each record stores:

- Module
- Prediction
- Confidence
- Risk Score
- Explainability Output
- Feature Contributions
- Timestamp
- Evidence Identifier

Unlike traditional logging systems, EEL preserves complete explainable AI evidence for auditing and forensic investigation.

---

## 🛂 Financial Communication Passport (FCP)

The Financial Communication Passport is the unified investigation report generated for every analysed communication.

The passport contains:

- Communication Identifier
- Sender Information
- Security Assessment
- Risk Score
- Trust Score
- Threat Indicators
- Verification Status
- Recommended Action
- Evidence References

The FCP transforms complex AI outputs into a standardized trust profile suitable for investigators and end users.

---

# 🔄 Investigation Workflow

Every investigation follows a consistent evidence-driven pipeline.

| Step | Investigation Stage |
|------|----------------------|
| 1 | Communication Ingestion |
| 2 | Communication Selection |
| 3 | Optical Content Extraction |
| 4 | Multi-Modal Intelligence Analysis |
| 5 | Trust Verification |
| 6 | Trust Intelligence Fusion |
| 7 | Securities Trust Graph Analysis |
| 8 | Financial Communication Passport Generation |
| 9 | Explainable Evidence Ledger Recording |
| 10 | Unified Investigation Dashboard |

---

# 🔍 Explainable Artificial Intelligence

Explainability is a core design principle of SecureSense AI.

Every AI prediction is accompanied by interpretable evidence rather than a black-box confidence score.

| Module | Explainability Technique |
|----------|--------------------------|
| NLP Intelligence | Integrated Gradients |
| URL Intelligence | TreeSHAP |
| Visual Intelligence | Grad-CAM |
| Communication Intent Intelligence | Semantic Evidence |
| Trust Intelligence Engine | Evidence Fusion Summary |
| Explainable Evidence Ledger | Persistent Evidence Records |

This enables users to understand:

- Why a communication was classified
- Which evidence influenced the decision
- Which AI model contributed
- How confidence and risk were derived

---

# 🛠️ Technology Stack & Frameworks

### Backend

- FastAPI
- SQLAlchemy
- SQLite
- Pydantic
- Uvicorn

### Frontend

- React
- Vite
- Axios
- CSS3

### Artificial Intelligence Models

- DistilBERT (NLP Phishing Detection)
- ConvNeXt-Tiny (Visual Phishing Detection)
- XGBoost (17-Feature URL Intelligence)
- Whisper Base (Speech Transcription)
- Spectra-AASIST3 (AI Voice Deepfake Detection)
- all-MiniLM-L6-v2 SentenceTransformer (Communication Intent Intelligence)

### Explainable AI

- SHAP (TreeSHAP)
- Grad-CAM
- Integrated Gradients
- Evidence Fusion

### Document & Visual Processing

- EasyOCR
- PDFPlumber
- OpenCV
- Pillow

### Data Science & Machine Learning

- PyTorch
- Transformers
- Sentence Transformers
- NumPy
- Pandas
- Scikit-learn

---

# 📂 Project Structure

```text
SecureSense-AI/
│
├── backend/
│   ├── app/
│   │   ├── ai/
│   │   ├── api/
│   │   ├── core/
│   │   ├── database/
│   │   ├── eel/
│   │   ├── fcp/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── stg/
│   │   ├── trust_engine/
│   │   └── main.py
│   │
│   ├── uploads/
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/
│   ├── src/
│   ├── public/
│   ├── package.json
│   └── vite.config.js
│
├── README.md
└── .gitignore
```

---

# 🚀 Getting Started

## 1️⃣ Clone the Repository

```bash
git clone https://github.com/gangabhuvan/SecureSense-AI.git
cd SecureSense-AI
```

---

## 2️⃣ Backend Setup

```bash
cd backend

python -m venv .venv
```

### Windows

```bash
.venv\Scripts\activate
```

### Linux / macOS

```bash
source .venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

Create the environment configuration

```bash
cp .env.example .env
```

Open the generated `.env` file and configure the authentication settings before starting the backend.

Run the backend

```bash
uvicorn app.main:app --reload
```

Backend URL

```
http://127.0.0.1:8000
```

---

## 3️⃣ Frontend Setup

```bash
cd frontend

npm install

npm run dev
```

Frontend URL

```
http://localhost:5173
```

# 🌟 What Makes SecureSense AI Different?

SecureSense AI is **not another phishing detector**.

It is an **end-to-end Multi-Modal Explainable Trust Intelligence Platform** designed to investigate financial communications using multiple AI models, authenticity verification, explainable evidence, and trust reasoning.

Unlike traditional security systems that analyse a single communication modality or produce isolated predictions, SecureSense AI performs a unified investigation by correlating evidence across multiple intelligence modules before generating a transparent trust assessment.

Instead of answering only:

> **"Is this phishing?"**

SecureSense AI answers:

> **"Can this financial communication be trusted, what evidence supports that conclusion, and why?"**

---

# 🚀 Key Contributions

SecureSense AI introduces an integrated architecture that combines multiple research and engineering concepts into a single explainable investigation platform.

### ✅ Multi-Modal Communication Investigation

Analyses financial communications across:

- Text
- Website URLs
- PDF Documents
- Images
- QR Codes
- Voice Recordings

---

### ✅ Explainable AI by Design

Every AI prediction is accompanied by interpretable evidence.

Explainability techniques include:

- Integrated Gradients
- TreeSHAP
- Grad-CAM
- Semantic Evidence
- Evidence Fusion Summary

---

### ✅ Communication Intent Intelligence (CII)

Rather than relying solely on phishing classification, SecureSense AI first determines the semantic purpose of a communication.

Examples include:

- Banking
- Investments
- Customer Support
- Payment Requests
- KYC Verification
- General Announcements

This contextual understanding enables more informed trust reasoning.

---

### ✅ Trust Verification Engine

SecureSense AI separates:

**Infrastructure Trust**

from

**Content Trust**

For example,

an official Google Forms link is recognised as trusted infrastructure while still reminding users that the hosted content is user-generated and should be verified before sharing sensitive information.

---

### ✅ Securities Trust Graph (STG)

SecureSense AI builds historical trust intelligence around observed entities instead of treating every investigation independently.

This enables entity-centric reasoning across multiple communications.

---

### ✅ Explainable Evidence Ledger (EEL)

Every investigation produces persistent evidence records instead of temporary prediction logs.

Each record contains:

- AI Model
- Prediction
- Confidence
- Risk Score
- Explainability
- Timestamp
- Evidence Metadata

This creates a transparent audit trail suitable for security investigations.

---

### ✅ Financial Communication Passport (FCP)

Instead of returning multiple disconnected outputs, SecureSense AI consolidates all investigation findings into a standardized Financial Communication Passport that summarises:

- Security Assessment
- Trust Score
- Threat Indicators
- Sender Verification
- Recommended Actions
- Evidence References

---

# 📊 Comparison with Conventional Approaches

| Capability | Traditional Phishing Detection | SecureSense AI |
|------------|-------------------------------|----------------|
| Text Analysis | ✅ | ✅ |
| URL Analysis | Limited | ✅ |
| Image Analysis | Rare | ✅ |
| Voice Scam Detection | ❌ | ✅ |
| QR Code Investigation | Limited | ✅ |
| Multi-Modal Fusion | ❌ | ✅ |
| Communication Intent Understanding | ❌ | ✅ |
| Authenticity Verification | Limited | ✅ |
| Explainable AI | Limited | ✅ |
| Trust Graph Intelligence | ❌ | ✅ |
| Evidence Ledger | ❌ | ✅ |
| Unified Investigation Dashboard | ❌ | ✅ |
| Financial Communication Passport | ❌ | ✅ |

---

# 🔒 Security Philosophy

SecureSense AI follows a simple principle:

> **Trust should be earned through evidence—not assumed from appearance.**

The platform therefore distinguishes between:

- Trusted infrastructure
- User-generated content
- Communication authenticity
- Historical trust intelligence
- AI security evidence

Every recommendation is based on explainable evidence generated during the investigation.

---

# 🔮 Future Enhancements

Future work may include:

- Real-time email integration
- Browser extension for instant URL investigation
- Mobile application
- Large Language Model assisted investigation summaries
- Graph Neural Networks for advanced trust reasoning
- Federated trust intelligence across institutions
- Blockchain-backed evidence integrity
- Real-time threat intelligence integration
- Continuous trust graph learning

---

# 👨‍💻 Project Information

**Project**

SecureSense AI

**Category**

Financial Communication Security

**Architecture**

Multi-Modal Explainable Trust Intelligence Platform

**Primary Technologies**

FastAPI • React • PyTorch • XGBoost • SQLAlchemy • Transformers

---

# 🤝 Contributors

**Bhuvankumar A Patri**

Information Science & Engineering

Nitte Meenakshi Institute of Technology

---

# ⭐ Acknowledgements

This project was developed as part of the **SEBI Hackathon** to explore how explainable artificial intelligence, trust intelligence, and multi-modal security analysis can improve the investigation of financial communications.

Special thanks to the open-source community and the developers of:

- FastAPI
- React
- PyTorch
- Hugging Face Transformers
- XGBoost
- Sentence Transformers
- SHAP
- OpenCV
- EasyOCR
- Whisper

whose tools and research have enabled rapid innovation in trustworthy AI systems.

---

<div align="center">

<img src="frontend/public/favicon.svg" alt="SecureSense AI Logo" width="90">

# SecureSense AI

### Multi-Modal Explainable Trust Intelligence Platform

### **Investigate Financial Communications Before You Trust Them.**

---

**Building trustworthy AI for secure financial communication investigations.**

⭐ If you found this project interesting, consider giving it a star!

</div>