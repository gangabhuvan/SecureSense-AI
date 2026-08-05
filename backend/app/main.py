from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.analysis import router as analysis_router
from app.database.database import Base, engine
from app.api import url
from app.api.upload import router as upload_router
from app.api.dashboard import router as dashboard_router
from app.api.nlp import router as nlp_router
from app.api.visual import router as visual_router
from app.api.ledger import router as ledger_router
from app.api.reports import router as reports_router
# ==========================================================
# Database
# ==========================================================

Base.metadata.create_all(bind=engine)


# ==========================================================
# FastAPI Application
# ==========================================================

app = FastAPI(
    title="SecureSense AI",
    description="Multi-Modal Trust Intelligence Platform",
    version="1.0.0",
)


# ==========================================================
# CORS
# ==========================================================

origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================================
# API Routes
# ==========================================================

app.include_router(upload_router)
app.include_router(dashboard_router)
app.include_router(analysis_router)
app.include_router(url.router)
app.include_router(nlp_router)
app.include_router(visual_router)
app.include_router(ledger_router)
app.include_router(reports_router)


# ==========================================================
# Root
# ==========================================================

@app.get("/")
def root():
    return {
        "message": "Welcome to SecureSense AI 🚀"
    }