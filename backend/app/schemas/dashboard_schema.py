"""
dashboard_schema.py

Pydantic schemas for the Dashboard API.
"""

from datetime import datetime
from typing import Dict, List

from pydantic import BaseModel


class Overview(BaseModel):
    total_documents: int
    processed_documents: int
    failed_documents: int


class RiskDistribution(BaseModel):
    high: int
    medium: int
    low: int


class RecentUpload(BaseModel):
    communication_id: str
    filename: str
    file_type: str
    risk_level: str
    status: str
    uploaded_at: datetime


class DashboardResponse(BaseModel):
    overview: Overview
    risk_distribution: RiskDistribution
    document_types: Dict[str, int]
    recent_uploads: List[RecentUpload]