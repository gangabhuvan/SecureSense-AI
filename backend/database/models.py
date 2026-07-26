from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime

from .database import Base


class Communication(Base):
    __tablename__ = "communications"

    id = Column(Integer, primary_key=True, index=True)

    communication_id = Column(String, unique=True)

    filename = Column(String)

    filetype = Column(String)

    filepath = Column(String)

    status = Column(String)

    uploaded_at = Column(DateTime, default=datetime.utcnow)