import os
import shutil
import hashlib
from datetime import datetime

from sqlalchemy.orm import Session

from app.database.models import Communication
from uuid import uuid4
UPLOAD_DIR = "uploads"

os.makedirs(UPLOAD_DIR, exist_ok=True)


def generate_communication_id():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"COMM-{timestamp}-{uuid4().hex[:6].upper()}"


def save_uploaded_file(file, db: Session):
    communication_id = generate_communication_id()

    filename = os.path.basename(file.filename)
    _, extension = os.path.splitext(filename)
    extension = extension.lstrip(".").lower()

    saved_filename = f"{communication_id}.{extension}"

    filepath = os.path.join(
        UPLOAD_DIR,
        saved_filename
    )

    # Save uploaded file
    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Read file for metadata
    with open(filepath, "rb") as f:
        file_bytes = f.read()

    filesize = len(file_bytes)

    sha256 = hashlib.sha256(file_bytes).hexdigest()

    mime_type = file.content_type

    communication = Communication(
        communication_id=communication_id,
        filename=filename,
        file_type=extension,
        filepath=filepath,
        filesize=filesize,
        mime_type=mime_type,
        sha256=sha256,
        status="Uploaded"
    )

    db.add(communication)
    db.commit()
    db.refresh(communication)

    return communication