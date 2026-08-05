from pydantic import BaseModel


class OCRResponse(BaseModel):
    communication_id: str
    filename: str
    ocr_status: str
    extracted_text: str
    text_length: int

    class Config:
        from_attributes = True