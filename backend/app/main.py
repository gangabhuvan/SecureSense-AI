from fastapi import FastAPI

app = FastAPI(
    title="SecureSense AI",
    description="Multi-Modal Trust Intelligence Platform",
    version="1.0.0"
)

@app.get("/")
def root():
    return {
        "message": "Welcome to SecureSense AI 🚀"
    }