from fastapi import FastAPI
from routes.upload import router as upload_router

app = FastAPI(
    title="AI Offline Security Sandbox",
    description="Offline Intelligent File Security Analyzer",
    version="1.0"
)

app.include_router(upload_router)

@app.get("/")
def home():
    return {
        "status": "Running",
        "message": "AI Offline Sandbox Started Successfully"
    }