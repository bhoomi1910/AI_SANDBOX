from fastapi import APIRouter, UploadFile, File
import os
import uuid
import shutil
from datetime import datetime

router = APIRouter()

UPLOAD_FOLDER = "../uploads"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):

    unique_id = str(uuid.uuid4())

    filename = unique_id + "_" + file.filename

    filepath = os.path.join(UPLOAD_FOLDER, filename)

    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {
        "success": True,
        "file_id": unique_id,
        "original_name": file.filename,
        "saved_name": filename,
        "upload_time": datetime.now(),
        "location": filepath
    }