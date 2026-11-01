from fastapi import HTTPException
from fastapi import FastAPI
from pydantic import BaseModel, Field
import uvicorn
from pymongo import MongoClient
from fastapi import Response
from pymongo.errors import DuplicateKeyError

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header

import os
import secrets


load_dotenv()

def require_api_key(x_api_key: str = Header(default="")) -> None:
    if not secrets.compare_digest(x_api_key.encode("utf-8"), API_KEY.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid API key")

app = FastAPI(title="CommitGuard Report Service", dependencies=[Depends(require_api_key)])


API_KEY = os.environ["REPORT_API_KEY"]

if not API_KEY:
    raise RuntimeError("REPORT_API_KEY must not be empty")

client = MongoClient(os.environ["MONGODB_URI"], serverSelectionTimeoutMS=5000)
scans = client["commitguard"]["scans"]


class ScanReport(BaseModel):
    scan_id: str = Field(min_length=1, max_length=200)
    repository: str = Field(min_length=1)
    findings: list[dict]



@app.post("/scans", status_code=201)
def receive_scan(report: ScanReport, response: Response):
    document = report.model_dump()
    scan_id = document.pop("scan_id")

    try:
        result = scans.update_one(
            {"_id": scan_id},
            {"$setOnInsert": document},
            upsert=True,
        )
        created = result.upserted_id is not None
    except DuplicateKeyError:
        if scans.find_one({"_id": scan_id}, {"_id": 1}) is None:
            raise
        created = False

    response.status_code = 201 if created else 200

    return {"scan_id": scan_id, "created": created}

@app.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    report = scans.find_one({"_id": scan_id})

    if report is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    report["scan_id"] = report.pop("_id")

    return report

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)