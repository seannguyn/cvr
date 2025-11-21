from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
import shutil
import os
from datetime import datetime
import logging
from .main import fetch_k8s_resources, cleanse_k8s_resouces_csv, generate_final_report, fetch_wiz_container_vulnerabilities_report

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For dev, allow all. In prod, specify frontend URL.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Constants
RAW_DIR = os.getenv("RAW_DIR", "../raws")
REPORT_DIR = os.getenv("REPORT_DIR", "../reports")

# Ensure directories exist
# Note: In a read-only container or if paths are relative to root, this might fail if not careful.
# For local dev (../raws), it checks the parent dir.
os.makedirs(RAW_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

class ReportRequest(BaseModel):
    date: str

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    try:
        today = datetime.now().strftime("%Y-%m-%d")
        file_location = f"{RAW_DIR}/{today}-wiz.csv"
        
        with open(file_location, "wb+") as file_object:
            shutil.copyfileobj(file.file, file_object)
            
        logger.info(f"File uploaded successfully to {file_location}")
        return JSONResponse(content={"message": "File uploaded successfully", "filename": file_location}, status_code=200)
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to upload file: {str(e)}")

@app.post("/cvr")
async def generate_report(request: ReportRequest):
    date_str = request.date
    try:
        # Validate date format
        datetime.strptime(date_str, "%Y-%m-%d")
        
        # Define paths
        wiz_csv_path = f"{RAW_DIR}/{date_str}-wiz.csv"
        k8s_csv_path = f"{RAW_DIR}/{date_str}-k8s.csv"
        report_base_path = f"{REPORT_DIR}/{date_str}-cvr"
        
        # Check if Wiz file exists
        if not os.path.exists(wiz_csv_path):
            raise HTTPException(status_code=404, detail=f"Wiz report for {date_str} not found. Please upload it first.")
        
        # 1. Fetch K8s resources (using SDK)
        # Note: fetch_k8s_resources now returns data directly, we need to save it to CSV for consistency/debugging or just use it
        # The requirement says: "save it to raws/YYYY-MM-DD-k8s.csv, maintain the same columns as the current one"
        logger.info("Fetching K8s resources...")
        k8s_data = fetch_k8s_resources()
        
        # Save K8s raw data
        import csv
        if k8s_data:
            keys = k8s_data[0].keys()
            with open(k8s_csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(k8s_data)
        
        # 2. Cleanse K8s data
        # We can pass the raw data directly or read from file. The current cleanse function takes data list.
        k8s_cleansed_data = cleanse_k8s_resouces_csv(k8s_data, f"{RAW_DIR}/{date_str}-k8s-cleansed.csv")
        
        # 3. Read Wiz data
        wiz_data = fetch_wiz_container_vulnerabilities_report(wiz_csv_path)
        
        # 4. Generate Final Report
        # We need to pass a cluster name. The requirement doesn't specify how to get it, maybe default or from env?
        # For now, let's assume a default or extract from data if possible. 
        # The previous code took it as an arg. Let's use a default "cluster" for now or maybe we can find it in the k8s data?
        # Actually, the requirement says "expose an endpoint /cvr, which takes in date format: YYYY-MM-DD". No cluster name.
        # But the report needs a cluster column. I'll use "current-cluster" or similar if not provided.
        # Or maybe I should add it to the request model? The plan didn't say.
        # I'll stick to "current-cluster" for now as it's running in the cluster.
        cluster_name = "current-cluster" 
        
        generate_final_report(k8s_cleansed_data, wiz_data, report_base_path, cluster_name, date_str)
        
        return JSONResponse(content={"message": f"Report generated successfully", "file_name": f"{report_base_path}.csv"}, status_code=200)

    except HTTPException as he:
        raise he
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD.")
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports/{date}")
async def get_report(date: str):
    file_path = f"{REPORT_DIR}/{date}-cvr.csv"
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type='text/csv', filename=f"{date}-cvr.csv")
    else:
        raise HTTPException(status_code=404, detail="Report not found")

@app.get("/health")
async def health_check():
    return {"status": "ok"}
