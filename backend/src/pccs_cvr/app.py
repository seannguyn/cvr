from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
import shutil
import os
from datetime import datetime
import logging
import zipfile
from .main import fetch_k8s_resources, cleanse_k8s_resouces_csv, generate_final_report, fetch_wiz_container_vulnerabilities_report
from time import sleep

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
DATA_DIR = os.getenv("DATA_DIR", "../data_cvr")
RAW_DIR = os.path.join(DATA_DIR, "raws")
REPORT_DIR = os.path.join(DATA_DIR, "reports")
CLUSTER_NAME = os.getenv("CLUSTER_NAME", "cluster")

# Ensure directories exist
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
        report_csv_path = f"{report_base_path}.csv"

        # Check if Wiz file exists
        if not os.path.exists(wiz_csv_path):
            raise HTTPException(status_code=404, detail=f"Wiz report for {date_str} not found. Please upload it first.")
        
        # 1. Fetch K8s resources (using SDK)
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
        k8s_cleansed_data = cleanse_k8s_resouces_csv(k8s_data, f"{RAW_DIR}/{date_str}-k8s-cleansed.csv")
        
        # 3. Read Wiz data
        wiz_data = fetch_wiz_container_vulnerabilities_report(wiz_csv_path)
        
        # 4. Generate Final Report
        generate_final_report(k8s_cleansed_data, wiz_data, report_base_path, date_str)
        
        return JSONResponse(content={"message": "Report generated successfully", "file_name": report_csv_path}, status_code=200)

    except HTTPException as he:
        raise he
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD.")
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports/all")
async def get_all_reports():
    """Returns a list of available report dates."""
    try:
        files = os.listdir(REPORT_DIR)
        dates = []
        for f in files:
            if f.endswith("-cvr.csv"):
                # Extract date from filename: YYYY-MM-DD-cvr.csv
                date_part = f.replace("-cvr.csv", "")
                dates.append(date_part)
        return {"dates": sorted(dates)}
    except Exception as e:
        logger.error(f"Error listing reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports/{date}")
async def get_report(date: str):
    file_path = f"{REPORT_DIR}/{date}-cvr.csv"
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type='text/csv', filename=f"{date}-cvr.csv")
    else:
        raise HTTPException(status_code=404, detail="Report not found")

def cleanup_file(path: str):
    """Deletes a file if it exists."""
    try:
        if os.path.exists(path):
            os.remove(path)
            logger.info(f"Deleted temporary file: {path}")
    except Exception as e:
        logger.warning(f"Failed to delete temporary file {path}: {e}")

@app.get("/download/{date}")
async def download_zip(date: str, background_tasks: BackgroundTasks):
    """Generates and downloads a zip file containing the CSV and MD reports."""
    try:
        # Validate date
        datetime.strptime(date, "%Y-%m-%d")
        
        csv_path = f"{REPORT_DIR}/{date}-cvr.csv"
        md_path = f"{REPORT_DIR}/{date}-cvr.md"
        
        if not os.path.exists(csv_path) or not os.path.exists(md_path):
            raise HTTPException(status_code=404, detail="Report files not found. Please generate the report first.")

        # Generate zip filename
        today_str = datetime.now().strftime("%Y-%m-%d")
        if date == today_str:
            timestamp = datetime.now().strftime("%H-%M-%S")
            zip_filename = f"{CLUSTER_NAME}-cvr-{date}-{timestamp}.zip"
            csv_arcname = f"{CLUSTER_NAME}-cvr-{date}-{timestamp}.csv"
            md_arcname = f"{CLUSTER_NAME}-cvr-{date}-{timestamp}.md"
        else:
            zip_filename = f"{CLUSTER_NAME}-cvr-{date}.zip"
            csv_arcname = f"{CLUSTER_NAME}-cvr-{date}.csv"
            md_arcname = f"{CLUSTER_NAME}-cvr-{date}.md"
            
        zip_path = f"{REPORT_DIR}/{zip_filename}"
        
        # Create zip file
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            zipf.write(csv_path, arcname=csv_arcname)
            zipf.write(md_path, arcname=md_arcname)
            
        logger.info(f"Created zip file: {zip_path}")
        
        # Schedule cleanup
        background_tasks.add_task(cleanup_file, zip_path)
        
        return FileResponse(zip_path, media_type='application/zip', filename=zip_filename)

    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD.")
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error creating zip download: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "ok"}
