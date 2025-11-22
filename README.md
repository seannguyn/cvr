# PCCS Container Vulnerability Report (CVR)

A full-stack application to generate, view, and download container vulnerability reports by combining Kubernetes resource data with Wiz vulnerability scans.

## Architecture

```mermaid
graph TD
    User[User] -->|Access UI| Frontend[Frontend (React/Vite)]
    Frontend -->|API Calls| Backend[Backend (FastAPI)]
    Backend -->|Read/Write| Storage[Shared Storage (PVC)]
    Backend -->|K8s API| K8s[Kubernetes Cluster]
    
    subgraph "Data Flow"
        Wiz[Wiz Report (CSV)] -->|Upload| Backend
        K8s -->|Fetch Resources| Backend
        Backend -->|Generate| Report[Final Report (CSV/MD)]
        Report -->|Download| User
    end
```

## Backend

The backend is a FastAPI application responsible for data processing and report generation.

### Key Components
- **`main.py`**: Core logic for fetching K8s resources, cleansing data, and merging with Wiz reports.
- **`app.py`**: API endpoints for file upload, report generation, and download.
- **`data_cvr/`**: Directory for storing raw inputs (`raws/`) and generated reports (`reports/`).

### Workflows
1.  **Upload**: User uploads a Wiz CSV report via `/upload`.
2.  **Generate**: User triggers generation via `/cvr`. Backend fetches K8s data, merges it with the uploaded Wiz report, and saves the result.
3.  **Download**: User downloads the report via `/download/{date}`. A zip file is created on-the-fly containing CSV and MD formats.

### Local Development
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
uvicorn src.pccs_cvr.app:app --reload --port 8000
```

### Testing
Run unit tests using `pytest`:
```bash
pytest tests
```

### Docker Build
```bash
docker build -t pccs-cvr-backend:latest ./backend
```

## Frontend

The frontend is a React application built with Vite and Material UI.

### Key Components
- **`App.tsx`**: Main component handling UI layout, state, and API interactions.
- **`api.ts`**: Axios client for backend communication.
- **`config.js`**: Runtime configuration for environment variables (e.g., `clusterName`).

### Features
- **Upload**: Upload Wiz CSV reports.
- **Date Selection**: View reports for specific dates.
- **Data Table**: Sortable, filterable table with search highlighting and severity chips.
- **CMDB Display**: Formatted display of CMDB tags with bolding.
- **Download**: Download reports as a zip file.

### Local Development
```bash
cd frontend
npm install
npm run dev
```
Access at `http://localhost:5173`.

### Docker Build
```bash
docker build -t pccs-cvr-frontend:latest ./frontend
```

## Helm Charts

Deploy the application to a Kubernetes cluster using Helm.

### Deployment
```bash
helm install pccs-cvr ./charts/pccs-cvr --set clusterName="MyCluster"
```

### Configuration
- **`clusterName`**: Name of the cluster (displayed in UI and filenames).
- **`storage.size`**: Size of the PVC (default `1Gi`).

### Access
The frontend service type is `LoadBalancer` by default. Get the external IP:
```bash
kubectl get svc pccs-cvr-frontend
```

## End-to-End Testing Scenarios

### Scenario 1: Generate New Report
1.  Open the UI.
2.  Click "Upload Today's Wiz Report" and select a valid Wiz CSV.
3.  Verify the success message "Wiz report uploaded successfully!".
4.  Select today's date in the Date Picker.
5.  Verify the report generates and displays in the table.
6.  Check that "CMDB" column is populated and formatted correctly.

### Scenario 2: Download Report
1.  Select a date with an existing report.
2.  Click the "Download" button in the header.
3.  Verify a zip file is downloaded.
4.  Unzip and verify it contains both CSV and MD files.
5.  **Check Filename**:
    - If today: `cluster-cvr-YYYY-MM-DD-HH-MM-SS.zip`
    - If past: `cluster-cvr-YYYY-MM-DD.zip`

### Scenario 3: Column Visibility & Filtering
1.  Click the "View Columns" icon.
2.  Toggle "Scan Date" and verify it appears/disappears.
3.  Type in the global search box. Verify matching text is highlighted in yellow.
4.  Type in a column filter. Verify rows are filtered.

### Scenario 4: Runtime Configuration
1.  Deploy with `--set clusterName="ProdCluster"`.
2.  Open UI.
3.  Verify header shows "Container Vulnerability Report: ProdCluster".
