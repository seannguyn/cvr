import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from pccs_cvr.app import app
import os

client = TestClient(app)

@pytest.fixture
def mock_env_vars(monkeypatch):
    monkeypatch.setenv("DATA_DIR", "/tmp/data_cvr")
    monkeypatch.setenv("CLUSTER_NAME", "test-cluster")

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

@patch("pccs_cvr.app.os.listdir")
def test_get_all_reports(mock_listdir):
    mock_listdir.return_value = ["2025-01-01-cvr.csv", "2025-01-02-cvr.csv"]
    response = client.get("/reports/all")
    assert response.status_code == 200
    assert "2025-01-01" in response.json()["dates"]
    assert "2025-01-02" in response.json()["dates"]

@patch("pccs_cvr.app.fetch_k8s_resources")
@patch("pccs_cvr.app.fetch_wiz_container_vulnerabilities_report")
@patch("pccs_cvr.app.generate_final_report")
@patch("pccs_cvr.app.cleanse_k8s_resouces_csv")
@patch("builtins.open", new_callable=MagicMock)
@patch("os.path.exists")
def test_generate_report(mock_exists, mock_open, mock_cleanse, mock_gen_report, mock_wiz, mock_k8s):
    # Mock existence checks
    # 1. report csv exists? False
    # 2. wiz csv exists? True
    mock_exists.side_effect = [False, True] 
    
    mock_k8s.return_value = [{'key': 'value'}]
    mock_cleanse.return_value = [{'key': 'value'}]
    mock_wiz.return_value = [{'key': 'value'}]
    
    response = client.post("/cvr", json={"date": "2025-01-01"})
    
    assert response.status_code == 200
    assert "Report generated successfully" in response.json()["message"]
    
    mock_k8s.assert_called_once()
    mock_gen_report.assert_called_once()

@patch("os.path.exists")
def test_download_zip_not_found(mock_exists):
    mock_exists.return_value = False
    response = client.get("/download/2025-01-01")
    assert response.status_code == 404
