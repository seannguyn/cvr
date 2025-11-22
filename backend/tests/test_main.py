import pytest
from unittest.mock import patch, mock_open, MagicMock
from pccs_cvr.main import cleanse_k8s_resouces_csv, generate_final_report

def test_cleanse_k8s_resouces_csv():
    # Input data with duplicates and missing fields
    data = [
        {'NAMESPACE': 'ns1', 'PARENT_KIND': 'Deployment', 'PARENT_NAME': 'dep1', 'IMAGE': 'img1', 'IMAGEID': 'id1', 'CMDB': 'cmdb1'},
        {'NAMESPACE': 'ns1', 'PARENT_KIND': 'Deployment', 'PARENT_NAME': 'dep1', 'IMAGE': 'img1', 'IMAGEID': 'id1', 'CMDB': 'cmdb1'}, # Duplicate
        {'NAMESPACE': 'ns2', 'PARENT_KIND': 'Pod', 'PARENT_NAME': 'pod1', 'IMAGE': '', 'IMAGEID': 'id2', 'CMDB': 'cmdb2'}, # Missing Image
        {'NAMESPACE': 'ns3', 'PARENT_KIND': 'DaemonSet', 'PARENT_NAME': 'ds1', 'IMAGE': 'img3', 'IMAGEID': 'id3', 'CMDB': 'cmdb3'},
    ]
    
    with patch("builtins.open", mock_open()) as mock_file:
        cleansed = cleanse_k8s_resouces_csv(data, "dummy_path.csv")
        
        assert len(cleansed) == 2
        assert cleansed[0]['NAMESPACE'] == 'ns1'
        assert cleansed[1]['NAMESPACE'] == 'ns3'
        
        # Verify file write
        mock_file.assert_called_with("dummy_path.csv", mode='w', newline='', encoding='utf-8')

def test_generate_final_report():
    k8s_data = [
        {'NAMESPACE': 'ns1', 'PARENT_KIND': 'Deployment', 'PARENT_NAME': 'dep1', 'IMAGE': 'img1', 'IMAGEID': 'sha256:1234567890', 'CMDB': 'cmdb1'}
    ]
    wiz_data = [
        {'ImageId': '1234567890', 'AssetName': 'asset1', 'Severity': 'Critical', 'Name': 'CVE-1', 'Link': 'http://cve.com'}
    ]
    
    with patch("builtins.open", mock_open()) as mock_file:
        generate_final_report(k8s_data, wiz_data, "dummy_report", "2025-01-01")
        
        # Check if files were opened (CSV and MD)
        assert mock_file.call_count == 2
        mock_file.assert_any_call("dummy_report.csv", mode='w', newline='', encoding='utf-8')
        mock_file.assert_any_call("dummy_report.md", mode='w', encoding='utf-8')
