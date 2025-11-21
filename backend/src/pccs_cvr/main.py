import logging
import sys
import csv
import subprocess
from typing import List, Dict

def setup_logging():
    """Configure logging for the application."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

def fetch_wiz_container_vulnerabilities_report(filepath: str):
    """Reads the vulnerability report CSV."""
    logger = logging.getLogger(__name__)
    logger.info(f"Reading vulnerability report from {filepath}")
    try:
        with open(filepath, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            logger.info(f"Read {len(rows)} records from vulnerability report")
            return rows
    except FileNotFoundError:
        logger.error(f"File not found: {filepath}")
        return []

def run_kubectl_command(cmd: str) -> List[Dict[str, str]]:
    """Runs a kubectl command and parses the custom-columns output."""
    logger = logging.getLogger(__name__)
    logger.info(f"Running command: {cmd}")
    
    try:
        result = subprocess.run(
            cmd, shell=True, check=True, capture_output=True, text=True
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e}")
        return []

    lines = result.stdout.strip().split('\n')
    if not lines:
        return []

    # Parse headers (assuming no spaces in headers)
    headers = lines[0].split()
    data = []
    
    for line in lines[1:]:
        # Split by whitespace. Note: This assumes values don't contain spaces.
        # The requested columns (NAMESPACE, KIND, NAME, IMAGE, IMAGEID) usually don't.
        parts = line.split()
        if len(parts) != len(headers):
            logger.warning(f"Skipping malformed line: {line}")
            continue
        
        row = dict(zip(headers, parts))
        data.append(row)
        
    return data

def fetch_k8s_resources() -> List[Dict[str, str]]:
    """Fetches K8s resources using kubectl."""
    queries = [
        "kubectl get pods -A -o custom-columns='NAMESPACE:.metadata.namespace,PARENT_KIND:.metadata.ownerReferences[0].kind,PARENT_NAME:.metadata.ownerReferences[0].name,IMAGE:.status.initContainerStatuses[*].image,IMAGEID:.status.initContainerStatuses[*].imageID'",
        "kubectl get pods -A -o custom-columns='NAMESPACE:.metadata.namespace,PARENT_KIND:.metadata.ownerReferences[0].kind,PARENT_NAME:.metadata.ownerReferences[0].name,IMAGE:.status.containerStatuses[*].image,IMAGEID:.status.containerStatuses[*].imageID'"
    ]
    
    all_data = []
    for query in queries:
        data = run_kubectl_command(query)
        all_data.extend(data)
        
    return all_data

def save_k8s_resouces_csv(data: List[Dict[str, str]], filepath: str):
    """Saves the K8s data to a CSV file."""
    logger = logging.getLogger(__name__)
    if not data:
        logger.warning("No K8s data to save")
        return

    logger.info(f"Saving K8s report to {filepath}")
    keys = data[0].keys()
    
    with open(filepath, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)
    
    logger.info(f"Saved {len(data)} records to {filepath}")

def cleanse_k8s_resouces_csv(data: List[Dict[str, str]], filepath: str) -> List[Dict[str, str]]:
    """Cleanses the K8s data CSV file and returns the cleansed data."""
    logger = logging.getLogger(__name__)
    if not data:
        logger.warning("No K8s data to cleanse")
        return []

    logger.info("Cleansing K8s data...")
    cleansed_data = []
    seen_rows = set()

    for row in data:
        namespace = row.get('NAMESPACE')
        parent_kind = row.get('PARENT_KIND')
        parent_name = row.get('PARENT_NAME')
        images_str = row.get('IMAGE', '')
        image_ids_str = row.get('IMAGEID', '')

        # Skip rows where image info is missing or <none>
        if not images_str or images_str == '<none>' or not image_ids_str or image_ids_str == '<none>':
            continue

        images = images_str.split(',')
        image_ids = image_ids_str.split(',')

        if len(images) != len(image_ids):
            logger.warning(f"Mismatch in image count for {namespace}/{parent_name}: {len(images)} images vs {len(image_ids)} IDs")
            continue

        for img, img_id in zip(images, image_ids):
            new_row = {
                'NAMESPACE': namespace,
                'PARENT_KIND': parent_kind,
                'PARENT_NAME': parent_name,
                'IMAGE': img,
                'IMAGEID': img_id
            }
            
            # Create a tuple for uniqueness check
            row_tuple = tuple(new_row.items())
            if row_tuple not in seen_rows:
                seen_rows.add(row_tuple)
                cleansed_data.append(new_row)

    logger.info(f"Cleansing complete. Resulting records: {len(cleansed_data)}")
    
    # Save cleansed data
    if cleansed_data:
        keys = cleansed_data[0].keys()
        with open(filepath, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(cleansed_data)
        logger.info(f"Saved cleansed data to {filepath}")
    else:
        logger.warning("No cleansed data to save")
        
    return cleansed_data

def generate_final_report(k8s_data: List[Dict[str, str]], wiz_data: List[Dict[str, str]], output_base_path: str, cluster_name: str, scan_date: str):
    """Joins K8s and Wiz data, generates CSV and Markdown reports."""
    logger = logging.getLogger(__name__)
    logger.info("Generating final report...")
    
    # Grouping dictionary: key -> list of CVE names
    grouped_data = {}
    
    # Severity order for sorting
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    
    for k8s_row in k8s_data:
        k8s_image_id = k8s_row.get('IMAGEID', '')
        
        for wiz_row in wiz_data:
            wiz_image_id = wiz_row.get('ImageId', '')
            
            # Check if K8s ImageID ends with Wiz ImageID
            if k8s_image_id.endswith(wiz_image_id):
                # Create a key for grouping (excluding IMAGEID and Name)
                key = (
                    k8s_row.get('NAMESPACE'),
                    k8s_row.get('PARENT_KIND'),
                    k8s_row.get('PARENT_NAME'),
                    k8s_row.get('IMAGE'),
                    wiz_row.get('AssetName'),
                    wiz_row.get('Severity')
                )
                
                if key not in grouped_data:
                    grouped_data[key] = set()
                
                # Add CVE Name to the set for this group
                grouped_data[key].add(wiz_row.get('Name'))

    # Convert grouped data to list of dicts with CamelCase keys
    # Requested order: Cluster, Image, AssetName, Severity, CVEs, Scan Date, Namespace, ParentKind, ParentName
    final_rows = []
    for key, cves in grouped_data.items():
        row = {
            'Cluster': cluster_name,
            'Image': key[3],
            'AssetName': key[4],
            'Severity': key[5],
            'CVEs': ", ".join(sorted(list(cves))), # Renamed from Name
            'Scan Date': scan_date,
            'Namespace': key[0],
            'ParentKind': key[1],
            'ParentName': key[2]
        }
        final_rows.append(row)

    # Sort by Namespace, then AssetName, then Severity
    final_rows.sort(key=lambda x: (
        x['Namespace'],
        x['AssetName'],
        severity_order.get(x['Severity'], 99)
    ))
    
    logger.info(f"Joined and grouped data contains {len(final_rows)} records")
    
    if not final_rows:
        logger.warning("No matching vulnerabilities found")
        return

    # Save CSV
    csv_path = f"{output_base_path}.csv"
    keys = ['Cluster', 'Image', 'AssetName', 'Severity', 'CVEs', 'Scan Date', 'Namespace', 'ParentKind', 'ParentName']
    with open(csv_path, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(final_rows)
    logger.info(f"Saved final CSV report to {csv_path}")
    
    # Save Markdown
    md_path = f"{output_base_path}.md"
    with open(md_path, mode='w', encoding='utf-8') as f:
        f.write("# Container Vulnerability Report\n\n")
        
        # Write header
        f.write("| " + " | ".join(keys) + " |\n")
        f.write("| " + " | ".join(["---"] * len(keys)) + " |\n")
        
        # Write rows
        for row in final_rows:
            values = [str(row.get(h, '')) for h in keys]
            f.write("| " + " | ".join(values) + " |\n")
            
    logger.info(f"Saved final Markdown report to {md_path}")

import argparse
from datetime import datetime
import os

def main():
    """Main entry point of the application."""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    parser = argparse.ArgumentParser(description='Generate container vulnerability report.')
    parser.add_argument('--cluster', type=str, default='fsp02', help='Cluster name (default: fsp02)')
    args = parser.parse_args()
    
    cluster_name = args.cluster
    
    today = datetime.now().strftime("%Y-%m-%d")
    input_path_wiz = f'raw/{cluster_name}-{today}-wiz.csv'
    input_path_k8s = f'raw/{cluster_name}-{today}-k8s.csv'
    output_path_report = f'reports/{cluster_name}-{today}'

    logger.info(f"Starting PCCS Container Vulnerabilities Report for cluster: {cluster_name}")
    
    wiz_data = fetch_wiz_container_vulnerabilities_report(input_path_wiz)
    
    k8s_raw_data = fetch_k8s_resources()
    
    # save_k8s_resouces_csv(k8s_raw_data, "raw/fsp02-k8s-raw.csv") # Optional: save raw data
    
    # Use the existing k8s file in raw/ for now since we are verifying backend code
    # In a real run we would use fetch_k8s_resources() output, but here we might want to rely on the file if kubectl isn't available or if we want to use the sample data.
    # However, the user asked to "Check that code in backend still run as expected", so I should probably use the fetched data if possible, OR just use the file if that's what the previous logic did.
    # The previous logic called fetch_k8s_resources() AND cleanse_k8s_resouces_csv().
    # I'll stick to the flow: fetch -> cleanse -> generate.
    
    k8s_cleansed_data = cleanse_k8s_resouces_csv(k8s_raw_data, input_path_k8s)
    
    generate_final_report(k8s_cleansed_data, wiz_data, output_path_report, cluster_name, today)

    logger.info("Application finished")

if __name__ == "__main__":
    main()
