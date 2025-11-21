import logging
import sys
import csv
from typing import List, Dict, Any
from kubernetes import client, config

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

def get_k8s_client():
    """Loads K8s config and returns CoreV1Api client."""
    logger = logging.getLogger(__name__)
    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster config")
    except config.ConfigException:
        try:
            config.load_kube_config()
            logger.info("Loaded kube-config")
        except config.ConfigException:
            logger.error("Could not load K8s config")
            return None
    return client.CoreV1Api()

def fetch_k8s_resources() -> List[Dict[str, str]]:
    """Fetches K8s resources using Kubernetes SDK."""
    logger = logging.getLogger(__name__)
    v1 = get_k8s_client()
    if not v1:
        return []

    logger.info("Fetching pods from all namespaces...")
    try:
        pods = v1.list_pod_for_all_namespaces(watch=False)
    except client.ApiException as e:
        logger.error(f"Exception when calling CoreV1Api->list_pod_for_all_namespaces: {e}")
        return []

    all_data = []
    for pod in pods.items:
        namespace = pod.metadata.namespace
        
        # Get parent info
        parent_kind = "<none>"
        parent_name = "<none>"
        if pod.metadata.owner_references:
            parent_kind = pod.metadata.owner_references[0].kind
            parent_name = pod.metadata.owner_references[0].name
            
        # Get labels
        labels = pod.metadata.labels if pod.metadata.labels else {}
        labels_str = ",".join([f"{k}={v}" for k, v in labels.items()])

        # Process Init Containers
        if pod.status.init_container_statuses:
            for status in pod.status.init_container_statuses:
                all_data.append({
                    'NAMESPACE': namespace,
                    'PARENT_KIND': parent_kind,
                    'PARENT_NAME': parent_name,
                    'IMAGE': status.image,
                    'IMAGEID': status.image_id,
                    'LABELS': labels_str
                })

        # Process Containers
        if pod.status.container_statuses:
            for status in pod.status.container_statuses:
                all_data.append({
                    'NAMESPACE': namespace,
                    'PARENT_KIND': parent_kind,
                    'PARENT_NAME': parent_name,
                    'IMAGE': status.image,
                    'IMAGEID': status.image_id,
                    'LABELS': labels_str
                })
                
    logger.info(f"Fetched {len(all_data)} container records")
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
        image = row.get('IMAGE', '')
        image_id = row.get('IMAGEID', '')
        labels = row.get('LABELS', '')

        # Skip rows where image info is missing or <none>
        if not image or image == '<none>' or not image_id or image_id == '<none>':
            continue

        # Note: SDK returns individual statuses, so no need to split by comma like in kubectl custom-columns
        # However, to be safe and consistent with previous logic if any weirdness, we keep it simple.
        # But wait, previous logic handled comma separated values because custom-columns aggregated them.
        # My new SDK logic appends a row per container, so NO comma splitting needed for IMAGE/IMAGEID.
        
        new_row = {
            'NAMESPACE': namespace,
            'PARENT_KIND': parent_kind,
            'PARENT_NAME': parent_name,
            'IMAGE': image,
            'IMAGEID': image_id,
            'LABELS': labels
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
    
    # Save Markdown (Optional, but kept for consistency)
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
