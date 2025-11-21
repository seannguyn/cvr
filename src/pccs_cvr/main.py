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

def fetch_wiz_container_vulnerabilities_report():
    """Reads the vulnerability report CSV."""
    # Insert dummy code to query wiz for vulnerabilities report
    # For now just read the csv file: ../csv/fsp02-wiz-container-vulnerabilities.csv
    pass

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

def cleanse_k8s_resouces_csv(data: List[Dict[str, str]], filepath: str):
    """Cleanses the K8s data CSV file."""
    # For this query: kubectl get pods -A -o custom-columns='NAMESPACE:.metadata.namespace,PARENT_KIND:.metadata.ownerReferences[0].kind,PARENT_NAME:.metadata.ownerReferences[0].name,IMAGE:.status.initContainerStatuses[*].image,IMAGEID:.status.initContainerStatuses[*].imageID'
    # some records don't have initContainer, which result in a row like: kube-system   ReplicaSet    coredns-57c7d7fc58   <none>                                                                                     <none>
    # which is not valid for our use case, so we need to remove it

    # Also there will be cases where the same image will be listed multiple times, so we need to remove duplicates
    
    # Also a row can contain multiple images like this:
    # kube-system   DaemonSet     aws-node             602401143452.dkr.ecr.ap-southeast-2.amazonaws.com/amazon/aws-network-policy-agent:v1.2.7-eksbuild.1,602401143452.dkr.ecr.ap-southeast-2.amazonaws.com/amazon-k8s-cni:v1.20.4-eksbuild.2   602401143452.dkr.ecr.ap-southeast-2.amazonaws.com/amazon/aws-network-policy-agent@sha256:f99fb1fea5e16dc3a2429ddd0a2660d0f3b4ba40b467e81e1898b001ee54c240,602401143452.dkr.ecr.ap-southeast-2.amazonaws.com/amazon-k8s-cni@sha256:23f64d454047173490658c5866bca1a68d1b3c11df4248b2c837253d933fd150
    # so we need to split the image and imageID columns into multiple rows
    
    # save as csv in ../csv
    pass

def main():
    """Main entry point of the application."""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    logger.info("Starting PCCS Container Vulnerabilities Report")
    
    fetch_wiz_container_vulnerabilities_report()
    
    fetch_k8s_resources()
    
    save_k8s_resouces_csv()

    cleanse_k8s_resouces_csv
    
    logger.info("Application finished")

if __name__ == "__main__":
    main()
