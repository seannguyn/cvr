import os
import shutil
import logging
import sys

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )

def sync_docs():
    logger = logging.getLogger(__name__)
    source_dir = "reports"
    target_dir = "docs/reports"
    
    logger.info(f"Syncing reports from {source_dir} to {target_dir}")
    
    if not os.path.exists(source_dir):
        logger.warning(f"Source directory {source_dir} does not exist. Nothing to sync.")
        return

    # Walk through the source directory
    for root, dirs, files in os.walk(source_dir):
        # Determine the relative path
        rel_path = os.path.relpath(root, source_dir)
        
        # Determine the target directory
        target_path = os.path.join(target_dir, rel_path)
        
        # Create target directory if it doesn't exist
        if not os.path.exists(target_path):
            os.makedirs(target_path)
            
        for file in files:
            if file.endswith(".md") or file.endswith(".csv"):
                source_file = os.path.join(root, file)
                target_file = os.path.join(target_path, file)
                
                shutil.copy2(source_file, target_file)
                logger.info(f"Copied {source_file} to {target_file}")

    logger.info("Sync completed")

if __name__ == "__main__":
    setup_logging()
    sync_docs()
