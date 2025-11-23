FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY src/ src/

# Install dependencies
# We install in editable mode or just install the package
RUN pip install --no-cache-dir .

# Set environment variables
ENV RAW_DIR=raws
ENV REPORT_DIR=reports

# Create directories (they will be mounted, but good to have)
RUN mkdir -p raws reports

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "src.pccs_cvr.app:app", "--host", "0.0.0.0", "--port", "8000"]
