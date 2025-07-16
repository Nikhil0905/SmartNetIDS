# syntax=docker/dockerfile:1
FROM python:3.10-slim

# Set workdir
WORKDIR /app

# Install system dependencies (for scapy, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the code
COPY . .

# Expose Streamlit and Flask ports
EXPOSE 8501 5001

# Set environment variable for service selection
ENV SERVICE=dashboard

# Entrypoint script to select service
CMD ["/bin/bash", "-c", "if [ \"$SERVICE\" = 'api' ]; then python src/alert_api.py; else streamlit run src/dashboard.py --server.port=8501 --server.address=0.0.0.0; fi"] 