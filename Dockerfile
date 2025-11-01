FROM python:3.10-slim

# Install system dependencies for Scapy
RUN apt-get update && apt-get install -y \\
    tcpdump \\
    libpcap-dev \\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Initialize database
RUN python init_db.py

EXPOSE 5000

# Run with network capabilities
CMD ["python", "run.py"]