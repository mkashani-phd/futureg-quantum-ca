# Dockerfile
FROM python:3.10-slim

# Install build tools and dependencies needed for your PQC libraries
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Set the working directory
WORKDIR /app

# Copy all files & directories from current dir to /app
COPY . /app

# Default command to run your handshake script
CMD ["python", "full_handshake.py"]
