# Start from the latest Python image
FROM python:latest

# Install required Python packages
RUN pip install --no-cache-dir paramiko boto3

# Prepare application directory
RUN mkdir -p /app
WORKDIR /app

# Default to interactive Bash shell
CMD ["/bin/bash"]
