# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
# --no-cache-dir reduces image size
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container at /app
COPY . .

# Make port 8080 available to the world outside this container
# Cloud Run uses the PORT environment variable, typically 8080
EXPOSE 8080

# Define environment variable for the port Cloud Run expects
ENV PORT=8080
ENV PYTHONUNBUFFERED=TRUE

# Run app.py when the container launches using Streamlit
# Listen on 0.0.0.0 and the port specified by Cloud Run ($PORT)
# --server.headless=true is recommended for containerized environments
CMD ["streamlit", "run", "app.py", "--server.port", "$PORT", "--server.address", "0.0.0.0", "--server.headless", "true"]
