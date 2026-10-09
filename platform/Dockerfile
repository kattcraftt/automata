FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y cmake gcc g++ zlib1g-dev liblzma-dev make
WORKDIR /build
# We'd copy engine source here to build, left as stub for now

FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
