FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY . .
CMD cd /app && uvicorn src.main:app --host 0.0.0.0 --port 8080