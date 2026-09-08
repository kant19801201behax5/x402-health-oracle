FROM python:3.12-slim

WORKDIR /app

COPY gateway/requirements.txt gateway/requirements.txt
COPY probe/requirements.txt probe/requirements.txt
RUN pip install --no-cache-dir -r gateway/requirements.txt -r probe/requirements.txt

COPY gateway/ gateway/
COPY probe/ probe/

RUN mkdir -p /opt/phoenix_zero/data

ENV PYTHONPATH=/app/gateway:/app/probe

EXPOSE 3002 8765 8766

CMD ["uvicorn", "gateway.x402_gateway:app", "--host", "0.0.0.0", "--port", "3002"]
