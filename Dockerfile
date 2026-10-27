FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 iputils-ping libpcap0.8 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && python -c "from mac_vendor_lookup import MacLookup; MacLookup().update_vendors()" || true

COPY . .
ENV DB_PATH=/app/data/netmap.db
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
