FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY attacks ./attacks
COPY run_range.py ./

ENV PYTHONPATH=/app/src
ENV AEVP_RUNTIME=/app/_runtime

# Default: run the oracle-validated campaign.
CMD ["python", "run_range.py", "--n", "5"]
