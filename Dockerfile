FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY pyproject.toml .
COPY src ./src
RUN pip install --no-cache-dir .

EXPOSE 8791
CMD ["uvicorn", "cyber_sentinel.app:app", "--host", "0.0.0.0", "--port", "8791"]
