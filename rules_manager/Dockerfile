FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY rules_manager.py .

CMD ["python", "rules_manager.py"]
