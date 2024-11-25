# Dockerfile для logs_collector
FROM python:3.10-slim

WORKDIR /app

# Устанавливаем зависимости
RUN pip install paramiko psycopg2-binary

# Копируем скрипт в контейнер
COPY log_collector.py .

# Устанавливаем точку входа
CMD ["python", "log_collector.py"]
