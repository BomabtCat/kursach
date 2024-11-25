import paramiko
import psycopg2
from psycopg2.extras import DictCursor
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Параметры подключения к базе данных
DB_CONFIG = {
    'dbname': 'security_logs',
    'user': 'bombatcat',
    'password': 'alim_2005',
    'host': '172.21.0.2',
    'port': 5432
}

# SSH-настройки
SSH_CONFIG = {
    'hostname': '192.168.100.2',    
    'port': 22,
    'username': 'bombatcat',
    'password': 'alim_2005'
}

MAX_LOG_LENGTH = 125  # Максимальная длина строки для записи в базу данных


def execute_ssh_command(command):
    """Выполнение команды на устройстве через SSH."""
    try:
        logging.info(f"Connecting to {SSH_CONFIG['hostname']} via SSH...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=SSH_CONFIG['hostname'],
            port=SSH_CONFIG['port'],
            username=SSH_CONFIG['username'],
            password=SSH_CONFIG['password']
        )
        logging.info(f"Executing command: {command}")
        full_command = f"echo {SSH_CONFIG['password']} | sudo -S {command}"
        stdin, stdout, stderr = client.exec_command(full_command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        client.close()

        if error:
            logging.error(f"SSH Error: {error}")
        else:
            logging.info(f"SSH Output: {output}")
        return output
    except Exception as e:
        logging.error(f"SSH Connection failed: {e}")
        return None



def split_log_text(logs, max_length=MAX_LOG_LENGTH):
    """Разделение текста логов на части."""
    parts = []
    while len(logs) > max_length:
        split_point = logs.rfind(' ', 0, max_length)
        if split_point == -1:  # Если нет пробела, обрезаем на max_length
            split_point = max_length
        parts.append(logs[:split_point])
        logs = logs[split_point:].lstrip()  # Убираем пробелы в начале
    parts.append(logs)  # Добавляем оставшуюся часть
    return parts


def analyze_log_part(log_part):
    """Анализ части лога для определения длины и типа."""
    log_length = len(log_part)
    if "ALERT" in log_part:
        log_type = "ALERT"
    elif "INFO" in log_part:
        log_type = "INFO"
    elif "ERROR" in log_part:
        log_type = "ERROR"
    else:
        log_type = "UNKNOWN"
    return log_length, log_type


def save_logs_to_db(logs):
    """Сохранение логов в базу данных."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()

        log_parts = split_log_text(logs)
        for part in log_parts:
            log_length, log_type = analyze_log_part(part)
            logging.info(f"Attempting to save log part: {part}, Length: {log_length}, Type: {log_type}")
            cursor.execute(
                "INSERT INTO logs (log_text, timestamp, log_length, log_type) VALUES (%s, CURRENT_TIMESTAMP, %s, %s)",
                (part, log_length, log_type)
            )
        conn.commit()
        logging.info("Logs saved to database successfully.")

    except psycopg2.DatabaseError as e:
        logging.error(f"Database error: {e}")
        conn.rollback()  # Откат изменений в случае ошибки

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()



def collect_suricata_logs():
    """Сбор логов Suricata."""
    try:
        logging.info("Collecting Suricata logs...")
        logs = execute_ssh_command("sudo cat /var/log/suricata/fast.log")
        if logs:
            logging.info(f"Collected Suricata logs: {logs[:100]}")
            save_logs_to_db(logs)
        else:
            logging.warning("No logs collected from Suricata.")
    except Exception as e:
        logging.error(f"Failed to collect Suricata logs: {e}")


if __name__ == "__main__":
    collect_suricata_logs()
