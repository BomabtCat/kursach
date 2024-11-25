import logging
import paramiko
import os

# Логирование
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# SSH-настройки
SSH_CONFIG = {
    'hostname': '10.192.209.149',
    'port': 22,
    'username': 'bombatcat',
    'password': os.getenv('SSH_PASSWORD', 'default_password')  # Лучше заменить на реальный секрет
}


def execute_ssh_command(command):
    """Выполнение команды на устройстве через SSH."""
    try:
        logging.info(f"Подключение к {SSH_CONFIG['hostname']} через SSH...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=SSH_CONFIG['hostname'],
            port=SSH_CONFIG['port'],
            username=SSH_CONFIG['username'],
            password=SSH_CONFIG['password']
        )
        logging.info(f"Выполнение команды: {command}")
        full_command = f"echo {SSH_CONFIG['password']} | sudo -S {command}"
        stdin, stdout, stderr = client.exec_command(full_command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        client.close()

        if error:
            logging.error(f"Ошибка выполнения команды: {error}")
        else:
            logging.info(f"Результат выполнения: {output}")
        return output
    except paramiko.AuthenticationException:
        logging.error("Ошибка аутентификации SSH. Проверьте имя пользователя или пароль.")
        return None
    except paramiko.SSHException as e:
        logging.error(f"Ошибка подключения SSH: {e}")
        return None
    except Exception as e:
        logging.error(f"Неизвестная ошибка SSH: {e}")
        return None


def add_suricata_rule(rule):
    """Добавление пользовательского правила Suricata."""
    command = f'echo "{rule}" | sudo tee -a /etc/suricata/rules/local.rules > /dev/null'
    execute_ssh_command(command)
    logging.info(f"Правило добавлено: {rule}")


def restart_suricata():
    """Перезапуск Suricata вручную."""
    logging.info("Завершение текущего процесса Suricata...")
    execute_ssh_command("sudo pkill suricata")
    
    logging.info("Запуск Suricata с новыми параметрами...")
    command = "sudo suricata -i eth0 --runmode=workers"
    execute_ssh_command(f"nohup {command} > /var/log/suricata/nohup.out 2>&1 &")
    logging.info("Suricata успешно перезапущена.")


def update_suricata_rules():
    """Обновление правил Suricata и ручной перезапуск."""
    logging.info("Обновление правил Suricata...")
    update_result = execute_ssh_command("sudo suricata-update")
    if update_result is None:
        logging.error("Ошибка при обновлении правил.")
        return

    restart_suricata()


if __name__ == "__main__":
    # Пример добавления нового правила
    new_rule = 'alert tcp any any -> any 80 (msg:"Test rule"; sid:100001; rev:1;)'
    add_suricata_rule(new_rule)
    update_suricata_rules()
