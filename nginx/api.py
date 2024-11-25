from flask import Flask, jsonify
from script1 import collect_suricata_logs  # Импорт функций из первого скрипта
from script2 import add_suricata_rule, update_suricata_rules  # Импорт из второго

app = Flask(__name__)

@app.route('/logs', methods=['GET'])
def get_logs():
    """Маршрут для сбора логов Suricata."""
    collect_suricata_logs()
    return jsonify({"status": "Logs collected and saved to database."})

@app.route('/rules', methods=['POST'])
def update_rules():
    """Маршрут для обновления правил."""
    new_rule = 'alert tcp any any -> any 80 (msg:"Dynamic rule"; sid:100002; rev:1;)'
    add_suricata_rule(new_rule)
    update_suricata_rules()
    return jsonify({"status": "Rules updated and Suricata restarted."})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)  # Запускает сервер на порту 5000
