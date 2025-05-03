from flask import Flask, render_template, request, jsonify
import subprocess
import os
import platform

app = Flask(__name__)
LOG_FILE = "logs/network_traffic.log"

# Path to python and scripts
PYTHON_EXECUTABLE = r"C:\Python312\python.exe"
SCRIPT_PATH = "script.py"

SCRIPTS = {
    "phishing": "scripts/phishing.py",
    "sql": "scripts/sql.py",
    "scan": "scripts/scan.py",
    "tcp": "scripts/tcp.py",
    "udp": "scripts/udp.py",
    "ddos": "scripts/ddos.py"
}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/start_sniffer", methods=["POST"])
def start_sniffer():
    try:
        system = platform.system()

        if system == "Windows":
            subprocess.Popen(
                ["start", "cmd", "/k", PYTHON_EXECUTABLE, SCRIPT_PATH],
                shell=True
            )
        elif system == "Linux":
            subprocess.Popen(
                ["gnome-terminal", "--", PYTHON_EXECUTABLE, SCRIPT_PATH]
            )
        elif system == "Darwin":  # macOS
            subprocess.Popen(
                ["osascript", "-e", f'tell app "Terminal" to do script "{PYTHON_EXECUTABLE} {SCRIPT_PATH}"']
            )
        else:
            return jsonify({"status": "error", "message": "Unsupported OS"})

        return jsonify({"status": "success", "message": "Sniffer started in a new terminal."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/run_attack", methods=["POST"])
def run_attack():
    attack_type = request.json.get("attack")
    script = SCRIPTS.get(attack_type)
    if script and os.path.exists(script):
        subprocess.Popen([PYTHON_EXECUTABLE, script])
        return jsonify({"status": "success", "message": f"{attack_type} script running."})
    return jsonify({"status": "error", "message": "Invalid attack type or script not found."})

@app.route("/logs", methods=["GET"])
def read_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()[-500:]
        return jsonify({"logs": lines})
    return jsonify({"logs": []})

if __name__ == "__main__":
    app.run(debug=True)

