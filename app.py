from flask import Flask, render_template, request, jsonify, send_from_directory
import subprocess
import os
import platform
import sys
import signal
import psutil

app = Flask(__name__)
LOG_FILE = "logs/network_traffic.log"

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        f.write("")

# Get Python executable path
PYTHON_EXECUTABLE = sys.executable
sniffer_process = None

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

@app.route("/static/<path:path>")
def serve_static(path):
    return send_from_directory("static", path)

@app.route("/status", methods=["GET"])
def check_status():
    global sniffer_process
    # Check if sniffer process is running
    is_running = False
    
    if sniffer_process is not None:
        try:
            process = psutil.Process(sniffer_process.pid)
            is_running = process.is_running()
        except (psutil.NoSuchProcess, AttributeError):
            is_running = False
    
    return jsonify({"status": "running" if is_running else "stopped"})

@app.route("/start_sniffer", methods=["POST"])
def start_sniffer():
    global sniffer_process
    
    try:
        # Kill any existing process first
        if sniffer_process is not None:
            try:
                if platform.system() == "Windows":
                    sniffer_process.terminate()
                else:
                    os.killpg(os.getpgid(sniffer_process.pid), signal.SIGTERM)
            except:
                pass
        
        # Start a new process
        if platform.system() == "Windows":
            sniffer_process = subprocess.Popen(
                [PYTHON_EXECUTABLE, "script.py"],
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
        elif platform.system() == "Linux":
            sniffer_process = subprocess.Popen(
                [PYTHON_EXECUTABLE, "script.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
        elif platform.system() == "Darwin":  # macOS
            sniffer_process = subprocess.Popen(
                [PYTHON_EXECUTABLE, "script.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
        else:
            return jsonify({"status": "error", "message": "Unsupported OS"})

        return jsonify({"status": "success", "message": "Packet sniffer started successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/stop_sniffer", methods=["POST"])
def stop_sniffer():
    global sniffer_process
    
    try:
        if sniffer_process is not None:
            if platform.system() == "Windows":
                sniffer_process.terminate()
            else:
                os.killpg(os.getpgid(sniffer_process.pid), signal.SIGTERM)
            sniffer_process = None
            return jsonify({"status": "success", "message": "Packet sniffer stopped."})
        else:
            return jsonify({"status": "warning", "message": "No sniffer was running."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/run_attack", methods=["POST"])
def run_attack():
    attack_type = request.json.get("attack")
    script = SCRIPTS.get(attack_type)
    
    if script and os.path.exists(script):
        try:
            subprocess.Popen([PYTHON_EXECUTABLE, script])
            return jsonify({"status": "success", "message": f"{attack_type.upper()} simulation running."})
        except Exception as e:
            return jsonify({"status": "error", "message": f"Error executing {attack_type} script: {str(e)}"})
    return jsonify({"status": "error", "message": "Invalid attack type or script not found."})

@app.route("/logs", methods=["GET"])
def read_logs():
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                lines = f.readlines()[-500:]  # Get last 500 lines
            return jsonify({"logs": lines})
        except Exception as e:
            return jsonify({"status": "error", "message": f"Error reading logs: {str(e)}"})
    return jsonify({"logs": []})

@app.route("/clear_logs", methods=["POST"])
def clear_logs():
    try:
        with open(LOG_FILE, "w") as f:
            f.write("")
        return jsonify({"status": "success", "message": "Logs cleared successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Error clearing logs: {str(e)}"})

if __name__ == "__main__":
    app.run(debug=True)