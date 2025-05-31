from flask import Flask, render_template, request, jsonify
import cups
import os
import logging

app = Flask(__name__)

# Настройка логирования
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Настройки CUPS
CUPS_SERVER = os.getenv("CUPS_SERVER", "localhost:631")
CUPS_ADMIN = os.getenv("CUPS_ADMIN", "admin")
CUPS_ADMIN_PASS = os.getenv("CUPS_ADMIN_PASS", "admin")
# CUPS_ADMIN_PASS не используется напрямую, но сохраняем для возможной настройки

# Устанавливаем пользователя для CUPS
os.environ["CUPS_USER"] = CUPS_ADMIN
os.environ["CUPS_ADMIN_PASS"] = CUPS_ADMIN_PASS

# Подключение к CUPS
try:
    conn = cups.Connection(host=CUPS_SERVER.split(":")[0], port=int(CUPS_SERVER.split(":")[1]) if ":" in CUPS_SERVER else 631)
    logger.info("Connected to CUPS server")
except Exception as e:
    logger.error(f"Failed to connect to CUPS: {e}")
    conn = None

@app.route("/")
def index():
    if not conn:
        return render_template("index.html", printers=[], error="Cannot connect to CUPS server")
    
    try:
        printers = conn.getPrinters()
        printer_list = [
            {
                "name": name,
                "uri": attrs.get("device-uri", ""),
                "state": attrs.get("printer-state-message", ""),
            }
            for name, attrs in printers.items()
        ]
        logger.info(f"Retrieved {len(printer_list)} printers")
        return render_template("index.html", printers=printer_list)
    except Exception as e:
        logger.error(f"Error getting printers: {e}")
        return render_template("index.html", printers=[], error=str(e))

@app.route("/printer-detail/<name>")
def printer_detail(name):
    if not conn:
        return render_template("printer.html", error="Cannot connect to CUPS server")
    
    try:
        printers = conn.getPrinters()
        if name not in printers:
            logger.warning(f"Printer {name} not found")
            return render_template("printer.html", error=f"Printer {name} not found")
        
        attrs = printers[name]
        # Извлекаем IP из device-uri
        ip = ""
        if attrs.get("device-uri"):
            parts = attrs["device-uri"].split("/")
            if len(parts) > 2:
                ip = parts[2].split(":")[0]
        
        printer = {
            "name": name,
            "description": attrs.get("printer-info", attrs.get("printer-state-message", "")),
            "location": attrs.get("printer-location", ""),
            "driver": attrs.get("printer-make-and-model", ""),
            "connection": f"ipp://{ip}/ipp" if ip else attrs.get("device-uri", ""),
            "defaults": "",
        }
        
        # Получаем параметры по умолчанию
        options = conn.getPrinterAttributes(name)
        defaults = []
        for key, value in options.items():
            if key.startswith("job-") or key in ["media", "sides"]:
                defaults.append(f"{key}={value}")
        printer["defaults"] = ", ".join(defaults) if defaults else "none"
        
        logger.info(f"Retrieved details for printer {name}")
        return render_template("printer.html", printer=printer)
    except Exception as e:
        logger.error(f"Error getting printer details: {e}")
        return render_template("printer.html", error=str(e))

@app.route("/add-printer", methods=["GET", "POST"])
def add_printer():
    if request.method == "POST":
        name = request.form.get("name")
        protocol = request.form.get("protocol")
        address = request.form.get("address")
        
        if not all([name, protocol, address]):
            logger.warning("Missing required fields in add-printer request")
            return jsonify({"error": "Missing required fields"}), 400
        
        # Формируем URI
        uri = f"{protocol}://{address}" if protocol != "socket" else f"socket://{address}"
        
        try:
            # Добавляем принтер
            conn.addPrinter(
                name=name,
                device=uri,
                ppdname="everywhere",
                info=name,
                location="",
                enabled=True
            )
            conn.acceptJobs(name)
            conn.enablePrinter(name)
            logger.info(f"Printer {name} added successfully")
            return jsonify({"message": f"Printer {name} added"}), 200
        except Exception as e:
            logger.error(f"Error adding printer: {e}")
            return jsonify({"error": str(e)}), 500
    
    return render_template("add_printer.html")

@app.route("/printers/<name>/pause", methods=["POST"])
def pause_printer(name):
    try:
        conn.disablePrinter(name)
        logger.info(f"Printer {name} paused successfully")
        return jsonify({"message": f"Printer {name} paused"}), 200
    except Exception as e:
        logger.error(f"Error pausing printer: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/printers/<name>/resume", methods=["POST"])
def resume_printer(name):
    try:
        conn.enablePrinter(name)
        conn.acceptJobs(name)
        logger.info(f"Printer {name} resumed successfully")
        return jsonify({"message": f"Printer {name} resumed"}), 200
    except Exception as e:
        logger.error(f"Error resuming printer: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/printers/<name>/delete", methods=["POST"])
def delete_printer(name):
    try:
        conn.deletePrinter(name)
        logger.info(f"Printer {name} deleted successfully")
        return jsonify({"message": f"Printer {name} deleted"}), 200
    except Exception as e:
        logger.error(f"Error deleting printer: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)