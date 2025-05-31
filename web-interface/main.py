from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_session import Session
import cups
import os
import logging

app = Flask(__name__)

# Настройка сессий
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Настройка логирования
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Настройки CUPS
CUPS_SERVER = os.getenv("CUPS_SERVER", "localhost")
CUPS_PORT = int(os.getenv("CUPS_PORT", "631"))

def get_connection(username, password):
    """Создаёт соединение с CUPS с указанными учетными данными."""
    try:
        def password_cb(prompt):
            return password
        cups.setPasswordCB(password_cb)
        cups.setUser(username)  # Устанавливаем имя пользователя
        conn = cups.Connection(host=CUPS_SERVER, port=CUPS_PORT)
        logger.info(f"Connected to CUPS server as {username}")
        return conn
    except Exception as e:
        logger.error(f"Failed to connect to CUPS: {e}")
        return None

def is_printer_class(conn, name):
    """Проверяет, является ли объект классом."""
    try:
        classes = conn.getClasses()
        return name in classes
    except Exception as e:
        logger.error(f"Error checking class {name}: {e}")
        return False

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if not all([username, password]):
            return render_template("login.html", error="Missing username or password")
        
        conn = get_connection(username, password)
        if conn:
            session['username'] = username
            session['password'] = password
            logger.info(f"User {username} logged in")
            return redirect(url_for('index'))
        else:
            logger.warning(f"Invalid login attempt for {username}")
            return render_template("login.html", error="Invalid username or password")
    
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop('username', None)
    session.pop('password', None)
    logger.info("User logged out")
    return redirect(url_for('login'))

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'username' not in session or 'password' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route("/")
@login_required
def index():
    conn = get_connection(session['username'], session['password'])
    if not conn:
        return render_template("index.html", printers=[], error="Cannot connect to CUPS server")
    
    try:
        printers = conn.getPrinters()
        classes = conn.getClasses()
        printer_list = [
            {
                "name": name,
                "uri": attrs.get("device-uri", ""),
                "state": attrs.get("printer-state-message", ""),
                "type": "class" if name in classes else "printer"
            }
            for name, attrs in printers.items()
        ]
        logger.info(f"Retrieved {len(printer_list)} printers/classes")
        return render_template("index.html", printers=printer_list)
    except Exception as e:
        logger.error(f"Error getting printers: {e}")
        return render_template("index.html", printers=[], error=str(e))

@app.route("/printer-detail/<name>")
@login_required
def printer_detail(name):
    conn = get_connection(session['username'], session['password'])
    if not conn:
        return render_template("printer.html", error="Cannot connect to CUPS server")
    
    try:
        printers = conn.getPrinters()
        classes = conn.getClasses()
        is_class = name in classes
        
        if name not in printers and not is_class:
            logger.warning(f"Object {name} not found")
            return render_template("printer.html", error=f"Object {name} not found")
        
        attrs = printers.get(name, {})
        ip = ""
        if attrs.get('device-uri'):
            parts = attrs["device-uri"].split("/")
            if len(parts) > 2:
                ip = parts[2].split(":")[0]
        
        printer = {
            "name": name,
            "type": "class" if is_class else "printer",
            "description": attrs.get("printer-info", attrs.get("printer-state-message", "")),
            "location": attrs.get("printer-location", ""),
            "driver": attrs.get("printer-make-and-model", ""),
            "connection": f"ipp://{ip}/ipp" if ip else attrs.get("device-uri", ""),
            "defaults": "",
            "members": classes.get(name, []) if is_class else []
        }
        
        options = conn.getPrinterAttributes(name) if not is_class else {}
        defaults = []
        for key, value in options.items():
            if key.startswith("job-") or key in ["media", "sides"]:
                defaults.append(f"{key}={value}")
        printer["defaults"] = ", ".join(defaults) if defaults else "none"
        
        logger.info(f"Retrieved details for {printer['type']} {name}")
        return render_template("printer.html", printer=printer)
    except Exception as e:
        logger.error(f"Error getting details: {e}")
        return render_template("printer.html", error=str(e))

@app.route("/add-printer", methods=["GET", "POST"])
@login_required
def add_printer():
    conn = get_connection(session['username'], session['password'])
    if not conn:
        return render_template("add_printer.html", error="Cannot connect to CUPS server", printers=[])
    
    try:
        printers = conn.getPrinters()
        printer_names = list(printers.keys())
    except Exception as e:
        logger.error(f"Error getting printers for add-printer: {e}")
        printer_names = []
    
    if request.method == "POST":
        name = request.form.get("name")
        is_class = request.form.get("is_class") == "true"
        protocol = request.form.get("protocol") if not is_class else None
        address = request.form.get("address") if not is_class else None
        description = request.form.get("description", "")
        location = request.form.get("location", "")
        members = request.form.getlist("members") if is_class else []
        
        if not name:
            return jsonify({"error": "Name is required"}), 400
        if not is_class and not all([protocol, address]):
            return jsonify({"error": "Protocol and address are required for printers"}), 400
        
        try:
            if is_class:
                logger.debug(f"Adding class {name} with members {members}")
                conn.addPrinter(name, info=description, location=location)
                for member in members:
                    conn.addPrinterToClass(member, name)
            else:
                uri = f"{protocol}://{address}" if protocol != "socket" else f"socket://{address}"
                logger.debug(f"Adding printer {name} with URI {uri}")
                conn.addPrinter(
                    name,
                    device=uri,
                    info=description,
                    location=location,
                    ppdname="everywhere"
                )
                conn.enablePrinter(name)
                conn.acceptJobs(name)
            
            logger.info(f"{'Class' if is_class else 'Printer'} {name} added successfully")
            return jsonify({"message": f"{'Class' if is_class else 'Printer'} {name} added"}), 200
        except cups.IPPError as e:
            logger.error(f"IPP Error adding {'class' if is_class else 'printer'}: {e}")
            return jsonify({"error": f"IPP Error: {e}"}), 500
        except Exception as e:
            logger.error(f"Error adding {'class' if is_class else 'printer'}: {e}")
            return jsonify({"error": str(e)}), 500
    
    return render_template("add_printer.html", printers=printer_names)

@app.route("/modify-printer/<name>", methods=["GET", "POST"])
@login_required
def modify_printer(name):
    conn = get_connection(session['username'], session['password'])
    if not conn:
        return render_template("modify_printer.html", error="Cannot connect to CUPS server", printer=None, printers=[])
    
    try:
        printers = conn.getPrinters()
        classes = conn.getClasses()
        is_class = name in classes
        printer_names = list(printers.keys())
        
        if name not in printers and not is_class:
            logger.warning(f"Object {name} not found")
            return render_template("modify_printer.html", error=f"Object {name} not found", printer=None, printers=printer_names)
        
        attrs = printers.get(name, {})
        printer = {
            "name": name,
            "type": "class" if is_class else "printer",
            "description": attrs.get("printer-info", ""),
            "location": attrs.get("printer-location", ""),
            "connection": attrs.get("device-uri", ""),
            "members": classes.get(name, []) if is_class else []
        }
    except Exception as e:
        logger.error(f"Error getting details for modify: {e}")
        return render_template("modify_printer.html", error=str(e), printer=None, printers=printer_names)
    
    if request.method == "POST":
        new_name = request.form.get("name")
        description = request.form.get("description", "")
        location = request.form.get("location", "")
        protocol = request.form.get("protocol") if not is_class else None
        address = request.form.get("address") if not is_class else None
        members = request.form.getlist("members") if is_class else []
        
        if not new_name:
            return jsonify({"error": "Name is required"}), 400
        if not is_class and not all([protocol, address]):
            return jsonify({"error": "Protocol and address are required for printers"}), 400
        
        try:
            if is_class:
                logger.debug(f"Modifying class {name} to {new_name} with members {members}")
                # Удаляем старый класс
                conn.deletePrinter(name)
                # Создаём новый с новым именем
                conn.addPrinter(new_name, info=description, location=location)
                for member in members:
                    conn.addPrinterToClass(member, new_name)
            else:
                uri = f"{protocol}://{address}" if protocol != "socket" else f"socket://{address}"
                logger.debug(f"Modifying printer {name} to {new_name} with URI {uri}")
                # Удаляем старый принтер
                conn.deletePrinter(name)
                # Создаём новый
                conn.addPrinter(
                    new_name,
                    device=uri,
                    info=description,
                    location=location,
                    ppdname="everywhere"
                )
                conn.enablePrinter(new_name)
                conn.acceptJobs(new_name)
            
            logger.info(f"{'Class' if is_class else 'Printer'} {new_name} modified successfully")
            return jsonify({"message": f"{'Class' if is_class else 'Printer'} {new_name} modified"}), 200
        except cups.IPPError as e:
            logger.error(f"IPP Error modifying {'class' if is_class else 'printer'}: {e}")
            return jsonify({"error": f"IPP Error: {e}"}), 500
        except Exception as e:
            logger.error(f"Error modifying {'class' if is_class else 'printer'}: {e}")
            return jsonify({"error": str(e)}), 500
    
    return render_template("modify_printer.html", printer=printer, printers=printer_names)

@app.route("/printers/<name>/pause", methods=["POST"])
@login_required
def pause_printer(name):
    conn = get_connection(session['username'], session['password'])
    if not conn:
        return jsonify({"error": "Cannot connect to CUPS server"}), 500
    
    try:
        conn.disablePrinter(name)
        logger.info(f"Printer/class {name} paused")
        return jsonify({"message": f"Printer/class {name} paused"}), 200
    except cups.IPPError as e:
        logger.error(f"IPP Error pausing {name}: {e}")
        return jsonify({"error": f"IPP Error: {e}"}), 500
    except Exception as e:
        logger.error(f"Error pausing {name}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/printers/<name>/resume", methods=["POST"])
@login_required
def resume_printer(name):
    conn = get_connection(session['username'], session['password'])
    if not conn:
        return jsonify({"error": "Cannot connect to CUPS server"}), 500
    
    try:
        conn.enablePrinter(name)
        conn.acceptJobs(name)
        logger.info(f"Printer/class {name} resumed")
        return jsonify({"message": f"Printer/class {name} resumed"}), 200
    except cups.IPPError as e:
        logger.error(f"IPP Error resuming {name}: {e}")
        return jsonify({"error": f"IPP Error: {e}"}), 500
    except Exception as e:
        logger.error(f"Error resuming {name}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/printers/<name>/delete", methods=["POST"])
@login_required
def delete_printer(name):
    conn = get_connection(session['username'], session['password'])
    if not conn:
        return jsonify({"error": "Cannot connect to CUPS server"}), 500
    
    try:
        is_class = is_printer_class(conn, name)
        conn.deletePrinter(name)
        
        # Проверяем удаление
        target = conn.getClasses() if is_class else conn.getPrinters()
        if name not in target:
            logger.info(f"{'Class' if is_class else 'Printer'} {name} deleted successfully")
            return jsonify({"message": f"{'Class' if is_class else 'Printer'} {name} deleted"}), 200
        else:
            logger.error(f"Failed to delete {'class' if is_class else 'printer'} {name}")
            return jsonify({"error": f"Failed to delete {'class' if is_class else 'printer'} {name}"}), 500
    except cups.IPPError as e:
        logger.error(f"IPP Error deleting {name}: {e}")
        return jsonify({"error": f"IPP Error: {e}"}), 500
    except Exception as e:
        logger.error(f"Error deleting {name}: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)