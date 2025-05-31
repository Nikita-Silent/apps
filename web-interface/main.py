from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_session import Session
import cups
import os
import logging
from dotenv import load_dotenv
from datetime import datetime

# Загружаем переменные из .env
load_dotenv()

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
        cups.setUser(username)
        conn = cups.Connection(host=CUPS_SERVER, port=CUPS_PORT)
        logger.info(f"Connected to CUPS server at {CUPS_SERVER}:{CUPS_PORT} as {username}")
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

def get_printer_health(attrs):
    """Определяет состояние принтера на основе printer-state и printer-state-reasons."""
    state = attrs.get("printer-state", 3)
    reasons = attrs.get("printer-state-reasons", ["none"])
    state_map = {3: "Idle", 4: "Printing", 5: "Stopped"}
    state_text = state_map.get(state, "Unknown")
    
    if state == 3 and "none" in reasons:
        return {"status": "Healthy", "badge": "badge-success", "details": "Idle"}
    elif state == 4:
        return {"status": "Active", "badge": "badge-warning", "details": "Printing"}
    else:
        details = ", ".join([r for r in reasons if r != "none"]) or "Error"
        return {"status": "Error", "badge": "badge-danger", "details": details}

@app.route("/")
def index():
    if 'username' in session and 'password' in session:
        logger.info("User already logged in, redirecting to dashboard")
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route("/login", methods=["GET", "POST"])
def login():
    if 'username' in session and 'password' in session:
        logger.info("User already logged in, redirecting to dashboard")
        return redirect(url_for('dashboard'))
    
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
            return redirect(url_for('dashboard'))
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

@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_connection(session['username'], session['password'])
    if not conn:
        return render_template("dashboard.html", error="Cannot connect to CUPS server", printer_count=0, active_printers=0, error_printers=0, completed_jobs=[], server_ip=CUPS_SERVER)
    
    try:
        # Количество принтеров/классов
        printers = conn.getPrinters()
        printer_count = len(printers)
        active_printers = 0
        error_printers = 0
        for attrs in printers.values():
            health = get_printer_health(attrs)
            if health["status"] == "Active":
                active_printers += 1
            elif health["status"] == "Error":
                error_printers += 1
        
        # Завершённые задания
        requested_attributes = [
            "job-id", "job-name", "job-printer-name", "job-originating-user-name",
            "job-state", "job-k-octets", "time-at-creation", "job-printer-uri",
            "destination"
        ]
        jobs = conn.getJobs(which_jobs="all", requested_attributes=requested_attributes)
        logger.debug(f"Dashboard raw jobs: {jobs}")
        job_states = {
            3: ("Pending", "badge-warning"),
            4: ("Held", "badge-warning"),
            5: ("Processing", "badge-warning"),
            6: ("Stopped", "badge-danger"),
            7: ("Canceled", "badge-danger"),
            8: ("Aborted", "badge-danger"),
            9: ("Completed", "badge-success")
        }
        completed_jobs = []
        for job_id, attrs in jobs.items():
            logger.debug(f"Dashboard job {job_id} attributes: {attrs}")
            if attrs.get("job-state", 0) == 9:  # Completed
                state_text, badge_class = job_states.get(9)
                # Извлекаем имя принтера из job-printer-uri или destination
                printer_name = attrs.get("job-printer-name", "Unknown")
                if printer_name == "Unknown" and attrs.get("job-printer-uri"):
                    uri_parts = attrs.get("job-printer-uri", "").split("/")
                    if len(uri_parts) > 3:
                        printer_name = uri_parts[-1] or "Unknown"
                elif printer_name == "Unknown" and attrs.get("destination"):
                    printer_name = attrs.get("destination", "Unknown")
                
                completed_jobs.append({
                    "id": job_id,
                    "name": attrs.get("job-name", f"Job {job_id}"),
                    "printer": printer_name,
                    "user": attrs.get("job-originating-user-name", "Unknown"),
                    "state": state_text,
                    "badge_class": badge_class,
                    "size": attrs.get("job-k-octets", 0),
                    "time": datetime.fromtimestamp(
                        attrs.get("time-at-creation", 0)
                    ).strftime("%Y-%m-%d %H:%M:%S") if attrs.get("time-at-creation", 0) > 0 else "Unknown"
                })
        completed_jobs = sorted(completed_jobs, key=lambda x: x["id"], reverse=True)[:10]  # Последние 10
        
        logger.info(f"Dashboard loaded: {printer_count} printers, {active_printers} active, {error_printers} error, {len(completed_jobs)} completed jobs")
        return render_template("dashboard.html", printer_count=printer_count, active_printers=active_printers, error_printers=error_printers, completed_jobs=completed_jobs, server_ip=CUPS_SERVER)
    except Exception as e:
        logger.error(f"Error loading dashboard: {e}")
        return render_template("dashboard.html", error=str(e), printer_count=0, active_printers=0, error_printers=0, completed_jobs=[], server_ip=CUPS_SERVER)

@app.route("/printers")
@login_required
def printers():
    conn = get_connection(session['username'], session['password'])
    if not conn:
        return render_template("printers.html", printers=[], error="Cannot connect to CUPS server")
    
    try:
        printers = conn.getPrinters()
        classes = conn.getClasses()
        printer_list = [
            {
                "name": name,
                "uri": attrs.get("device-uri", ""),
                "state": attrs.get("printer-state-message", ""),
                "type": "class" if name in classes else "printer",
                "health": get_printer_health(attrs)
            }
            for name, attrs in printers.items()
        ]
        logger.info(f"Retrieved {len(printer_list)} printers/classes")
        return render_template("printers.html", printers=printer_list)
    except Exception as e:
        logger.error(f"Error getting printers: {e}")
        return render_template("printers.html", printers=[], error=str(e))

@app.route("/jobs")
@login_required
def jobs():
    conn = get_connection(session['username'], session['password'])
    if not conn:
        logger.error("Cannot connect to CUPS server")
        return render_template("jobs.html", jobs=[], error="Cannot connect to CUPS server")
    
    try:
        filter_type = request.args.get("filter", "all")
        requested_attributes = [
            "job-id", "job-name", "job-printer-name", "job-originating-user-name",
            "job-state", "job-k-octets", "time-at-creation", "job-printer-uri",
            "destination"
        ]
        jobs = conn.getJobs(which_jobs="all", requested_attributes=requested_attributes)
        logger.debug(f"Raw jobs: {jobs}")
        job_list = []
        job_states = {
            3: ("Pending", "badge-warning"),
            4: ("Held", "badge-warning"),
            5: ("Processing", "badge-warning"),
            6: ("Stopped", "badge-danger"),
            7: ("Canceled", "badge-danger"),
            8: ("Aborted", "badge-danger"),
            9: ("Completed", "badge-success")
        }
        
        for job_id, attrs in jobs.items():
            logger.debug(f"Job {job_id} attributes: {attrs}")
            state = attrs.get("job-state", 0)
            if filter_type == "active" and state not in [3, 4, 5]:
                continue
            if filter_type == "completed" and state != 9:
                continue
            state_text, badge_class = job_states.get(state, ("Unknown", "badge-danger"))
            # Извлекаем имя принтера из job-printer-uri или destination
            printer_name = attrs.get("job-printer-name", "Unknown")
            if printer_name == "Unknown" and attrs.get("job-printer-uri"):
                uri_parts = attrs.get("job-printer-uri", "").split("/")
                if len(uri_parts) > 3:
                    printer_name = uri_parts[-1] or "Unknown"
            elif printer_name == "Unknown" and attrs.get("destination"):
                printer_name = attrs.get("destination", "Unknown")
            
            job_list.append({
                "id": job_id,
                "name": attrs.get("job-name", f"Job {job_id}"),
                "printer": printer_name,
                "user": attrs.get("job-originating-user-name", "Unknown"),
                "state": state_text,
                "badge_class": badge_class,
                "size": attrs.get("job-k-octets", 0),
                "time": datetime.fromtimestamp(
                    attrs.get("time-at-creation", 0)
                ).strftime("%Y-%m-%d %H:%M:%S") if attrs.get("time-at-creation", 0) > 0 else "Unknown"
            })
        job_list = sorted(job_list, key=lambda x: x["id"], reverse=True)[:50]  # Ограничим 50 заданиями
        logger.info(f"Retrieved {len(job_list)} print jobs (filter: {filter_type})")
        return render_template("jobs.html", jobs=job_list, filter=filter_type)
    except Exception as e:
        logger.error(f"Error getting jobs: {e}")
        return render_template("jobs.html", jobs=[], error=f"Error retrieving jobs: {str(e)}", filter=filter_type)

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
            "members": classes.get(name, []) if is_class else [],
            "state": attrs.get("printer-state-message", "Unknown"),
            "health": get_printer_health(attrs)
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
                conn.deletePrinter(name)
                conn.addPrinter(new_name, info=description, location=location)
                for member in members:
                    conn.addPrinterToClass(member, new_name)
            else:
                uri = f"{protocol}://{address}" if protocol != "socket" else f"socket://{address}"
                logger.debug(f"Modifying printer {name} to {new_name} with URI {uri}")
                conn.deletePrinter(name)
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