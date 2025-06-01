from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import cups
import socket
import re
import logging
import os
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

CUPS_SERVER = os.getenv("CUPS_SERVER", "localhost")
CUPS_PORT = int(os.getenv("CUPS_PORT", "631"))
ALLOWED_USER = os.getenv("CUPS_ADMIN_USER")
ALLOWED_PASSWORD = os.getenv("CUPS_ADMIN_PASSWORD")
SECRET_KEY = os.getenv("SECRET_KEY", "default_insecure_key")

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = SECRET_KEY

def get_connection(username, password):
    try:
        def password_cb(prompt):
            logger.debug(f"CUPS запросил пароль для {username}")
            return password
        cups.setPasswordCB(password_cb)
        cups.setUser(username)
        conn = cups.Connection(host=CUPS_SERVER, port=CUPS_PORT)
        conn.getPrinters()
        logger.info(f"Подключено к серверу CUPS на {CUPS_SERVER}:{CUPS_PORT} как {username}")
        return conn
    except Exception as e:
        logger.error(f"Ошибка подключения к CUPS для {username}: {str(e)}")
        return None

def get_cups_server_ip():
    try:
        server_ip = socket.gethostbyname(CUPS_SERVER)
        logger.debug(f"Сервер CUPS {CUPS_SERVER} разрешён в IP: {server_ip}")
        return server_ip
    except socket.gaierror:
        logger.error(f"Не удалось разрешить IP сервера CUPS для {CUPS_SERVER}")
        return "Неизвестно"

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        logger.debug(f"Проверка сессии: username={session.get('username')}")
        if 'username' not in session:
            logger.warning(f"Несанкционированный доступ к {request.path}")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def create_cups_connection():
    try:
        username = session.get('username')
        password = session.get('password')
        logger.debug(f"Содержимое сессии: username={username}, password={'*' * len(password) if password else None}")
        if not username or not password:
            logger.error("Нет учетных данных в сессии")
            raise ValueError("Нет учетных данных в сессии")
        logger.debug(f"Создание подключения к CUPS для {username}")
        conn = get_connection(username, password)
        if conn is None:
            raise RuntimeError("Не удалось создать подключение к CUPS")
        return conn
    except Exception as e:
        logger.error(f"Ошибка подключения к CUPS: {str(e)}")
        raise

def extract_printer_name(printer_uri):
    if not printer_uri:
        return 'Неизвестно'
    match = re.search(r'/printers/([^/]+)', printer_uri)
    return match.group(1) if match else 'Неизвестно'

@app.route('/')
def index():
    logger.debug(f"Доступ к индексу, сессия: {session.get('username')}")
    if 'username' in session:
        return redirect(url_for('printers'))  # Перенаправляем на /printers вместо dashboard
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        logger.info(f"Пользователь {session['username']} уже аутентифицирован, перенаправление на /printers")
        return redirect(url_for('printers'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        logger.debug(f"Попытка входа: username={username}, password={'*' * len(password) if password else 'empty'}")
        if not username or not password:
            logger.warning("Пустые учетные данные при попытке входа")
            return render_template('login.html', error='Заполните все поля'), 400
        if not ALLOWED_USER or not ALLOWED_PASSWORD:
            logger.error("ALLOWED_USER или ALLOWED_PASSWORD не установлены в .env")
            return render_template('login.html', error='Сервер не настроен'), 500
        if username != ALLOWED_USER:
            logger.warning(f"Попытка входа с недопустимым пользователем: {username}")
            return render_template('login.html', error='Доступ запрещён для этого пользователя'), 401
        if password != ALLOWED_PASSWORD:
            logger.warning(f"Неверный пароль для {username}")
            return render_template('login.html', error='Неверное имя пользователя или пароль'), 401
        conn = get_connection(username, password)
        if conn is None:
            logger.warning(f"Неуспешная попытка входа для {username}")
            return render_template('login.html', error='Ошибка подключения к CUPS'), 401
        session['username'] = username
        session['password'] = password
        session.permanent = True
        logger.info(f"Успешная аутентификация для {username}, сессия: {session.get('username')}")
        return redirect(url_for('printers'))
    logger.debug("Отображение страницы входа")
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'username' in session:
        username = session.pop('username')
        session.pop('password', None)
        logger.info(f"Пользователь {username} вышел")
    return redirect(url_for('login'))

@app.route('/dashboard')
@require_auth
def dashboard():
    data = {
        'printer_count': 0,
        'active_printers': 0,
        'error_printers': 0,
        'server_ip': get_cups_server_ip(),
        'completed_jobs': [],
        'error': None
    }
    try:
        conn = create_cups_connection()
        logger.debug("Получение принтеров для дашборда")
        printers = conn.getPrinters()
        logger.debug(f"Получено {len(printers)} принтеров")
        data['printer_count'] = len(printers)
        data['active_printers'] = sum(1 for p in printers.values() if p.get('printer-state') == 3)
        data['error_printers'] = sum(1 for p in printers.values() if p.get('printer-state') == 5)
        try:
            logger.debug("Получение последних завершённых заданий")
            jobs = conn.getJobs(
                which_jobs='completed',
                my_jobs=False,
                requested_attributes=[
                    'job-id', 'job-name', 'job-state', 'job-printer-name',
                    'job-originating-user-name', 'job-k-octets', 'time-at-creation',
                    'job-state-reasons', 'job-printer-uri'
                ]
            )
            logger.debug(f"Получено {len(jobs)} завершённых заданий: {jobs}")
            completed_jobs = []
            for job_id, job_info in jobs.items():
                logger.debug(f"Задание {job_id} атрибуты: {job_info}")
                state = job_info.get('job-state', 0)
                state_text = 'Неизвестно'
                badge_class = 'badge-info'
                if state in [3, 4, 5, 6, 7, 8, 9]:
                    state_map = {
                        3: ('Ожидает', 'badge-warning'),
                        4: ('Приостановлено', ''),
                        5: ('Обрабатывается', 'badge-success'),
                        6: ('Остановлено', 'badge-danger'),
                        7: ('Отменено', ''),
                        8: ('Прервано', 'badge-danger'),
                        9: ('Завершено', 'badge-success')
                    }
                    state_text, badge_class = state_map[state]
                time_at_creation = job_info.get('time-at-creation', 0)
                time_str = 'Неизвестно'
                if time_at_creation > 0:
                    time_str = datetime.fromtimestamp(time_at_creation).strftime('%Y-%m-%d %H:%M:%S')
                printer_name = job_info.get('job-printer-name', extract_printer_name(job_info.get('job-printer-uri')))
                completed_jobs.append({
                    'id': job_id,
                    'name': job_info.get('job-name', 'Неизвестно'),
                    'printer': printer_name,
                    'user': job_info.get('job-originating-user-name', 'Неизвестно'),
                    'state': state_text,
                    'badge_class': badge_class,
                    'size': job_info.get('job-k-octets', 0),
                    'time': time_str,
                    'creation_time': time_at_creation
                })
            completed_jobs.sort(key=lambda x: x['creation_time'], reverse=True)
            data['completed_jobs'] = completed_jobs[:5]
            logger.debug(f"Подготовлено {len(data['completed_jobs'])} завершённых заданий для отображения")
        except Exception as e:
            logger.error(f"Ошибка получения заданий: {str(e)}")
            data['error'] = f"Ошибка получения заданий: {str(e)}"
        logger.info("Отображение дашборда")
        return render_template('dashboard.html', **data)
    except Exception as e:
        logger.error(f"Ошибка дашборда: {str(e)}")
        data['error'] = str(e)
        return render_template('dashboard.html', **data), 500

@app.route('/jobs')
@require_auth
def jobs():
    filter_type = request.args.get('filter', 'all')
    logger.info(f"Обработка /jobs с фильтром: {filter_type}")
    try:
        conn = create_cups_connection()
        logger.debug("Получение всех заданий")
        try:
            jobs = conn.getJobs(
                which_jobs='all',
                my_jobs=False,
                requested_attributes=[
                    'job-id', 'job-name', 'job-state', 'job-printer-name',
                    'job-originating-user-name', 'job-k-octets', 'time-at-creation',
                    'job-state-reasons', 'job-printer-uri'
                ]
            )
            logger.debug(f"Получено {len(jobs)} заданий: {jobs}")
        except Exception as e:
            logger.error(f"Ошибка вызова getJobs: {str(e)}")
            return render_template('jobs.html', error=f"Ошибка получения заданий: {str(e)}"), 500
        job_list = []
        state_map = {
            3: ('Ожидает', 'badge-warning'),
            4: ('Приостановлено', ''),
            5: ('Обрабатывается', 'badge-success'),
            6: ('Остановлено', 'badge-danger'),
            7: ('Отменено', ''),
            8: ('Прервано', 'badge-danger'),
            9: ('Завершено', 'badge-success')
        }
        for job_id, job_info in jobs.items():
            logger.debug(f"Задание {job_id} атрибуты: {job_info}")
            state = job_info.get('job-state', 0)
            state_text = 'Неизвестно'
            badge_class = 'badge-info'
            if state in state_map:
                state_text, badge_class = state_map[state]
            else:
                logger.warning(f"Неизвестное состояние задания {state} для задания {job_id}")
            time_at_creation = job_info.get('time-at-creation', 0)
            time_str = 'Неизвестно'
            if time_at_creation > 0:
                time_str = datetime.fromtimestamp(time_at_creation).strftime('%Y-%m-%d %H:%M:%S')
            printer_name = job_info.get('job-printer-name', extract_printer_name(job_info.get('job-printer-uri')))
            if filter_type == 'active' and state not in [3, 4, 5]:
                continue
            if filter_type == 'completed' and state != 9:
                continue
            job_list.append({
                'id': job_id,
                'name': job_info.get('job-name', 'Неизвестно'),
                'printer': printer_name,
                'user': job_info.get('job-originating-user-name', 'Неизвестно'),
                'state': state_text,
                'badge_class': badge_class,
                'size': job_info.get('job-k-octets', 0),
                'time': time_str,
                'creation_time': time_at_creation
            })
        job_list.sort(key=lambda x: x['creation_time'], reverse=True)
        logger.info(f"Возвращено {len(job_list)} заданий для фильтра {filter_type}")
        if request.args.get('filter'):
            return jsonify({'jobs': job_list})
        else:
            return render_template('jobs.html', jobs=job_list, filter=filter_type)
    except Exception as e:
        logger.error(f"Ошибка заданий: {str(e)}")
        return render_template('jobs.html', error=str(e)), 500

@app.route('/printers')
@require_auth
def printers():
    try:
        conn = create_cups_connection()
        printers = conn.getPrinters()
        logger.debug(f"Получено {len(printers)} принтеров")
        printer_list = []
        for name, info in printers.items():
            logger.debug(f"Принтер {name}: printer-state={info.get('printer-state')}")
            health = {'status': 'Неизвестно', 'badge': ''}
            state = info.get('printer-state')
            if state == 3:
                health = {'status': 'Готов', 'badge': 'badge-success'}
            elif state == 4:
                health = {'status': 'Обрабатывается', 'badge': 'badge-warning'}
            elif state == 5:
                health = {'status': 'Остановлен', 'badge': 'badge-danger'}
            ipp_uri = f"http://{CUPS_SERVER}:{CUPS_PORT}/printers/{name}"
            printer_list.append({
                'name': name,
                'type': 'printer' if not info.get('printer-is-class', False) else 'class',
                'state': {3: 'Готов', 4: 'Обрабатывается', 5: 'Остановлен'}.get(state, 'Неизвестно'),
                'health': health,
                'connection_uri': info.get('device-uri', 'Неизвестно'),
                'ipp_uri': ipp_uri
            })
        logger.info("Отображение страницы принтеров")
        return render_template('printers.html', printers=printer_list)
    except Exception as e:
        logger.error(f"Ошибка принтеров: {str(e)}")
        return render_template('printers.html', error=str(e)), 500

@app.route('/add-printer', methods=['GET', 'POST'])
@require_auth
def add_printer():
    if request.method == 'POST':
        printer_name = request.form.get('printer-name')
        printer_type = request.form.get('printer-type')
        printer_uri = request.form.get('printer-uri')
        is_shared = request.form.get('is-shared') == 'on'
        ppd_name = request.form.get('ppd-name')
        logger.debug(f"Попытка добавить принтер: name={printer_name}, type={printer_type}, uri={printer_uri}, shared={is_shared}, ppd={ppd_name}")
        if not all([printer_name, printer_type, printer_uri]):
            logger.warning("Неполные данные формы принтера")
            return render_template('add_printer.html', error='Заполните все обязательные поля'), 400
        try:
            conn = create_cups_connection()
            if printer_type == 'printer':
                ppd_file = None
                if ppd_name:
                    ppd_file = conn.getPPD(ppd_name)
                conn.addPrinter(
                    name=printer_name,
                    device=printer_uri,
                    ppd=ppd_file,
                    info={'printer-is-shared': 'true' if is_shared else 'false'}
                )
                conn.enablePrinter(printer_name)
                conn.acceptJobs(printer_name)
            else:
                conn.createClass(printer_name, [printer_name])
            logger.info(f"Добавлен {printer_type} {printer_name} с URI {printer_uri}, shared={is_shared}")
            return redirect(url_for('printers'))
        except Exception as e:
            logger.error(f"Ошибка добавления принтера {printer_name}: {str(e)}")
            return render_template('add_printer.html', error=str(e)), 400
        finally:
            if ppd_file and os.path.exists(ppd_file):
                os.remove(ppd_file)
    try:
        conn = create_cups_connection()
        ppds = conn.getPPDs()
        vendors = sorted(set(ppd.get('ppd-make', 'Неизвестно') for ppd in ppds.values()))
        logger.debug(f"Получено {len(vendors)} производителей")
    except Exception as e:
        logger.error(f"Ошибка получения производителей: {str(e)}")
        vendors = []
    return render_template('add_printer.html', vendors=vendors)

@app.route('/get-drivers', methods=['GET'])
@require_auth
def get_drivers():
    vendor = request.args.get('vendor')
    try:
        conn = create_cups_connection()
        ppds = conn.getPPDs()
        drivers = [
            {'ppd_name': ppd_name, 'ppd_display': ppd.get('ppd-make-and-model', ppd_name)}
            for ppd_name, ppd in ppds.items()
            if ppd.get('ppd-make') == vendor
        ]
        logger.debug(f"Получено {len(drivers)} драйверов для производителя {vendor}")
        return jsonify(drivers)
    except Exception as e:
        logger.error(f"Ошибка получения драйверов для {vendor}: {str(e)}")
        return jsonify([]), 500

@app.route('/printer-detail/<name>')
@require_auth
def printer_detail(name):
    try:
        conn = create_cups_connection()
        printers = conn.getPrinters()
        logger.debug(f"Получено {len(printers)} принтеров")
        if name not in printers:
            logger.error(f"Принтер {name} не найден")
            return render_template('printer.html', printer=None, error='Принтер не найден'), 404
        printer = printers[name]
        connection_uri = printer.get('device-uri', 'Неизвестно')
        logger.debug(f"Принтер {name} URI: {connection_uri}")
        ip_address = 'Неизвестно'
        hostname_match = re.search(r'://([^:/]+)(?::\d+)?/', connection_uri)
        if hostname_match:
            hostname = hostname_match.group(1)
            try:
                ip_address = socket.gethostbyname(hostname)
                logger.debug(f"Разрешён {hostname} в {ip_address}")
            except socket.gaierror:
                logger.warning(f"Не удалось разрешить хост {hostname}")
                ip_address = hostname
        state = printer.get('printer-state')
        logger.debug(f"Принтер {name}: printer-state={state}")
        health = {'status': 'Неизвестно', 'badge': ''}
        if state == 3:
            health = {'status': 'Готов', 'badge': 'badge-success'}
        elif state == 4:
            health = {'status': 'Обрабатывается', 'badge': 'badge-warning'}
        elif state == 5:
            health = {'status': 'Остановлен', 'badge': 'badge-danger'}
        ipp_uri = f"ipp://{CUPS_SERVER}:{CUPS_PORT}/printers/{name}"
        printer_data = {
            'name': name,
            'type': 'printer' if not printer.get('printer-is-class', False) else 'class',
            'state': {3: 'Готов', 4: 'Обрабатывается', 5: 'Остановлен'}.get(state, 'Неизвестно'),
            'health': health,
            'connection_uri': connection_uri,
            'ipp_uri': ipp_uri,
            'ip_address': ip_address
        }
        logger.info(f"Отображение деталей принтера для {name}")
        return render_template('printer.html', printer=printer_data)
    except Exception as e:
        logger.error(f"Ошибка деталей принтера для {name}: {str(e)}")
        return render_template('printer.html', printer=None, error=str(e)), 500

@app.route('/modify-printer/<name>', methods=['GET', 'POST'])
@require_auth
def modify_printer(name):
    try:
        conn = create_cups_connection()
        printers = conn.getPrinters()
        if name not in printers:
            logger.error(f"Принтер {name} не найден для модификации")
            return render_template('printer.html', printer=None, error='Принтер не найден'), 404
        if request.method == 'POST':
            new_name = request.form.get('printer-name')
            printer_type = request.form.get('printer-type')
            printer_uri = request.form.get('printer-uri')
            logger.debug(f"Попытка модифицировать принтер: old_name={name}, new_name={new_name}, type={printer_type}, uri={printer_uri}")
            if not all([new_name, printer_type, printer_uri]):
                logger.warning("Неполные данные формы модификации принтера")
                printer_data = {
                    'name': name,
                    'type': 'printer' if not printers[name].get('printer-is-class', False) else 'class',
                    'connection_uri': printers[name].get('device-uri', 'Неизвестно')
                }
                return render_template('modify_printer.html', printer=printer_data, error='Заполните все обязательные поля'), 400
            try:
                if printer_type == 'printer':
                    conn.addPrinter(name=new_name, device=printer_uri)
                    conn.enablePrinter(new_name)
                    conn.acceptJobs(new_name)
                else:
                    conn.createClass(new_name, [new_name])
                if new_name != name:
                    conn.deletePrinter(name)
                logger.info(f"Модифицирован принтер {name} в {new_name}")
                return redirect(url_for('printer_detail', name=new_name))
            except Exception as e:
                logger.error(f"Ошибка модификации принтера {name}: {str(e)}")
                printer_data = {
                    'name': name,
                    'type': 'printer' if not printers[name].get('printer-is-class', False) else 'class',
                    'connection_uri': printers[name].get('device-uri', 'Неизвестно')
                }
                return render_template('modify_printer.html', printer=printer_data, error=str(e)), 500
        printer_data = {
            'name': name,
            'type': 'printer' if not printers[name].get('printer-is-class', False) else 'class',
            'connection_uri': printers[name].get('device-uri', 'Неизвестно')
        }
        return render_template('modify_printer.html', printer=printer_data)
    except Exception as e:
        logger.error(f"Ошибка модификации принтера для {name}: {str(e)}")
        return render_template('printer.html', printer=None, error=str(e)), 500

@app.route('/delete-printer/<name>', methods=['POST'])
@require_auth
def delete_printer(name):
    try:
        conn = create_cups_connection()
        printers = conn.getPrinters()
        if name not in printers:
            logger.error(f"Принтер {name} не найден для удаления")
            return redirect(url_for('printers'))
        conn.deletePrinter(name)
        logger.info(f"Удалён принтер {name}")
        return redirect(url_for('printers'))
    except Exception as e:
        logger.error(f"Ошибка удаления принтера {name}: {str(e)}")
        return render_template('printers.html', error=str(e)), 500
