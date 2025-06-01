from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import cups
import socket
import re
import logging
import os
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv

# Загружаем переменные из .env
load_dotenv()

# Настройки CUPS и авторизации
CUPS_SERVER = os.getenv("CUPS_SERVER", "localhost")
CUPS_PORT = int(os.getenv("CUPS_PORT", "631"))
ALLOWED_USER = os.getenv("ALLOWED_USER")
ALLOWED_PASSWORD = os.getenv("ALLOWED_PASSWORD")

# Configure logging
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
app.secret_key = os.urandom(24)  # Безопасный ключ для сессий

def get_connection(username, password):
    """Создаёт соединение с CUPS с указанными учетными данными."""
    try:
        def password_cb(prompt):
            logger.debug(f"CUPS запросил пароль для {username}")
            return password
        cups.setPasswordCB(password_cb)
        cups.setUser(username)
        conn = cups.Connection(host=CUPS_SERVER, port=CUPS_PORT)
        # Проверяем соединение
        conn.getPrinters()
        logger.info(f"Connected to CUPS server at {CUPS_SERVER}:{CUPS_PORT} as {username}")
        return conn
    except Exception as e:
        logger.error(f"Failed to connect to CUPS for {username}: {str(e)}")
        return None

def get_cups_server_ip():
    """Получает IP-адрес сервера CUPS из CUPS_SERVER."""
    try:
        server_ip = socket.gethostbyname(CUPS_SERVER)
        logger.debug(f"CUPS server {CUPS_SERVER} resolved to IP: {server_ip}")
        return server_ip
    except socket.gaierror:
        logger.error(f"Failed to resolve CUPS server IP for {CUPS_SERVER}")
        return "Unknown"

def require_auth(f):
    """Декоратор для проверки авторизации."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            logger.warning(f"Неавторизованный доступ к {request.path}")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def create_cups_connection():
    """Создает соединение с CUPS с учетными данными из сессии."""
    try:
        username = session.get('username')
        password = session.get('password')
        if not username or not password:
            logger.error("Нет учетных данных в сессии")
            raise ValueError("Нет учетных данных в сессии")
        
        logger.debug(f"Создание CUPS-соединения для {username}")
        conn = get_connection(username, password)
        if conn is None:
            raise RuntimeError("Не удалось создать соединение с CUPS")
        return conn
    except Exception as e:
        logger.error(f"Ошибка подключения к CUPS: {str(e)}")
        raise

def extract_printer_name(printer_uri):
    """Извлекает имя принтера из job-printer-uri."""
    if not printer_uri:
        return 'Unknown'
    match = re.search(r'/printers/([^/]+)', printer_uri)
    return match.group(1) if match else 'Unknown'

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        logger.info(f"Пользователь {session['username']} уже авторизован, перенаправление на /dashboard")
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        logger.debug(f"Попытка входа: username={username}, password={'*' * len(password) if password else 'пусто'}")
        
        if not username or not password:
            logger.warning("Пустые учетные данные при попытке входа")
            return render_template('login.html', error='Заполните все поля'), 400
        
        # Проверка конфигурации
        if not ALLOWED_USER or not ALLOWED_PASSWORD:
            logger.error("ALLOWED_USER или ALLOWED_PASSWORD не указаны в .env")
            return render_template('login.html', error='Сервер не настроен'), 500
        
        # Проверка пользователя
        if username != ALLOWED_USER:
            logger.warning(f"Попытка входа с недопустимым пользователем: {username}")
            return render_template('login.html', error='Доступ запрещён для этого пользователя'), 401
        
        # Проверка пароля
        if password != ALLOWED_PASSWORD:
            logger.warning(f"Неверный пароль для {username}")
            return render_template('login.html', error='Неверное имя пользователя или пароль'), 401
        
        # Проверка через CUPS
        conn = get_connection(username, password)
        if conn is None:
            logger.warning(f"Неудачная попытка входа для {username}")
            return render_template('login.html', error='Ошибка подключения к CUPS'), 401
        
        session['username'] = username
        session['password'] = password  # ВНИМАНИЕ: Хранение пароля в сессии небезопасно
        logger.info(f"Успешная авторизация для {username}")
        return redirect(url_for('dashboard'))
    
    logger.debug("Отображение страницы логина")
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
        
        # Получение принтеров
        logger.debug("Получение списка принтеров для дашборда")
        printers = conn.getPrinters()
        logger.debug(f"Получено {len(printers)} принтеров")
        
        data['printer_count'] = len(printers)
        data['active_printers'] = sum(1 for p in printers.values() if p.get('printer-state') == 3)
        data['error_printers'] = sum(1 for p in printers.values() if p.get('printer-state') == 5)
        
        # Получение заданий
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
                # Логируем все атрибуты задания
                logger.debug(f"Атрибуты задания {job_id}: {job_info}")
                
                state = job_info.get('job-state', 0)
                state_text = 'Unknown'
                badge_class = 'badge-info'
                if state in [3, 4, 5, 6, 7, 8, 9]:
                    state_map = {
                        3: ('Pending', 'badge-warning'),  # Жёлтый для Pending
                        4: ('Held', ''),
                        5: ('Processing', 'badge-success'),
                        6: ('Stopped', 'badge-danger'),
                        7: ('Canceled', ''),
                        8: ('Aborted', 'badge-danger'),
                        9: ('Completed', 'badge-success')
                    }
                    state_text, badge_class = state_map[state]
                
                time_at_creation = job_info.get('time-at-creation', 0)
                time_str = 'Unknown'
                if time_at_creation > 0:
                    time_str = datetime.fromtimestamp(time_at_creation).strftime('%Y-%m-%d %H:%M:%S')
                
                # Извлечение имени принтера из job-printer-uri, если job-printer-name отсутствует
                printer_name = job_info.get('job-printer-name', extract_printer_name(job_info.get('job-printer-uri')))
                
                completed_jobs.append({
                    'id': job_id,
                    'name': job_info.get('job-name', 'Unknown'),
                    'printer': printer_name,
                    'user': job_info.get('job-originating-user-name', 'Unknown'),
                    'state': state_text,
                    'badge_class': badge_class,
                    'size': job_info.get('job-k-octets', 0),
                    'time': time_str,
                    'creation_time': time_at_creation
                })
            
            # Сортировка по времени создания (от новых к старым)
            completed_jobs.sort(key=lambda x: x['creation_time'], reverse=True)
            data['completed_jobs'] = completed_jobs[:5]
            logger.debug(f"Подготовлено {len(data['completed_jobs'])} завершённых заданий для отображения")
            
        except Exception as e:
            logger.error(f"Ошибка при получении заданий: {str(e)}")
            data['error'] = f"Ошибка получения заданий: {str(e)}"
        
        logger.info("Рендеринг дашборда")
        return render_template('dashboard.html', **data)
    
    except Exception as e:
        logger.error(f"Ошибка в /dashboard: {str(e)}")
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
            logger.error(f"Ошибка при вызове getJobs: {str(e)}")
            return render_template('jobs.html', error=f"Ошибка получения заданий: {str(e)}"), 500

        job_list = []
        state_map = {
            3: ('Pending', 'badge-warning'),  # Жёлтый для Pending
            4: ('Held', ''),
            5: ('Processing', 'badge-success'),
            6: ('Stopped', 'badge-danger'),
            7: ('Canceled', ''),
            8: ('Aborted', 'badge-danger'),
            9: ('Completed', 'badge-success')
        }

        for job_id, job_info in jobs.items():
            # Логируем все атрибуты задания для диагностики
            logger.debug(f"Атрибуты задания {job_id}: {job_info}")
            
            state = job_info.get('job-state', 0)
            state_text = 'Unknown'
            badge_class = 'badge-info'
            
            if state in state_map:
                state_text, badge_class = state_map[state]
            else:
                logger.warning(f"Неизвестное состояние задания {state} для задания {job_id}")

            # Обработка времени создания
            time_at_creation = job_info.get('time-at-creation', 0)
            time_str = 'Unknown'
            if time_at_creation > 0:
                time_str = datetime.fromtimestamp(time_at_creation).strftime('%Y-%m-%d %H:%M:%S')

            # Извлечение имени принтера из job-printer-uri, если job-printer-name отсутствует
            printer_name = job_info.get('job-printer-name', extract_printer_name(job_info.get('job-printer-uri')))

            # Применяем фильтры
            if filter_type == 'active' and state not in [3, 4, 5]:
                continue
            if filter_type == 'completed' and state != 9:
                continue

            job_list.append({
                'id': job_id,
                'name': job_info.get('job-name', 'Unknown'),
                'printer': printer_name,
                'user': job_info.get('job-originating-user-name', 'Unknown'),
                'state': state_text,
                'badge_class': badge_class,
                'size': job_info.get('job-k-octets', 0),
                'time': time_str,
                'creation_time': time_at_creation
            })

        # Сортировка по времени создания (от новых к старым)
        job_list.sort(key=lambda x: x['creation_time'], reverse=True)
        logger.info(f"Возвращено {len(job_list)} заданий для фильтра {filter_type}")

        if request.args.get('filter'):
            return jsonify({'jobs': job_list})
        else:
            return render_template('jobs.html', jobs=job_list, filter=filter_type)
    except Exception as e:
        logger.error(f"Ошибка в /jobs: {str(e)}")
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
            # Логируем состояние принтера
            logger.debug(f"Принтер {name}: printer-state={info.get('printer-state')}")
            
            health = {'status': 'Unknown', 'badge': ''}
            state = info.get('printer-state')
            if state == 3:
                health = {'status': 'Ready', 'badge': 'badge-success'}
            elif state == 4:
                health = {'status': 'Processing', 'badge': 'badge-warning'}
            elif state == 5:
                health = {'status': 'Stopped', 'badge': 'badge-danger'}

            printer_list.append({
                'name': name,
                'type': 'printer' if not info.get('printer-is-class', False) else 'class',
                'state': {3: 'Ready', 4: 'Processing', 5: 'Stopped'}.get(state, 'Unknown'),
                'health': health,
                'uri': info.get('device-uri', 'Unknown')
            })

        logger.info("Рендеринг страницы принтеров")
        return render_template('printers.html', printers=printer_list)
    except Exception as e:
        logger.error(f"Ошибка в /printers: {str(e)}")
        return render_template('printers.html', error=str(e)), 500

@app.route('/add-printer', methods=['GET', 'POST'])
@require_auth
def add_printer():
    if request.method == 'POST':
        printer_name = request.form.get('printer-name')
        printer_type = request.form.get('printer-type')
        printer_uri = request.form.get('printer-uri')

        logger.debug(f"Попытка добавить принтер: name={printer_name}, type={printer_type}, uri={printer_uri}")

        if not all([printer_name, printer_type, printer_uri]):
            logger.warning("Неполные данные формы добавления принтера")
            return render_template('add_printer.html', error='Заполните все поля'), 400

        try:
            conn = create_cups_connection()
            if printer_type == 'printer':
                conn.addPrinter(name=printer_name, device=printer_uri)
                conn.enablePrinter(printer_name)
                conn.acceptJobs(printer_name)
            else:  # class
                conn.createClass(printer_name, [printer_name])
            logger.info(f"Добавлен {printer_type} {printer_name} с URI {printer_uri}")
            return redirect(url_for('printers'))
        except Exception as e:
            logger.error(f"Ошибка добавления принтера {printer_name}: {str(e)}")
            return render_template('add_printer.html', error=str(e)), 500

    return render_template('add_printer.html')

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
        uri = printer.get('device-uri', 'Unknown')
        logger.debug(f"URI принтера {name}: {uri}")

        # Извлечение IP
        ip_address = 'Unknown'
        hostname_match = re.search(r'://([^:/]+)(?::\d+)?/', uri)
        if hostname_match:
            hostname = hostname_match.group(1)
            try:
                ip_address = socket.gethostbyname(hostname)
                logger.debug(f"Разрешено {hostname} в {ip_address}")
            except socket.gaierror:
                logger.warning(f"Не удалось разрешить хост {hostname}")
                ip_address = hostname

        # Здоровье принтера
        state = printer.get('printer-state')
        logger.debug(f"Принтер {name}: printer-state={state}")
        health = {'status': 'Unknown', 'badge': ''}
        if state == 3:
            health = {'status': 'Ready', 'badge': 'badge-success'}
        elif state == 4:
            health = {'status': 'Processing', 'badge': 'badge-warning'}
        elif state == 5:
            health = {'status': 'Stopped', 'badge': 'badge-danger'}

        printer_data = {
            'name': name,
            'type': 'printer' if not printer.get('printer-is-class', False) else 'class',
            'state': {3: 'Ready', 4: 'Processing', 5: 'Stopped'}.get(state, 'Unknown'),
            'health': health,
            'uri': uri,
            'ip_address': ip_address
        }

        logger.info(f"Рендеринг деталей принтера {name}")
        return render_template('printer.html', printer=printer_data)
    except Exception as e:
        logger.error(f"Ошибка в /printer-detail/{name}: {str(e)}")
        return render_template('printer.html', printer=None, error=str(e)), 500

@app.route('/modify-printer/<name>', methods=['GET', 'POST'])
@require_auth
def modify_printer(name):
    try:
        conn = create_cups_connection()
        printers = conn.getPrinters()
        if name not in printers:
            logger.error(f"Принтер {name} не найден для изменения")
            return render_template('printer.html', printer=None, error='Принтер не найден'), 404

        if request.method == 'POST':
            new_name = request.form.get('printer-name')
            printer_type = request.form.get('printer-type')
            printer_uri = request.form.get('printer-uri')

            logger.debug(f"Попытка изменить принтер: old_name={name}, new_name={new_name}, type={printer_type}, uri={printer_uri}")

            if not all([new_name, printer_type, printer_uri]):
                logger.warning("Неполные данные формы изменения принтера")
                printer_data = {
                    'name': name,
                    'type': 'printer' if not printers[name].get('printer-is-class', False) else 'class',
                    'uri': printers[name].get('device-uri', 'Unknown')
                }
                return render_template('modify_printer.html', printer=printer_data, error='Заполните все поля'), 400

            try:
                if printer_type == 'printer':
                    conn.addPrinter(name=new_name, device=printer_uri)
                    conn.enablePrinter(new_name)
                    conn.acceptJobs(new_name)
                else:
                    conn.createClass(new_name, [new_name])
                if new_name != name:
                    conn.deletePrinter(name)
                logger.info(f"Изменен принтер {name} на {new_name}")
                return redirect(url_for('printer_detail', name=new_name))
            except Exception as e:
                logger.error(f"Ошибка изменения принтера {name}: {str(e)}")
                printer_data = {
                    'name': name,
                    'type': 'printer' if not printers[name].get('printer-is-class', False) else 'class',
                    'uri': printers[name].get('device-uri', 'Unknown')
                }
                return render_template('modify_printer.html', printer=printer_data, error=str(e)), 500

        printer_data = {
            'name': name,
            'type': 'printer' if not printers[name].get('printer-is-class', False) else 'class',
            'uri': printers[name].get('device-uri', 'Unknown')
        }
        return render_template('modify_printer.html', printer=printer_data)
    except Exception as e:
        logger.error(f"Ошибка в /modify-printer/{name}: {str(e)}")
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
        logger.info(f"Удален принтер {name}")
        return redirect(url_for('printers'))
    except Exception as e:
        logger.error(f"Ошибка удаления принтера {name}: {str(e)}")
        return render_template('printers.html', error=str(e)), 500

if __name__ == '__main__':
    logger.info("Запуск Flask-приложения")
    app.run(debug=True, host='0.0.0.0', port=8080)