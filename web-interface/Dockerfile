FROM python:3.12-slim

# Устанавливаем зависимости для pycups и cups
RUN apt-get update && apt-get install -y \
    libcups2-dev \
    cups-client \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файлы проекта
COPY requirements.txt .
COPY main.py .
COPY templates/ templates/
COPY static/ static/
COPY pycups-2.0.4/ pycups-2.0.4/
COPY .env .

# Устанавливаем Python-зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Открываем порт
EXPOSE 8088

# Запускаем приложение через Gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8088", "main:app"]