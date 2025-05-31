FROM ubuntu:24.04

# Устанавливаем рабочую директорию
WORKDIR /tmp

# Задаем аргументы для имени пользователя и пароля (можно переопределить при сборке)
ARG CUPS_ADMIN_USER=cupsadmin
ARG CUPS_ADMIN_PASSWORD=securepassword123

# Устанавливаем зависимости для сборки CUPS
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    tar \
    zlib1g-dev \
    libpam0g-dev \
    libusb-1.0-0-dev \
    libdbus-1-dev \
    libavahi-client-dev \
    libavahi-common-dev \
    libcups2 \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Скачиваем, распаковываем, собираем и устанавливаем CUPS
RUN wget https://github.com/OpenPrinting/cups/releases/download/v2.4.12/cups-2.4.12-source.tar.gz \
    && tar -xvzf cups-2.4.12-source.tar.gz \
    && cd cups-2.4.12 \
    && ./configure --enable-shared --disable-tls \
    && make \
    && make install \
    && cd .. \
    && rm -rf cups-2.4.12* cups-2.4.12-source.tar.gz

# Создаем пользователя и задаем пароль
RUN groupadd printadmin && sed -i 's/SystemGroup sys root/SystemGroup printadmin/' /etc/cups/cups-files.conf
RUN useradd -m -G printadmin ${CUPS_ADMIN_USER} \
    && echo "${CUPS_ADMIN_USER}:${CUPS_ADMIN_PASSWORD}" | chpasswd

# Копируем конфигурационный файл CUPS
COPY cupsd.conf /etc/cups/cupsd.conf

# Устанавливаем переменные окружения для CUPS
ENV CUPS_PORT=631
ENV CUPS_LOG_LEVEL=debug

# Открываем порт для CUPS
EXPOSE 631

# Запускаем CUPS в foreground
CMD ["/usr/sbin/cupsd", "-f"]