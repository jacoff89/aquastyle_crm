FROM phpdockerio/php:8.5-fpm
WORKDIR '/var/www/html'

ARG DEBIAN_FRONTEND=noninteractive
ARG UID=1000
ARG GID=1000
RUN usermod -u ${UID} ubuntu && groupmod -g ${GID} ubuntu

# Install FPM
RUN apt-get update \
    && apt-get -y --no-install-recommends install php-zip unzip php8.5-mysql php-sqlite3 php8.5-bcmath php8.5-intl php8.5-xml php8.5-gd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/share/doc/*

RUN cd /tmp/ \
    && php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" \
    && php composer-setup.php --install-dir=/usr/local/bin --filename=composer

#RUN apt-get update
#RUN apt-get install -y mc iproute2 dnsutils inetutils-telnet iputils-ping nano \
#    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Создаём pid-файл и каталог сокета, даем права
RUN mkdir -p /run/php \
    && touch /run/php-fpm.pid \
    && chown -R ${UID}:${GID} /run/php /run/php-fpm.pid


# Переключаемся на нового пользователя
USER ubuntu

# Запуск php-fpm
CMD ["/usr/sbin/php-fpm8.5", "-O"]
