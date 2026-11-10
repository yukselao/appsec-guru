# syntax=docker/dockerfile:1
# PHP-FPM runtime for the web UI pages. Only the runtime and its libraries are
# installed here; the application in ./wwwroot is bind-mounted at runtime.
FROM php:8.3-fpm

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends libzip-dev tini unzip; \
    docker-php-ext-install -j"$(nproc)" zip opcache; \
    rm -rf /var/lib/apt/lists/*; \
    usermod -u 1000 www-data; groupmod -g 1000 www-data

# Twig lives outside /var/www/html so the bind mount does not hide it.
RUN --mount=from=composer:2,source=/usr/bin/composer,target=/usr/bin/composer \
    --mount=type=bind,source=composer.json,target=/opt/app/composer.json \
    set -eux; cd /opt/app; \
    COMPOSER_ALLOW_SUPERUSER=1 composer install --no-dev --no-interaction --no-progress

RUN { \
      echo 'expose_php = Off'; \
      echo 'display_errors = Off'; \
      echo 'log_errors = On'; \
      echo 'error_log = /proc/self/fd/2'; \
      echo 'memory_limit = 128M'; \
    } > /usr/local/etc/php/conf.d/was-troubleshooter.ini

WORKDIR /var/www/html
ENTRYPOINT ["tini", "--"]
CMD ["php-fpm"]
