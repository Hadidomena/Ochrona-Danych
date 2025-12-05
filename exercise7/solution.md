# Exercise 7: Flask + Nginx + TLS (Gunicorn)

## 1. Wygenerować certyfikat samo podpisany

### Polecenie generowania certyfikatu
```bash
cd /mnt/c/Users/szepiet33/Documents/Workspace/Ochrona\ Danych/exercise7
bash ssl/generateSSL
```

### Zawartość skryptu `ssl/generateSSL`
```bash
#!/bin/bash
set -e
mkdir -p "$(dirname "$0")"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$(dirname "$0")/selfsigned.key" \
  -out "$(dirname "$0")/selfsigned.crt" \
  -subj "/CN=localhost"
chmod 600 "$(dirname "$0")/selfsigned.key"
```

### Szczegóły certyfikatu
```bash
$ openssl x509 -in exercise7/ssl/selfsigned.crt -noout -subject -dates
subject=CN = localhost
notBefore=Dec  3 00:07:32 2025 GMT
notAfter=Dec  3 00:07:32 2026 GMT
```

## 2. Skonfigurować i uruchomić serwer nginx (tylko połączenia szyfrowane)

### Konfiguracja nginx (`exercise7/nginx/exercise7.conf`)
```nginx
server {
    listen 80;
    server_name localhost;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name localhost;

    ssl_certificate     /etc/ssl/exercise7/selfsigned.crt;
    ssl_certificate_key /etc/ssl/exercise7/selfsigned.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
    }
}
```

### Instalacja konfiguracji i restart nginx
```bash
# Skrypt start.sh automatycznie:
# - kopiuje certyfikaty do /etc/ssl/exercise7/
# - instaluje config do /etc/nginx/sites-available/
# - testuje konfigurację (nginx -t)
# - restartuje nginx

cd exercise7/scripts
bash start.sh
```

### Weryfikacja nasłuchu nginx na portach 80 i 443
```bash
$ sudo ss -ltnp | grep -E ':443|:80'
LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:(("nginx",pid=311,...))
LISTEN 0      511          0.0.0.0:443       0.0.0.0:*    users:(("nginx",pid=311,...))
LISTEN 0      511             [::]:80           [::]:*    users:(("nginx",pid=311,...))
```

### Test połączenia SSL (verbose output pokazujący TLS handshake)
```bash
$ curl -vk https://localhost/status 2>&1 | head -30
*   Trying 127.0.0.1:443...
* Connected to localhost (127.0.0.1) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* Server certificate:
*  subject: CN=localhost
```

**Wniosek**: Nginx obsługuje tylko połączenia HTTPS (port 443) z TLS 1.2/1.3. Port 80 przekierowuje na HTTPS.

## 3. Użyć nginx jako proxy do aplikacji Flask (Gunicorn)

### WSGI entry point (`exercise7/app/wsgi.py`)
```python
from app import app
```

### Uruchomienie Gunicorn (backend)
```bash
cd exercise7/app
gunicorn --workers 2 --bind 127.0.0.1:8000 wsgi:app \
  --daemon \
  --access-logfile ../logs/gunicorn-access.log \
  --error-logfile ../logs/gunicorn-error.log
```

### Weryfikacja działającego Gunicorn
```bash
$ ps aux | grep '[g]unicorn' | head -3
szepietp    2027  0.5  0.1  32324 21604 ?  S  14:02  0:00 /usr/bin/python3 /usr/bin/gunicorn --workers 2 --bind 127.0.0.1:8000 wsgi:app --daemon ...
szepietp    2029  5.5  0.1  39248 31340 ?  S  14:02  0:00 /usr/bin/python3 /usr/bin/gunicorn --workers 2 --bind 127.0.0.1:8000 wsgi:app --daemon ...
szepietp    2030 12.0  0.1  39248 31340 ?  S  14:02  0:00 /usr/bin/python3 /usr/bin/gunicorn --workers 2 --bind 127.0.0.1:8000 wsgi:app --daemon ...
```


## 4. Pokazać z jakimi uprawnieniami działa aplikacja Flask

### Test endpointu `/status` (przez HTTPS)
```bash
$ curl -sk https://localhost/status
{"gid":1000,"uid":1000,"user":"szepietp"}
```

### Sprawdzenie procesu Gunicorn
```bash
$ ps aux | grep '[g]unicorn' | head -1
szepietp    2027  0.5  0.1  32324 21604 ?  S  14:02  0:00 /usr/bin/python3 /usr/bin/gunicorn ...
```

## 5. Umożliwić odczytanie prawdziwego adresu IP z przychodzących zapytań

### Konfiguracja nginx (przekazywanie nagłówków proxy)
```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

### Konfiguracja Flask (ProxyFix middleware)
```python
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
```

### Test endpointu `/ip` (przez HTTPS)
```bash
$ curl -sk https://localhost/ip
{"X-Forwarded-For":"127.0.0.1","X-Real-IP":"127.0.0.1","remote_addr":"127.0.0.1"}
```