FROM alpine

RUN apk update &&\
    apk add python3 curl nginx

COPY tests/test_web_server/issuer/index.html /var/www/html/index.html
COPY tests/test_web_server/issuer/nginx.conf /etc/nginx

EXPOSE 80

RUN curl -sSL https://pdm-project.org/install-pdm.py | python3 -

WORKDIR /usr/src/app
COPY pdm.lock pyproject.toml tests/test_web_server/issuer/main.py ./
COPY src/token_status_list.py src/issuer.py ./src/
RUN /root/.local/bin/pdm run main.py

CMD ["nginx", "-g", "daemon off;"]
