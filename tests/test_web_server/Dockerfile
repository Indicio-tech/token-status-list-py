FROM alpine

RUN apk update &&\
    apk add python3 curl nginx

COPY tests/test_web_server/index.html /var/www/html/index.html
COPY tests/test_web_server/nginx.conf /etc/nginx

EXPOSE 80

RUN curl -sSL https://pdm-project.org/install-pdm.py | python3 -

WORKDIR /usr/src/app
COPY pdm.lock pyproject.toml tests/test_web_server/main.py README.md ./
COPY src/token_status_list.py src/issuer.py ./src/

# cbor2 is an optional dependency, but we use it for this test
RUN /root/.local/bin/pdm add cbor2
RUN /root/.local/bin/pdm run main.py

CMD ["nginx", "-g", "daemon off;"]
