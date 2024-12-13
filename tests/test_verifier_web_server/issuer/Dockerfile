FROM alpine

RUN apk update &&\
    apk add python3 curl nginx

COPY index.html /var/www/html/index.html
COPY nginx.conf /etc/nginx

EXPOSE 80

RUN curl -sSL https://pdm-project.org/install-pdm.py | python3 -

WORKDIR /usr/src/app
COPY ../../../pdm.lock ../../../pyproject.toml ../../../token_status_list.py ../../../issuer.py ./main.py ./
RUN pdm run main.py

CMD ["nginx", "-g", "daemon off;"]
