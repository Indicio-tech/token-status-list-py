FROM nginx-1.26.2:alpine
WORKDIR /usr/src/app

RUN apk update &&\
    apk add python3 curl

ENV HOME=.
RUN curl -sSL https://pdm-project.org/install-pdm.py | python3 -

COPY ../../../pdm.lock ../../../pyproject.toml ../../../token_status_list.py ../../../issuer.py ./main.py ./
RUN pdm run main.py
