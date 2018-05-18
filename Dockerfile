FROM ubuntu:16.04
MAINTAINER Adam Trask ”adam@punchcyber.com”

ENV LANG='C.UTF-8' LC_ALL='C.UTF-8' LANGUAGE='C.UTF-8' NODE_VERSION='8.0.0'
ENV API_DIR='/usr/local/YaraGuardian' API_USER='YaraManager' API_GROUP='YaraManager'

ADD . ${API_DIR}

RUN apt-get update \
  && apt-get -y install software-properties-common \
  && apt-add-repository -y multiverse \
  && apt-get update \
  && apt-get upgrade -y \
  && echo "Installing prerequisite packages..." \
  && apt-get -y install \
    curl \
    git \
    libpq-dev \
    npm \
    python3 \
    python3-dev \
    python3-setuptools \
  && easy_install3 pip \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

############################
### Install Dependencies ###
############################
WORKDIR ${API_DIR}/plyara
RUN python3 setup.py test \
  && python3 setup.py install \
  && rm -r ${API_DIR}/plyara \
  && rm -r ${API_DIR}/configs

WORKDIR ${API_DIR}
RUN echo "Installing NodeJS version ${NODE_VERSION}" \
  && npm cache clean -f \
  && npm install -g n \
  && n ${NODE_VERSION} \
  && ln -sf /usr/local/n/versions/node/${NODE_VERSION}/bin/node /usr/bin/node \
  && echo "Installing python requirements..." \
  && pip3 install -r requirements.txt \
  && echo "Installing front-end components" \
  && npm install yarn -g \
  && yarn \
  && yarn webpack \
  && python3 manage.py collectstatic --noinput \
  && rm -rf /usr/local/n

RUN groupadd -r ${API_USER} \
  && useradd -r -g ${API_GROUP} ${API_USER} \
  && chown -R ${API_USER}:${API_GROUP} ${API_DIR}

EXPOSE 8080
USER ${API_USER}

CMD PYTHONUNBUFFERED=1 gunicorn -k gevent --bind=0.0.0.0:8080 --access-logfile - --error-logfile - YaraGuardian.wsgi:application
