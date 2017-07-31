FROM ubuntu:16.04
MAINTAINER Adam Trask ”adam@punchcyber.com”

ENV LANG='C.UTF-8' LC_ALL='C.UTF-8' LANGUAGE='C.UTF-8' NODE_VERSION='7.6.0'
ENV API_DIR='/usr/local/YaraGuardian' API_USER='YaraManager' API_GROUP='YaraManager'
ENV API_ENV ${API_DIR}/.pyenv

ADD . ${API_DIR}

RUN apt-get update \
  && apt-get -y install software-properties-common \
  && apt-add-repository -y multiverse

#############################
### Install Prerequisites ###
#############################
RUN apt-get update \
  && echo "Installing prerequisite packages..." \
  && apt-get -y install \
    apache2 \
    curl \
    git \
    libapache2-mod-wsgi-py3 \
    libpq-dev \
    npm \
    python3 \
    python3-dev \
    python3-setuptools \
  && echo "Setting up virtualenv..." \
  && easy_install3 pip \
  && pip3 install virtualenv --quiet \
  && virtualenv ${API_ENV}

############################
### Install Dependencies ###
############################
WORKDIR ${API_DIR}/plyara
RUN ${API_ENV}/bin/python3.5 setup.py test \
  && ${API_ENV}/bin/python3.5 setup.py install

WORKDIR ${API_DIR}
RUN echo "Installing NodeJS version ${NODE_VERSION}" \
  && npm cache clean -f \
  && npm install -g n \
  && n ${NODE_VERSION} \
  && ln -sf /usr/local/n/versions/node/${NODE_VERSION}/bin/node /usr/bin/node

RUN echo "Installing python requirements..." \
  && ${API_ENV}/bin/pip3.5 install -r requirements.txt \
  && echo "Installing front-end components" \
  && npm install yarn -g \
  && yarn \
  && yarn webpack

#################################
### Cleanup and Initial Setup ###
#################################
RUN echo "Configuring Apache2" \
  && cp ${API_DIR}/additional_configs/apache2/YaraGuardian.conf /etc/apache2/sites-available/YaraGuardian.conf \
  && cp ${API_DIR}/additional_configs/apache2/ports.conf /etc/apache2/ports.conf \
  && a2ensite YaraGuardian \
  && service apache2 stop

RUN echo "Cleaning up" \
  && rm -r ${API_DIR}/plyara \
  && rm -r ${API_DIR}/additional_configs

EXPOSE 8080

RUN groupadd -r ${API_USER} && useradd -r -g ${API_GROUP} ${API_USER}
RUN chown -R ${API_USER}:${API_GROUP} ${API_DIR}

COPY ./docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]
