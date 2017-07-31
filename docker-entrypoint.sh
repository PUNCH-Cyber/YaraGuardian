#!/bin/bash
su -c "${API_ENV}/bin/python3.5 manage.py migrate" ${API_USER}
su -c "${API_ENV}/bin/python3.5 manage.py collectstatic --noinput" ${API_USER}

chown -R ${API_USER}:www-data ${API_DIR}/static
chown -R ${API_USER}:www-data ${API_DIR}/logs
chmod 660 ${API_DIR}/logs/manager.log

/usr/sbin/apache2ctl -D FOREGROUND
