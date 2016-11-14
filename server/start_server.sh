#!/bin/bash
python ./manage.py makemigrations collab
python ./manage.py migrate
has_admin=$(echo "select count(*) from auth_user where username='admin';" | python ./manage.py dbshell)
if [ $has_admin -eq 0 ]; then
    echo "Creating admin super user, please enter password"
    python ./manage.py createsuperuser --username admin --email admin@local.com
fi
sudo python manage.py runserver 192.168.152.138:80
