#!/bin/bash

python ./manage.py makemigrations collab
python ./manage.py migrate
has_admin=$(echo "select count(*) from auth_user where username='admin';" | ./manage.py dbshell)
if [ $has_admin -eq 0 ]; then
    echo "Creating admin super user, please enter password"
    ./manage.py createsuperuser --username admin --email admin@local.com
fi
./manage.py runserver -v 3
