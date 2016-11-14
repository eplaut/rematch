#!/bin/bash

sqlite3_loc=/usr/bin/sqlite3
if [ ! -f $sqlite3_loc ]; then
  echo "sqlite3 is not installed, installing.."
  sudo apt-get install sqlite3
fi;
python ./manage.py makemigrations collab
python ./manage.py migrate
has_admin=$(echo "select count(*) from auth_user where username='admin';" | python ./manage.py dbshell)
if [ $has_admin -eq 0 ]; then
    echo "Creating admin super user, please enter password"
    python ./manage.py createsuperuser --username admin --email admin@local.com
fi
python ./manage.py runserver -v 3
