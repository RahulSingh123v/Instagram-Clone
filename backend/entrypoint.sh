#!/bin/sh

echo "Making migrations..."
python manage.py makemigrations accounts
python manage.py makemigrations posts
python manage.py makemigrations

echo "Applying migrations..."
python manage.py migrate

echo "Starting Django dev server..."
python manage.py runserver 0.0.0.0:8000
