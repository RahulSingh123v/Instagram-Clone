#!/bin/sh

echo "Applying migrations..."
python manage.py migrate

echo "Starting Django dev server..."
python manage.py runserver 0.0.0.0:8000
