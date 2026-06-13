Create and apply Django migrations for any model changes made this session.

```bash
docker-compose exec web python manage.py makemigrations --check 2>&1
docker-compose exec web python manage.py makemigrations 2>&1
docker-compose exec web python manage.py migrate 2>&1
```

Show the migration files created. Do not commit them.