# HoneyDjango

Django 5.2 honeypot platform. Captures attackers hitting decoy endpoints,
enriches events via Celery, displays real-time intelligence in Django admin.

## Stack
- Python 3.12, Django 5.2 LTS, DRF, Django Channels 4
- PostgreSQL 16 (JSONB for payloads), Redis (cache + Channels layer)
- Celery 5 + Celery Beat, docker-compose for local dev

## Project layout
- apps/ — all Django apps (honeypot, events, profiles, alerts, feeds, dashboard)
- honeydj/settings/ — base / local / production split
- docs/context/ — load these manually when needed, not auto-loaded

## Dev workflow
- Run: docker-compose up
- Tests: pytest (target 80% coverage)
- Lint: ruff check . && mypy .
- Migrations: python manage.py migrate

## Commit rules
- I make all commits myself — never run git commit or git push
- Never suggest "commit this" — just implement the code
- Conventional commits format when I do commit: feat/fix/refactor/test/docs

## Code style
- Type hints on all functions
- Django ORM only — no raw SQL unless migration-critical
- Celery tasks must be idempotent
- No print() — use Django logging

## Context files (load with @docs/context/FILE when needed)
- architecture.md — system design decisions
- models.md — full model field reference
- session-notes.md — decisions from last session