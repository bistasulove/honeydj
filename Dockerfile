FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements/base.txt requirements/base.txt
RUN pip install -r requirements/base.txt

COPY . .

RUN addgroup --system django && adduser --system --ingroup django django
USER django

EXPOSE 8000

CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "honeydj.asgi:application"]
