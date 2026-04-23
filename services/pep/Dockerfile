FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

COPY services/pep/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

COPY shared /srv/shared
COPY services/pep/app /srv/app

ENV PYTHONPATH=/srv

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
