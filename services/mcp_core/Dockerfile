FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

COPY services/mcp_core/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

COPY shared /srv/shared
COPY services/mcp_core/app /srv/app

ENV PYTHONPATH=/srv

EXPOSE 8080
CMD ["python", "-m", "app.server"]
