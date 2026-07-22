FROM python:3.11.9-slim-bookworm@sha256:8fb099199b9f2d70342674bd9dbccd3ed03a258f26bbd1d556822c6dfc60c317

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/opt/runtime

WORKDIR /opt/runtime

COPY agent_image/requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir --requirement requirements.txt \
    && groupadd --gid 10001 sandbox \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin sandbox

COPY src/sandbox ./sandbox
COPY agent_image/app ./app

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=2s --timeout=1s --retries=10 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=1)"

CMD ["python", "-m", "uvicorn", "app.server:app", "--host", "127.0.0.1", "--port", "8080", "--no-access-log"]
