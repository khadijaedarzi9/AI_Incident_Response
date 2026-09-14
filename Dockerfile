ARG PYTHON_IMAGE=python:3.12.5-slim
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY app ./app
COPY auditor ./auditor
COPY benchmarks ./benchmarks
COPY demo ./demo
RUN pip install --no-cache-dir .

RUN id -u 10001 >/dev/null 2>&1 || useradd --create-home --uid 10001 ballistic
USER 10001

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
