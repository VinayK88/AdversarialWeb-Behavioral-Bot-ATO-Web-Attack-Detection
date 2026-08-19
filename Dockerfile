FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY adversarialweb ./adversarialweb
COPY dashboard ./dashboard

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e '.[dashboard]'

EXPOSE 8501
HEALTHCHECK CMD python -c "import adversarialweb; print(adversarialweb.__version__)" || exit 1
CMD ["streamlit", "run", "dashboard/app.py", "--server.address=0.0.0.0", "--server.port=8501"]
