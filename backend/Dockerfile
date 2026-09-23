FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
# Vendored security-skill corpora required by the LLM pipelines
# (whitebox: code-audit-main, blackbox: dsh-pentest-skills-main).
COPY code-audit-main ./code-audit-main
COPY dsh-pentest-skills-main ./dsh-pentest-skills-main

EXPOSE 8000

CMD ["uvicorn", "ai2sec_backend.main:app", "--app-dir", "backend", "--host", "0.0.0.0", "--port", "8000"]
