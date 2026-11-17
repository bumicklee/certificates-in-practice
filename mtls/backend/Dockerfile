FROM python:3.14.10-slim-trixie
RUN pip install --no-cache-dir cryptography==50.0.2
COPY app.py /app.py
CMD ["python", "-u", "/app.py"]
