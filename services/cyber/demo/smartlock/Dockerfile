FROM python:3.12-slim
RUN useradd -r -u 10002 lock
WORKDIR /app
COPY smartlock.py /app/smartlock.py
USER lock
EXPOSE 8080
CMD ["python", "smartlock.py"]
