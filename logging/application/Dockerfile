FROM python:3.8-slim-buster
COPY ./log_test_app.py .
COPY ./requirements.txt .
RUN pip3 install -r requirements.txt
RUN mkdir ./logs
ENV PYTHONUNBUFFERED 1
ENV PERIOD 30
ENV LOG_FORMAT plain
ENV PROCESSOR unprocessed
ENV STACK elastic
ENV FINISH_AFTER_SEC 60
CMD ["python3", "log_test_app.py"]