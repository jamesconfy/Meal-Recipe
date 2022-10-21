FROM python:3.10.2-alpine

WORKDIR /app

COPY . /app

RUN pip install --upgrade pip && pip install -r requirements.txt

EXPOSE 8080

CMD [ "gunicorn", "--bind", "0.0.0.0:8080", "run:app" ]