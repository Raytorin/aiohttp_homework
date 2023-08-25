FROM python:3.11

WORKDIR /main_app

COPY ./main_app .

EXPOSE 5000

CMD pip install -r requirements.txt && \
    python models.py && \
    gunicorn -b 0.0.0.0:5000 main:app --worker-class aiohttp.GunicornWebWorker
