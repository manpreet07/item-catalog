FROM python:2.7

ADD . /item-catalog

WORKDIR /item-catalog

RUN pip install -r requirements.txt

COPY application.py .

CMD ["python", "./application.py"]