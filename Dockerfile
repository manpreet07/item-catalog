FROM ubuntu:latest
MAINTAINER Manpreet Singh "manpreet1107@gmail.com"
RUN apt-get update -y
RUN apt-get install -y python-pip python-dev build-essential
COPY . /item-catalog
WORKDIR /item-catalog
RUN pip install -r requirements.txt
ENTRYPOINT ["python"]
CMD ["application.py"]