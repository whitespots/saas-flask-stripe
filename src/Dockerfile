FROM python:3
ADD . /opt
WORKDIR /opt
RUN pip install -r requirements.txt
RUN pip install python-dotenv
ENTRYPOINT [ "python", "app.py" ]