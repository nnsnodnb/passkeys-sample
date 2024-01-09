FROM python:3.12.0

COPY . /app
WORKDIR /app

RUN pip install -U pip pipenv && \
    pipenv install --system --deploy --ignore-pipfile

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
