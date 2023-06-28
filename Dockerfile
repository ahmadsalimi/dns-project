FROM python:3.10

RUN apt-get update && apt-get install -y lsb-release gettext wget ca-certificates && apt-get clean all

RUN echo "deb http://apt.postgresql.org/pub/repos/apt/ $(lsb_release -cs)-pgdg main" >>  /etc/apt/sources.list.d/pgdg.list
RUN sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt/ $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
RUN wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -
RUN apt-get update
RUN apt-get install -y postgresql-client

WORKDIR /app/

COPY requirements.txt /tmp/
RUN pip install -r /tmp/requirements.txt

COPY src/ ./

COPY entrypoint.sh ./

ENTRYPOINT ["./manage.py", "grpcrunserver", "--settings", "e2e_messenger.server_settings"]
