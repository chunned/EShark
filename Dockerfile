FROM python:3.12-bookworm

COPY . /EShark
WORKDIR /EShark

RUN pip3 install -r requirements.txt
RUN apt-get update && apt-get install -y iproute2 tshark
RUN chmod +x eshark_run.sh

CMD ["./eshark_run.sh"]
