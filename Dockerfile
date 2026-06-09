#FROM rml1977/lab-h1:latest
FROM debian:12-slim 

#COPY ./uoscore-uedhoc /root/uoscore-uedhoc 

ENV SRC_PATH /home/uedhoc
WORKDIR $SRC_PATH

RUN apt-get update
RUN apt-get check
RUN apt-get dist-upgrade -y
RUN apt-get install -y vim iputils-ping rsyslog tcpdump net-tools procps git make gcc g++ python3 python3-pip
RUN apt-get install -y pkg-config libssl-dev libdbus-1-dev libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libtalloc-dev
#RUN service rsyslog restart	

# Install required Python packages
RUN pip3 install --no-cache-dir --break-system-packages regex cbor2 pyyaml  

CMD tail -f /dev/null
