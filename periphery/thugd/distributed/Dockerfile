FROM thughoneyclient/thug:version-4.8

USER root
ENV DEBIAN_FRONTEND=noninteractive
RUN echo 'APT::Get::Assume-Yes "true";' >> /etc/apt/apt.conf

ADD . /home/thug/distributed

USER thug
ENV USER thug

WORKDIR /home/thug/distributed
#RUN mkdir -p logs
RUN pip3 install -r requirements.txt
CMD ["python3", "./thugd.py", "--config", "/home/thug/distributed/config.yml"]
