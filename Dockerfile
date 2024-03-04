FROM python:3.10

RUN apt-get update && apt-get install -y nmap masscan python3-pip sed

RUN apt-get update && apt-get install -y wget
RUN wget https://github.com/sullo/nikto/archive/refs/tags/2.5.0.tar.gz \
    && tar -zxvf 2.5.0.tar.gz \
    && mv nikto-2.5.0 /opt/nikto \
    && ln -s /opt/nikto/nikto-2.5.0/program/nikto.pl /usr/local/bin/nikto

ENV PATH="opt/nikto/nikto-2.5.0/program/:${PATH}"

WORKDIR /media/sf_Kali-linux/LastSborka/

COPY . /media/sf_Kali-linux/LastSborka/

RUN pip install -r requirements.txt

CMD python /media/sf_Kali-linux/LastSborka/main.py
