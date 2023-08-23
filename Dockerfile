# Use Kali Rolling release latest as the main base image
# FROM debian:bookworm
FROM python:3.11-bookworm
# FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Adding Go paths to the PATH environment variable
ENV PATH=$PATH:/usr/local/go/bin
ENV PATH=$PATH:/root/go/bin

RUN mkdir /application

VOLUME /application /src

WORKDIR /application

# Update package index and install kali-linux-large without recommended packages
# Remove junk files and apt cache
RUN apt-get update \
    && apt-get -y --no-install-recommends install bind9-dnsutils sudo nmap zip unzip gcc musl-dev \
    && apt-get clean; rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/share/doc/*

COPY ./requirements.txt .

RUN pip3 install --upgrade pip

RUN pip3 install -r requirements.txt

# Install Go 1.20.7
RUN wget https://go.dev/dl/go1.20.7.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go*.tar.gz && \
    rm go*.tar.gz

# Project Discovery's tools.
RUN go install github.com/xm1k3/cent@latest && \
    go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/tomnomnom/fff@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/tomnomnom/waybackurls@latest
    
# Clone git repositories
RUN git clone 'https://github.com/projectdiscovery/nuclei-templates' /nuclei-templates \
    && cent init \
    && cent -p cent-nuclei-templates -k

ENTRYPOINT ["python3"]

