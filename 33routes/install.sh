#!/bin/bash

sudo apt update
sudo apt upgrade -y
sudo apt install -y \
    git \
    make

# 
# nginx
# 
sudo apt update
sudo apt install nginx -y

rm /etc/nginx/nginx.conf
cp nginx.conf /etc/nginx/nginx.conf
cp 33routes.ru.crt /etc/ssl/33routes.ru.crt
cp 33routes.ru.key /etc/ssl/33routes.ru.key
cp ca.crt /etc/ssl/ca.crt

sudo useradd -r nginx
sudo systemctl enable nginx
sudo systemctl start nginx

# 
# docker
# 
sudo apt update
sudo apt install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common

sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) \
    signed-by=/etc/apt/keyrings/docker.asc] \
    https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

sudo systemctl enable docker
sudo systemctl start docker

# 
# portainer
# 
docker volume create portainer_data
docker run -d \
    -p 8000:8000 \
    -p 9443:9443 \
    --name=portainer \
    --restart=always \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v portainer_data:/data \
    portainer/portainer-ce:latest

# 
# jenkins
# 
# docker run -d \
#     -p 9090:8080 \
#     -p 50000:50000 \
#     --name=jenkins \
#     --restart=always \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     -v jenkins_home:/var/jenkins_home \
#     -e JENKINS_OPTS="--prefix=/admin/jenkins" \
#     jenkins/jenkins:alpine3.20-jdk21
# # sudo usermod -aG docker jenkins

sudo apt update
sudo apt install -y openjdk-17-jdk

sudo wget -O /usr/share/keyrings/jenkins-keyring.asc \
    https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
echo "deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc]" \
    https://pkg.jenkins.io/debian-stable binary/ | \
    sudo tee /etc/apt/sources.list.d/jenkins.list > /dev/null
sudo apt update
sudo apt install -y jenkins
sudo systemctl enable jenkins
sudo systemctl start jenkins
# /usr/lib/systemd/system/jenkins-service

# vless x-ui
git clone https://github.com/MHSanaei/3x-ui.git && \
cd 3x-ui && \
docker run -itd \
    -e XRAY_VMESS_AEAD_FORCED=false \
    -v $PWD/db/:/etc/x-ui/ \
    -v $PWD/cert/:/root/cert/ \
    --network=host \
    --restart=unless-stopped \
    --name=3x-ui \
    ghcr.io/mhsanaei/3x-ui:latest
