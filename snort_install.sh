#/bin/bash
# Baseado na documentação oficial em:
# https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/000/122/original/Snort_2.9.9.x_on_Ubuntu_14-16.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIXACIED2SPMSC7GA%2F20200517%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20200517T135338Z&X-Amz-Expires=172800&X-Amz-SignedHeaders=host&X-Amz-Signature=dfe1ecdfa262be1528bd457454e81cca2be4d8ef8434f086db012a9a984848a5

echo "Install Snort on Ubuntu 16.04"

sudo apt update
sudo apt upgrade -y
sudo apt install -y build-essential libpcap-dev libpcre3-dev libdumbnet-dev \
                    bison flex zlib1g-dev liblzma-dev openssl libssl-dev \
                    autoconf libtool pkg-config unzip luajit libluajit-5.1-dev \
                    libluajit-5.1-common libluajit-5.1-2

cd /tmp
wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz
wget https://www.snort.org/downloads/snort/snort-2.9.16.tar.gz

tar xvzf daq-2.0.7.tar.gz
tar xvzf snort-2.9.16.tar.gz

# Compile and install daq
cd daq-2.0.7
./configure && make && sudo make install

# Compile and install snort
cd ../snort-2.9.16
./configure --enable-sourcefire && make && sudo make install

sudo ldconfig

sudo ln -s /usr/local/bin/snort /usr/sbin/snort

# Create the snort user and group:
sudo groupadd snort
sudo useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort

# Create the Snort directories:
sudo mkdir /etc/snort
sudo mkdir /etc/snort/rules
sudo mkdir /etc/snort/rules/iplists
sudo mkdir /etc/snort/preproc_rules
sudo mkdir /usr/local/lib/snort_dynamicrules
sudo mkdir /etc/snort/so_rules

# Create some files that stores rules and ip lists
sudo touch /etc/snort/rules/iplists/black_list.rules
sudo touch /etc/snort/rules/iplists/white_list.rules
sudo touch /etc/snort/rules/local.rules
sudo touch /etc/snort/sid-msg.map

# Create our logging directories:
sudo mkdir /var/log/snort
sudo mkdir /var/log/snort/archived_logs

# Adjust permissions:
sudo chmod -R 5775 /etc/snort
sudo chmod -R 5775 /var/log/snort
sudo chmod -R 5775 /var/log/snort/archived_logs
sudo chmod -R 5775 /etc/snort/so_rules
sudo chmod -R 5775 /usr/local/lib/snort_dynamicrules

# Change Ownership on folders:
sudo chown -R snort:snort /etc/snort
sudo chown -R snort:snort /var/log/snort
sudo chown -R snort:snort /usr/local/lib/snort_dynamicrules

# Copy configuration file
cd /tmp/snort-2.9.16/etc/
sudo cp *.conf* /etc/snort
sudo cp *.map /etc/snort
sudo cp *.dtd /etc/snort

cd /tmp/snort-2.9.16/src/dynamic-preprocessors/build/usr/local/lib/snort_dynamicpreprocessor/
sudo cp * /usr/local/lib/snort_dynamicpreprocessor/

cd /tmp
wget https://github.com/tjota/snort_conf/archive/master.zip
unzip master.zip
sudo mv snort_conf-master/snort.conf /etc/snort/snort.conf


# Create Startup script - Systemd
sudo touch /lib/systemd/system/snort.service
sudo echo "[Unit]
Description=Snort NIDS Daemon
After=syslog.target network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/snort -q -u snort -g snort -c /etc/snort/snort.conf -i enp0s8
[Install]
WantedBy=multi-user.target" > /lib/systemd/system/snort.service

sudo systemctl enable snort
sudo systemctl start snort