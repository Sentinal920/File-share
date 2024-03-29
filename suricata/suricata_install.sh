sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update -y
sudo apt-get install curl suricata -y
cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz
sudo tar -xvzf emerging.rules.tar.gz && sudo mv rules/*.rules /etc/suricata/rules/
sudo chmod 640 /etc/suricata/rules/*.rules

wget -O /etc/suricata/suricata.yaml https://raw.githubusercontent.com/Sentinal920/File-share/main/suricata/suricata.yaml

# Add your local ip [ifconfig/ip a]
ip=192.168.182.151/24
sed -i "s|CHANGE_MY_IP|$ip|g" /etc/suricata/suricata.yaml

# Add your adaptername [ifconfig/ip a]
adapter="ens33"
sed -i "s|CHANGE_MY_ADAPTER|$adapter|g" /etc/suricata/suricata.yaml

sudo systemctl restart suricata
