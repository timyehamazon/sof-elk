oss-graylog-forensics Virtual Machine How To Build By YourSelf
=======

Build on debian 12

apt-get update && apt-get -y install lsb-release ca-certificates curl gnupg2
curl -o- https://artifacts.opensearch.org/publickeys/opensearch.pgp | sudo gpg --dearmor --batch --yes -o /usr/share/keyrings/opensearch-keyring
echo "deb [signed-by=/usr/share/keyrings/opensearch-keyring] https://artifacts.opensearch.org/releases/bundle/opensearch/2.x/apt stable main" | sudo tee /etc/apt/sources.list.d/opensearch-2.x.list

export OPENSEARCH_INITIAL_ADMIN_PASSWORD=yourpassword
apt install opensearch

sudo systemctl daemon-reload
sudo systemctl enable opensearch.service

/etc/opensearch/opensearch.yml

```
cluster.name: oss-graylog-awsforensics
plugins.security.disabled: true

assistant.chat.enabled: true
```

wget https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/2.13.0/opensearch-dashboards-2.13.0-linux-x64.deb
sudo dpkg -i opensearch-dashboards-2.13.0-linux-x64.deb
sudo systemctl enable opensearch-dashboards.service

OpenSearch Dashboards remove plugins
```
/usr/share/opensearch-dashboards/bin/opensearch-dashboards-plugin remove securityDashboards --allow-root
```

Remove security related in opensearch-dashboard.yml

sudo systemctl start opensearch.service
sudo systemctl start opensearch-dashboards.service

Install graylog Open
```
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' >> sudo /etc/sysctl.conf

curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | \
   sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg \
   --dearmor
echo "deb [ signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] http://repo.mongodb.org/apt/debian bullseye/mongodb-org/7.0 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt update

sudo wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb
sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2_amd64.deb

sudo apt-get install -y mongodb-org=7.0.7 mongodb-org-database=7.0.7

sudo systemctl start mongod && sudo systemctl enable mongod

wget https://packages.graylog2.org/repo/packages/graylog-5.2-repository_latest.deb
sudo dpkg -i graylog-5.2-repository_latest.deb

sudo apt update
sudo apt install -y graylog-server pwgen

sudo sed -i "s/password_secret =.*$/password_secret = $(pwgen -N 1 -s 96)/g" /etc/graylog/server/server.conf
read -s -p "Enter Password: " PASSWORD && echo && PASSWORD=$(echo -n "$PASSWORD" | sha256sum | cut -d" " -f1) && sudo sed -i "s/root_password_sha2 =.*$/root_password_sha2 = $PASSWORD/g" /etc/graylog/server/server.conf
# here set awsforensics as password

sudo sed -i "s@#root_timezone = UTC@root_timezone = Asia/Taipei@g" /etc/graylog/server/server.conf
sudo sed -i "s@#http_bind_address = 127.0.0.1:9000@http_bind_address = 0.0.0.0:9000@g" /etc/graylog/server/server.conf
sudo sed -i "s/allow_highlighting = false/allow_highlighting = true/g" /etc/graylog/server/server.conf
sudo sed -i 's/#elasticsearch_hosts = http:\/\/node1:9200,http:\/\/user:password@node2:19200/elasticsearch_hosts = http:\/\/127.0.0.1:9200/g' /etc/graylog/server/server.conf


sudo systemctl daemon-reload
sudo systemctl restart graylog-server
sudo systemctl enable graylog-server

sudo tail -f /var/log/graylog-server/server.log
# To get password and login graylog
```

sudo apt install logstash, filebeat

sudo ./logstash-plugin install logstash-input-relp
sudo ./logstash-plugin install logstash-input-google_pubsub
sudo ./logstash-plugin install logstash-filter-tld
sudo ./logstash-plugin install logstash-filter-rest
sudo ./logstash-plugin install logstash-filter-json_encode
sudo ./logstash-plugin install logstash-output-opensearch

Copy geoip mmdb sof-elk to oss-graylog-forensics ( /usr/share/GeoIP )

Fix logstash config 
Example : /etc/logstash/conf.d/9901-output-aws.conf

```
# SOF-ELK® Configuration File
# (C)2021 Lewes Technology Consulting, LLC
#
# This file contains outputs for AWS logs

output {
  if [type] == "aws" {
    opensearch {
      index => "aws-%{+YYYY.MM}"
      template => "/usr/local/sof-elk/lib/elasticsearch-aws-template.json"
      template_name => "aws"
      template_overwrite => true
      ecs_compatibility => "disabled"
    }
  }
}
```

