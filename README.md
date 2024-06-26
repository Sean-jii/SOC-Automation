# SOC-Automation
SOC lab that utilized SIEM, SOAR, EDR, 2 Ubuntu servers hosted in the cloud, and a Windows 10 virtual host creating malicious traffic.

By the time you're done, the workflow should looks something like this:
-Mimikatz alert is sent to shuffle 
-Shuffle receives Mimikatz alert
-Extract SHA256 hash from File
-Check the reputation score with VirusTotal 
-Send Details to TheHive to create alert 
-Send Email to the SOC analyst to begin investigation. 


To start we need to:
- Create a Windows 10 VM. 
- Create 2 cloud hosted virtual machines running Ubuntu 22.04 through digital ocean. Each virtual machine is connected to a firewall. 
- Install sysmon onto the Windows 10 VM.

Wazuh VM Setup
- First we "apt-get update && apt get upgrade -y"
- Next we need to run "curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a" to install Wazuh.
- If the credentials are needed we would run "sudo tar -xvf wazuh-install-files.tar"
- After that's all setup you should be able to access Wazuh by searching https://"IP-Address of Wazuh"

TheHive VM Setup 
- Initially, we need to install multiple Cassandra, Elasticsearch, Thehive, and Java. 
- To download all of these, the following commands need to be ran:
Installing TheHive 5

Dependences
apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release

Install Java
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"

Install Cassandra
wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra

Install ElasticSearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch

***OPTIONAL ELASTICSEARCH***
Create a jvm.options file under /etc/elasticsearch/jvm.options.d and put the following configurations in that file.
-Dlog4j2.formatMsgNoLookups=true
-Xms2g
-Xmx2g

Install TheHive
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive

Configuring cassandra 
- We need to change the listen address, RPC address, ports, seed address, and cluster name in /etc/cassandra/cassandra.yaml.
- Be sure to remove old files by running "rm -rf /var/lib/cassandra/*"

Configuring Elasticsearch
- We need to change the cluster name, node name, network host, and remove "node-2" from the "cluster.initial_master_nodes" in /etc/elasticsearch/elasticsearch.yml
- Enable elasticsearch by running "systemctl enable elasticsearch"
- If we can't log into thehive dashboard, we need to create a custom jvm. option file. This file will be located at /etc/elasticsearch/jvm.options.d/jvm.options
- instert:
              "-Dlog4j2.formatMsgNoLookups=true
              -Xms2g
              -Xmx2g" 

Configuring TheHive
- We need to change ownership on the /opt/thp file.
- Run "ls -la /opt/thp" to check ownership
- Run "chown -R thehive:thehive /opt/thp" to change ownership to thehive user and thehive group
- Next we need to make some changes in thehive's configuration file located in /etc/thehive/application.conf
- While in the configuration file, we need to: 
              - Change all hostnames and clusternames under "Database and index Configuration"
              - Change the application.baseURL to "http://TheHive_IP_Address:9000" under "Service Configuration"
              - Comment out both the "scalligraph.modules" at the bottom of the file

Configurations on the Windows10 VM 
- We need to configure our ossec.conf file
- Under "Log Analysis", In our ossec.conf file, we need to insert:
            <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
- be sure to replace this with the old <location>Application</location> <localfile>
- also remove the security and system localfile in ossec.conf
- this asks the ossec.conf file to ingest the sysmon logs

Inside the Wazuh Ubuntu VM
- We need to make some changes in /var/ossec/ossec.conf
- Change <logall>no</logall> to <logall>yes</logall> and <logall_json>no</logall_json> to <logall_json>yes</logall_json>
- In order for Wazuh to start ingesting these logs, we need to change the configuration in filebeat. This will be located in /etc/filebeat/filebeat.yml
- Under filebeat.modules, we need to change "archives: enable: false" to "archives: enable: true"

Inside the Wazuh dashboard. 
- A rule needs to be created
- While creating a customer rule, I inserted this into the bottom of the xml file:

          <rule id="100002" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
    <description>Mimikatz Usage Detected</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>

</group>

-Regardless of if the filename for Mimikatz was changed, the alert will still show up in wazuh since the original filename for Mimikatz was used to setup the alert. 


Settings up SOAR (Shuffle)

Creating a Wazuh-Alerts webhook
- copy the uri of the webhook and insert it into the integration tag found within /var/ossec/etc/ossec.conf
- Change <level>3</level> to <rule_id>100002</rule_id>
- After running Mimikatz, you will see an event in shuffle 
- A regex parse with a sha256 value was created using chatgpt, then it was configured in shuffle

Setting up virusTotal in Shuffle 
- VirusTotal is configured to check the hash and return the values
- Insterted my VirusTotal API key into shuffle

Setting up TheHive in Shuffle 
- Created an additional Service account in TheHive for SOAR implementation
- Pasted the url for https://thehive-IP-address:9000 and api key into shuffle
- set the rule as 100002
- set severity as 2
- set Pap as 2
- set source as Wazuh
- set sourceref as 100002
- set statys as new
- summary is set as "Mimikatz activity detection on host computer, process ID and, the command line 
- set tag as MITRE tag [*T1003*] (Credential stuffing)
- set title as Mimikatz Detected
- set tlp as 2
- set type as internet

Settings up email in Shuffle 
- Add the Email application to Shuffle workflow
- Entered the recipients for who receives the email 
- Filled out the subject and body fields to determine what information is sent via email. 









