<oss-graylog-forensics VM beta>

Modify from SOF-ELK (Great thanks!)

Replace ElasticSearch with OpenSearch (Has free sigma rules functionality)

VM contain pre-installed SOF-ELK with opensearch(not elasticsearch) and graylog open

VM can be found on [OSSVM_DOWNLOAD](OSSVM_DOWNLOAD.md) ( better have 6GB ram and free 40GB disk )

How to build by yourself [OSSVM_BUILD](OSSVM_BUILD.md)

Conference talk material can be found here : 

<https://cybersec.ithome.com.tw/2024/en/speaker-page/1343>

====== Original SOF-ELK message 

https://github.com/philhagen/sof-elk/issues/301 

[](SOFELK-README.md)

# SOF-ELK® Configuration Files

This repository contains the configuration and support files for the SOF-ELK® VM Appliance.

SOF-ELK® is a “big data analytics” platform focused on the typical needs of computer forensic investigators/analysts and information security operations personnel.  The platform is a customized build of the open source Elastic stack, consisting of the Elasticsearch storage and search engine, Logstash ingest and enrichment system, Kibana dashboard frontend, and Elastic Beats log shipper (specifically filebeat).  With a significant amount of customization and ongoing development, SOF-ELK® users can avoid the typically long and involved setup process the Elastic stack requires.  Instead, they can simply download the pre-built and ready-to-use SOF-ELK® virtual appliance that consumes various source data types (numerous log types as well as NetFlow), parsing out the most critical data and visualizing it on several stock dashboards.  Advanced users can build visualizations the suit their own investigative or operational requirements, optionally contributing those back to the primary code repository.

The SOF-ELK® platform was initially developed for SANS FOR572, Advanced Network Forensics and Analysis, and is now used in several other SANS courses, with additional course integrations being considered.  Most importantly, the platform is also distributed as a free and open source resource for the community at large, without a specific course requirement or tie-in required to use it.

More details about the pre-packaged VM are available here: <https://for572.com/sof-elk-readme>.

[readme](https://for572.com/sof-elk-readme).
