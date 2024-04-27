# APT-Scope
Source code of applications, utility tools and multiple data sets for the paper "APT-Scope: A Novel Framework to Predict Advanced Persistent Threat Groups from Enriched Heterogeneous Information Network of Cyber Threat Intelligence"

You may find our paper as "APT-Scope: A Novel Framework to Predict Advanced Persistent Threat Groups from Enriched Heterogeneous Information Network of Cyber Threat Intelligence"



## apt_reports_download_app
The source code to download APT Reports from app.box.com.
APT reports are fetched from APTNotes repository and scraped from. app.box.com  [APTNotes](https://github.com/aptnotes/data "APTNotes")
Implemented in Golang, you may add extra features.

## apt_reports_extracted_iocs_files
Extracted IoCs from APT reports served in this repository. Also manually labeled named entities appended to each corresponding file.

## apt_reports_files
Raw APT reports downlaoded are served in this folder.

## graph_data
Graph database backup is server here. You can use folder as docker volume to automatically import HIN data.
Here is how to run Neo4j docker container on your environment.

docker run -d --publish=7474:7474 --publish=7687:7687 --volume={PATH_TO_VOLUME}/CTI_NEO4J_VOLUME/neo4j/data:/data --volume={PATH_TO_VOLUME}/CTI_NEO4J_VOLUME/neo4j/plugins:/plugins --volume={PATH_TO_VOLUME}/CTI_NEO4J_VOLUME/neo4j/logs:/logs --volume={PATH_TO_VOLUME}/CTI_NEO4J_VOLUME/neo4j/conf:/conf --env 'NEO4J_PLUGINS=[\"apoc\",\"graph-data-science\"]' --env NEO4J_apoc_export_file_enabled=true --env NEO4J_apoc_import_file_enabled=true --env NEO4J_apoc_import_file_use__neo4j__config=true --env=NEO4J_AUTH=none neo4j:5.13.0

## ioc_extractor_app
Forked from [https://github.com/malicialab/iocsearcher](https://github.com/malicialab/iocsearcher "https://github.com/malicialab/iocsearcher") 

Sample usage:
iocsearcher -f "Democracy_HongKong_Under_Attack.pdf"

## pg_raw_data
Export of PostgreSQL  databases.
Each file corresponds to an individual PostgreSQL database instance.
Each file contains sql scripts to create database and import data.

**blocklists_db:** Collected IoC blocklists

**ioc_transformations_db:** transformation between IoC served in this database. Possible transformation between IP <-> Domain <-> Subdomain <-> URL divided into different tables.

**scan_db:** Scan results of IoCs are served in this database.

**ssl_db:** SSL certificates and related info like fingerprints and etc. served in this database.

**whois_lookup_db:** Whois lookup results served in this database.

**x_db:** X (Twitter) posts and related info about IoCs served in tihs database. 

## pg_to_graph_app:

Actual business logic that transforms raw CTI data in PostgreSQL databases to the HIN of CTI served in this project. Project is implemented in Golang. 
