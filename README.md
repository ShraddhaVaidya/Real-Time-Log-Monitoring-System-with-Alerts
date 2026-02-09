Real-Time Log Monitoring System with Alerts 

A scalable and containerized real-time log monitoring and alerting system that continuously collects, processes, visualizes, and alerts on Windows Event Logs using Python, Docker, and the ELK Stack. 

Project Overview 

Modern systems generate massive volumes of logs containing critical information related to system health, performance, and security. Manual analysis of these logs is inefficient and error-prone. 

This project provides a real-time, automated, and cost-effective log monitoring solution with instant email alerts for critical events, leveraging open-source technologies. 

Key Features 

- ✅ Real-time Windows Event Log collection   

- ✅ Multi-threaded Python-based log collector   

- ✅ Structured JSON log processing   

- ✅ Centralized log storage using Elasticsearch   

- ✅ Interactive dashboards using Kibana   

- ✅ Automated email alerts for critical events   

- ✅ Alert deduplication and rate-limiting   

- ✅ Fault-tolerant design with retry & fallback mechanisms   

- ✅ Fully containerized using Docker & Docker Compose   

Tech Stack 

Component :Technology  

Log Collection :Python (`win32evtlog`)  

Log Processing : Logstash  

Storage :Elasticsearch  

Visualization :Kibana  

Alerting :SMTP (Email Alerts)  

Containerization : Docker, Docker Compose  

OS :Windows  

System Architecture 

Workflow: 

1. Windows Event Logs are captured using Python 

2. Logs are processed using a multi-threaded queue 

3. Logs are converted to structured JSON 

4. Logstash ingests logs into Elasticsearch 

5. Kibana visualizes logs in real time 

6. Critical events trigger automated email alerts 

 

 Project Structure 

```bash 

Real-Time-Log-Monitoring-System/ 

│ 

├── log_collector/ 

│   ├── collector.py 

│   ├── alert_manager.py 

│   └── config.py 

│ 

├── logstash/ 

│   └── logstash.conf 

│ 

├── docker/ 

│   ├── docker-compose.yml 

│   └── Dockerfile 

│ 

├── dashboards/ 

│   └── kibana_visualizations.json 

│ 

├── screenshots/ 

│ 

├── README.md 

└── requirements.txt 
