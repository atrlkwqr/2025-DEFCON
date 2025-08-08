```
docker build -t atrlkwqr/pcap-analyzer .
docker push atrlkwqr/pcap-analyzer


docker pull atrlkwqr/pcap-analyzer
docker run -d -p 5000:5000 atrlkwqr/pcap-analyzer
```
