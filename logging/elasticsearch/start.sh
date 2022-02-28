wait=4m

echo "Starting Elasticsearch"
echo "Starting master nodes"
helm -n hsnlab install es-master elastic/elasticsearch -f ~/lfdia/logging/elasticsearch/master_values.yml --version 7.8.1
echo Waiting $wait
sleep $wait
echo "Starting data nodes"
helm -n hsnlab install es-data elastic/elasticsearch -f ~/lfdia/logging/elasticsearch/data_values.yml --version 7.8.1
echo Waiting $wait
sleep $wait
echo "Starting ingest nodes"
helm -n hsnlab install es-ingest elastic/elasticsearch -f ~/lfdia/logging/elasticsearch/ingest_values.yml --version 7.8.1
echo "Starting Kibana"
helm -n hsnlab install kibana elastic/kibana -f ~/lfdia/logging/elasticsearch/kibana_values.yml --version 7.8.1
