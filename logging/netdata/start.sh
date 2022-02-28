# helm repo add netdata https://netdata.github.io/helmchart/

helm -n hsnlab install netdata netdata/netdata -f lfdia/logging/netdata/netdata_values.yml

kubectl port-forward service/netdata 30563:19998
