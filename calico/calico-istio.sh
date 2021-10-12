calicoctl patch FelixConfiguration default --patch '{"spec": {"policySyncPathPrefix": "/var/run/nodeagent"}}'

calicoctl get felixconfiguration default -oyaml


curl https://docs.projectcalico.org/manifests/alp/istio-inject-configmap-1.10.yaml -o calico-istio-inject-configmap.yaml

kubectl patch configmap -n istio-system istio-sidecar-injector --patch "$(cat calico-istio-inject-configmap.yaml)"

#Add Calico authorization services to the mesh
kubectl apply -f https://docs.projectcalico.org/manifests/alp/istio-app-layer-policy-envoy-v3.yaml