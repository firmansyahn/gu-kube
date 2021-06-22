#!/usr/bin/env bash

#Change variable below
CLUSTER_NAME=nebula
CLUSTER_DOMAIN=moratel.id
HOST_FQDN=falcon1.nebula.moratel.id

#Do not change if possible
KUBE_VERSION=1.21
KUBE_SVC_SUBNET=172.24.24.0/24
KUBE_POD_SUBNET=172.25.0.0/16
KUBE_TMPDIR=$HOME/my-kube
#host_wanip=$(/sbin/ip -o -4 addr list $host_wanif | awk '{print $4}' | cut -d/ -f1)
HOST_VIF_NAME=virbr2
HOST_VIF_IP=172.24.25.1
CGROUP_DRIVER=systemd       #systemd, cgroupfs
HELM_INSTALL=yes
CALICO_INSTALL=yes
DNSUTILS_INSTALL=yes
METALLB_INSTALL=yes
METALLB_VERSION=0.10.2
METALLB_ADDRESS_RANGE=172.24.25.111-172.24.25.250
NGINX_INGRESS_INSTALL=yes
KUBE_DASHBOARD_INSTALL=yes
CERT_MANAGER_INSTALL=yes
PROMETHEUS_INSTALL=yes
GRAFANA_INSTALL=yes

firewalld_rules() {
    if [ ! `systemctl -q is-active firewalld` ]; then
        printf '%s\n' "[system] Starting \"firewalld\"" >&2
        systemctl start firewalld
    fi

    firewall-cmd --permanent --remove-service=dhcpv6-client
    firewall-cmd --permanent --add-service={http,https,snmp,dns}
    firewall-cmd --permanent --add-port=2379-2380/tcp
    firewall-cmd --permanent --add-port=6443/tcp #Kubernetes API server
    firewall-cmd --permanent --add-port=8001/tcp #kube-proxy kube-dashboard
    firewall-cmd --permanent --add-port=8080/tcp
    firewall-cmd --permanent --add-port=8443/tcp
    firewall-cmd --permanent --add-port=10250/tcp #Kubelet API
    firewall-cmd --permanent --add-port=10251/tcp #kube-scheduler
    firewall-cmd --permanent --add-port=10252/tcp #kube-controller-manager
    firewall-cmd --permanent --add-port=30000-32767/tcp #nodePort range
    firewall-cmd --permanent --add-port=30000-32767/udp #nodePort range
    firewall-cmd --permanent --zone=public --add-rich-rule='rule protocol value="esp" accept'
    firewall-cmd --permanent --zone=public --add-rich-rule='rule protocol value="ah" accept'
    firewall-cmd --permanent --zone=public --add-port=500/udp
    firewall-cmd --permanent --zone=public --add-port=4500/udp
    firewall-cmd --permanent --zone=public --add-service=ipsec
    #firewall-cmd --permanent --zone=public --add-rich-rule "rule family=ipv4 source address=$HOST_VIF_IP/32 accept" #Access pods using NodePort
    firewall-cmd --permanent --zone=public --add-rich-rule "rule family=ipv4 source address=${KUBE_SVC_SUBNET} accept"
    firewall-cmd --permanent --zone=public --add-rich-rule "rule family=ipv4 destination address=${KUBE_SVC_SUBNET} accept"
    firewall-cmd --permanent --zone=public --add-masquerade
    firewall-cmd --reload
}

ufw_rules() {
    cat <<EOF | tee ${KUBE_TMPDIR}/ufw.sed >/dev/null
#   ufw-before-forward
#
# nat Table rules
*nat
:POSTROUTING ACCEPT [0:0]

# Forward traffic from eth1 through $wan_if.
-A POSTROUTING -o $wan_if -j MASQUERADE

# don't delete the 'COMMIT' line or these nat table rules won't be processed
COMMIT
EOF

    printf '\n%s\n' "[ufw] Patching UFW default config" >&2
    if [ -f /etc/default/ufw ]; then sed -i 's/^DEFAULT_FORWARD_POLICY="DROP"$/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw; fi
    if [ -f /etc/ufw/before.rules ]; then sed -i 's@\#   ufw-before-forward@cat < ${KUBE_TMPDIR}/ufw.sed@e' /etc/ufw/before.rules; fi

    ufw_allow=(http https snmp dns ipsec 2379:2380/tcp 6443/tcp 8001/tcp 8080/tcp 8443/tcp 10250:10252/tcp 30000:32767/tcp 30000:32767/udp 500/udp 4500/udp)
    ufw_allow_if=(${HOST_VIF_NAME} kube-ipvs0)

    printf '%s\n' "[ufw] Applied UFW rules" >&2
    for i in "${ufw_allow[@]}"; do ufw allow $i; done
    for i in "${ufw_allow_if[@]}"; do ufw allow in on $i; done

    printf '%s\n' "[ufw] Enabling UFW" >&2
    ufw --force enable
}

trim_quotes() {
    trim_output="${1//\'}"
    trim_output="${trim_output//\"}"
    printf "%s" "$trim_output"
}

get_distro() {
    [[ $distro ]] && return

    if [[ -f /etc/os-release || -f /usr/lib/os-release || -f /etc/lsb-release ]]; then
        for file in /etc/lsb-release /usr/lib/os-release /etc/os-release; do source "$file" && break; done
    fi

    distro="${ID:-${DISTRIB_ID}}"
    distro=$(trim_quotes "$distro")
    distro_ver="${VERSION_ID:-${DISTRIB_RELEASE}}"
    distro_major_ver=$(echo -n "${distro_ver}" | awk -F. '{print $1}')

    case $distro in
        almalinux|rhel|centos|fedora)
            distro_name=CentOS
            distro_rel=${distro_major_ver}
        ;;
        ubuntu|Ubuntu)
            distro_name=Ubuntu
            distro_rel=${distro_ver}
        ;;
    esac
}

run_svc() {
    if [ -f "$2" ]; then
        printf '\n%s\n' "Restarting the $1." >&2
        sudo systemctl restart $1
    else
        printf '%s\n' "Starting the $1." >&2
        sudo systemctl enable --now $1
    fi
}

kubelet_cgroup_patch() {
    printf '%s\n' "[kubelet] Writing kubelet patch file" >&2
    if [ ! -d "/etc/systemd/system/kubelet.service.d" ]; then mkdir -p /etc/systemd/system/kubelet.service.d; fi
    cat <<EOF | tee /etc/systemd/system/kubelet.service.d/11-cgroups.conf &>/dev/null
[Service]
CPUAccounting=true
MemoryAccounting=true
IOAccounting=true
BlockIOAccounting=true
EOF

    systemctl daemon-reload
}

kubeadm_config() {
    printf '%s\n' "[kubeadm] Writing kubeadmin-config.yaml manifest file" >&2
    cat <<EOF | tee ${KUBE_TMPDIR}/kubeadm-config.yaml &>/dev/null
apiVersion: kubeadm.k8s.io/v1beta2
kind: InitConfiguration
nodeRegistration:
# name: "logankube"
  criSocket: /run/crio/crio.sock
  kubeletExtraArgs:
    cgroup-driver: ${CGROUP_DRIVER}
localAPIEndpoint:
  advertiseAddress: $HOST_VIF_IP
  bindPort: 6443
---
apiVersion: kubeadm.k8s.io/v1beta2
kind: ClusterConfiguration
clusterName: $CLUSTER_NAME
controlPlaneEndpoint: ${HOST_VIF_IP}:6443
networking:
  dnsDomain: $CLUSTER_NAME.$CLUSTER_DOMAIN
  podSubnet: $KUBE_POD_SUBNET
  serviceSubnet: $KUBE_SVC_SUBNET
apiServer:
  certSANs:
  - $HOST_VIF_IP
  - $host_wanip
  - $HOST_FQDN
  extraArgs:
    bind-address: ${HOST_VIF_IP}
scheduler:
  extraArgs:
    address: ${HOST_VIF_IP}
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
cgroupDriver: ${CGROUP_DRIVER}
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: ipvs
ipvs:
  strictARP: true
EOF
}

get_wanif() {
#   Get WAN Interface, assume interface used for default route
    host_wanif=$(/sbin/ip -o -4 route show to default | awk '{print $5}')
    host_wanip=$(/sbin/ip -o -4 addr list $host_wanif | awk '{print $4}' | cut -d/ -f1)
    #host_wanip=ip a | sed -rn '/: '"$host_wanif"':.*state UP/{N;N;s/.*inet (\S*).*/\1/p}'
}

install_vif() {
    printf '\n%s\n' "[system] Creating dummy interface" >&2

    case ${distro_name} in
        centos|Centos|CentOS)
            nmcli connection add type bridge autoconnect yes con-name ${HOST_VIF_NAME} ifname ${HOST_VIF_NAME}
            nmcli connection add type dummy con-name ${HOST_VIF_NAME}-nic ifname ${HOST_VIF_NAME}-nic master ${HOST_VIF_NAME}
            nmcli connection modify ${HOST_VIF_NAME} bridge.stp no connection.zone trusted
            nmcli connection modify ${HOST_VIF_NAME} ipv4.method manual ipv4.addresses ${HOST_VIF_IP}/32 ipv4.dns-search ${CLUSTER_NAME}.${CLUSTER_DOMAIN}
            nmcli connection up ${HOST_VIF_NAME}
            nmcli connection show
        ;;
        ubuntu|Ubuntu)
            cat <<EOF | tee /etc/netplan/01-kubernetes.yaml &>/dev/null
network:
  version: 2
  renderer: networkd
  bridges:
    ${HOST_VIF_NAME}:
      dhcp6: no
      accept-ra: no
      addresses:
      - ${HOST_VIF_IP}/32
      interfaces: []
      nameservers:
        search: [$CLUSTER_NAME.$CLUSTER_DOMAIN]
      parameters:
        stp: false
        forward-delay: 0
EOF
            netplan apply
            systemctl restart system-networkd
        ;;
    esac
}

get_pod() {
    pod=$1
    [ -z "${pod}" ] && echo "ERROR: Pod name not passed" && exit 1

    # ns is namespace. Defaults to 'default'
    ns=$2
    [ -z "${ns}" ] && ns='default'

    # Return code
    pod_result=1

    p=$(kubectl get pods --namespace ${ns} | grep "${pod}")

    if [ -n "${p}" ]; then
        ## Uncomment to see output later down the script
        pod_name=$(echo -n "${p}" | awk '{print $1}')
        pod_ready=$(echo -n "${p}" | awk '{print $2}')
        pod_ready_actual=$(echo -n "${pod_ready}" | awk -F/ '{print $1}')
        pod_ready_max=$(echo -n "${pod_ready}" | awk -F/ '{print $2}')
        pod_status=$(echo -n "${p}" | awk '{print $3}')

        #echo "Pod ${pod_name}; ready is ${ready}; ready_actual is ${ready_actual}; ready_max is ${ready_max}; status is ${status}"
        if [ "${pod_ready_actual}" == "${pod_ready_max}" ] && [ "${pod_status}" == "Running" ]; then
            pod_result=0
            echo "[${pod_name}] Pod ready is ${pod_ready}; ready_actual is ${pod_ready_actual}; ready_max is ${pod_ready_max}; status is ${pod_status}"
        fi
#    else
#        printf '%s\n\r' "[${pod}] Pod ${pod} is not exist." >&2
    fi
}

check_pod() {
    n=0
    j=${3:-12}
    printf '%s\n' "[system] Waiting \"$2/$1\" pod to run" >&2
    while [[ ${n} -le ${j} ]]; do
        get_pod $1 $2
        if [[ ${pod_result} == 1 ]] && [[ ${n} -eq ${j} ]]; then
            printf '%s\n' "[$1] Pod is not available or refused to run" >&2
            printf '%s\n' "[$1] ${p}." >&2
            break 1
        elif [[ ${pod_result} == 1 ]]; then
            sleep 5
            ((n++))
        elif [[ ${pod_result} == 0 ]]; then
            break 1
        fi
    done
}

install_crio() {
    case ${distro_name} in
        centos|Centos|CentOS)
            printf '%s\n' "[system] Downloading cri-o repo file" >&2
            curl -fsSL -o /etc/yum.repos.d/devel:kubic:libcontainers:stable.repo https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/${distro_name}_${distro_rel}/devel:kubic:libcontainers:stable.repo
            curl -fsSL -o /etc/yum.repos.d/devel:kubic:libcontainers:stable:cri-o:${KUBE_VERSION}.repo https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable:cri-o:${KUBE_VERSION}/${distro_name}_${distro_rel}/devel:kubic:libcontainers:stable:cri-o:${KUBE_VERSION}.repo

            printf '%s\n' "[system] Install cri-o cri-tools conntrack iproute-tc." >&2
            dnf -y -q module enable container-tools
            dnf -y -q install cri-o cri-tools conntrack-tools iproute-tc

            RUNC_RPM=$(curl -sL https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/CentOS_8_Stream/x86_64/ | \
            grep -o -h -m 1 'runc-[0-9]\.[0-9]\.[0-9]-[[:digit:]]\{1,3\}\.rc[[:digit:]]\{1,2\}\.el8\.[0-9]\.[0-9]\.x86_64\.rpm' | head -1)

            printf '\n%s\n' "[crio] Upgrading runc to \"${RUNC_RPM}\"" >&2
            #dnf -y -q install https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/${distro_name}_${distro_rel}/x86_64/${RUNC_RPM}
            dnf -y -q install https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/CentOS_8_Stream/x86_64/${RUNC_RPM}
        ;;
        ubuntu|Ubuntu)
            printf '%s\n' "[system] Downloading cri-o repo file" >&2
            echo "deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/x${distro_name}_${distro_rel}/ /" > /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
            echo "deb http://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/${KUBE_VERSION}/x${distro_name}_${distro_rel}/ /" > /etc/apt/sources.list.d/devel:kubic:libcontainers:stable:cri-o:${KUBE_VERSION}.list

            curl -L -s https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable:cri-o:${KUBE_VERSION}/x${distro_name}_${distro_rel}/Release.key | apt-key add -
            curl -L -s https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/x${distro_name}_${distro_rel}/Release.key | apt-key add -
            
            printf '%s\n' "[system] Refresh \"apt\" database" >&2
            apt-get -qq -o Dpkg::Use-Pty=0 update
            #apt-get -y update

            printf '%s\n' "[apt] Install cri-o, cri-o-runc, cri-tools, conntrack, runc" >&2
            #apt-get -qq -o Dpkg::Use-Pty=0 install cri-o cri-o-runc cri-tools conntrack runc
            apt-get -y install cri-o cri-o-runc cri-tools conntrack runc
        ;;
    esac

    printf '%s\n' "[crio] Patching \"/etc/containers/storage.conf\" file" >&2
    sed -i 's/^driver = "overlay"$/driver = "overlay2"/' /etc/containers/storage.conf

    if [ ! -d "/etc/crio" ]; then
        printf '%s\n' "[crio] Configuration directory not found!" >&2
        exit 1
    else
        mkdir /etc/crio/crio.conf.d
    fi

    printf '%s\n' "[crio] Writing cri-o config." >&2
    cat <<EOF | tee /etc/crio/crio.conf.d/99-kubernetes.conf &>/dev/null
[crio]
storage_driver = "overlay2"
storage_option = [ "overlay2.override_kernel_check=1" ]

[crio.runtime]
conmon_cgroup = "pod"
cgroup_manager = "${CGROUP_DRIVER}"
EOF

    run_svc crio /etc/systemd/system/multi-user.target.wants/crio.service
}

install_storageclass_localhostpath() {
    printf '%s\n' "[addons] Writing \"sc-localhostpath.yaml\" manifest file" >&2
    cat <<EOF | tee ${KUBE_TMPDIR}/sc-localhostpath.yaml &>/dev/null
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: local-sc
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: WaitForFirstConsumer
# Supported policies: Delete, Retain
reclaimPolicy: Delete
EOF
    printf '%s\n' "[storageclass] Applied StorageClass: local-sc" >&2
    kubectl apply -f ${KUBE_TMPDIR}/sc-localhostpath.yaml
}

install_dnsutils() {
    case ${DNSUTILS_INSTALL} in
        yes|on|true)
            printf '%s\n' "[addons] Applied essential addon: dnsutils" >&2
            kubectl apply -f https://raw.githubusercontent.com/kubernetes/website/master/content/en/examples/admin/dns/dnsutils.yaml
            
            check_pod dnsutils default 20

            printf '%s\n' "[dnsutils] Query google.com over CoreDNS" >&2
            #kubectl exec -i -t dnsutils -- nslookup google.com
            kubectl exec -i -t dnsutils -- dig yahoo.com google.com +short
        ;;
    esac
}

get_kube_repo() {
    printf '%s\n' "[system] Writing Kubernetes repo file" >&2

    case ${distro_name} in
        centos|Centos|CentOS)
            cat <<EOF | tee /etc/yum.repos.d/kubernetes.repo &>/dev/null
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
exclude=kubelet kubeadm kubectl
EOF
        ;;
        ubuntu|Ubuntu)
            curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
            echo "deb https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list
            apt-get -qq -o Dpkg::Use-Pty=0 update
        ;;
    esac
}

install_kube() {
    kubelet_cgroup_patch
    kubeadm_config
    get_kube_repo
    
    printf '\n%s\n' "Install kubelet, kubeadm, kubectl." >&2
    case ${distro_name} in
        centos|Centos|CentOS)
            dnf -y -q install kubelet kubeadm kubectl --disableexcludes=kubernetes
        ;;
        ubuntu|Ubuntu)
            apt-get -qq -o Dpkg::Use-Pty=0 install kubelet kubeadm kubectl
        ;;
    esac

    run_svc kubelet /etc/systemd/system/multi-user.target.wants/kubelet.service

    printf '\n%s\n' "[kubeadm] List kubernetes images." >&2
    kubeadm config images list

    printf '\n%s\n' "[kubeadm] Pre-pull kubernetes images." >&2
    kubeadm config images pull

    printf '%s\n' "[kubeadm] kubeadm config \"${KUBE_TMPDIR}/kubeadm-config.yaml\" not found" >&2
    if [ ! -f "${KUBE_TMPDIR}/kubeadm-config.yaml" ]; then exit 1; fi

    printf '\n%s\n' "[kubeadm] Creating '${CLUSTER_NAME}' cluster." >&2
    kubeadm init --config=${KUBE_TMPDIR}/kubeadm-config.yaml
}

install_calico() {
    if [[ ${distro_name} == Ubuntu ]]; then CALICO_INSTALL=on; fi

    case ${CALICO_INSTALL} in
        yes|on|true)
            printf '%s\n' "[addons] Applied essential addon: calico" >&2

            printf '%s\n' "[calico] Downloading \"calico.yaml\" manifest file." >&2
            curl -fsSL -o ${KUBE_TMPDIR}/calico.yaml https://docs.projectcalico.org/manifests/calico.yaml

            cat <<EOF | tee ${KUBE_TMPDIR}/calico.sed &>/dev/null
/\(\s\)- name: CALICO_IPV4POOL_IPIP/ { p;n; /Always/ { s/Always/Never/;p;d; } }
/\(\s\)- name: CALICO_IPV4POOL_VXLAN/ { p;n; /Never/ { s/Never/Always/;p;d; } }
p;
EOF
            if [ -f "${KUBE_TMPDIR}/calico.yaml" ]; then
                printf '%s\n' "[calico] Patching \"calico.yaml\" manifest file to support VXLAN." >&2
                sed -i -n -f ${KUBE_TMPDIR}/calico.sed ${KUBE_TMPDIR}/calico.yaml
                sed -i '0,/\(\s\)calico_backend: "bird"/{s/bird/vxlan/}' ${KUBE_TMPDIR}/calico.yaml #only replace first occurrence
                sed -i 's/^\(.*- -bird-live\)$/#\1/' ${KUBE_TMPDIR}/calico.yaml
                sed -i 's/^\(.*- -bird-ready\)$/#\1/' ${KUBE_TMPDIR}/calico.yaml
                sed -i 's/# - name: CALICO_IPV4POOL_CIDR/- name: CALICO_IPV4POOL_CIDR/' ${KUBE_TMPDIR}/calico.yaml
                sed -i 's@#   value: "192.168.0.0/16"@  value: "'"${KUBE_POD_SUBNET}"'"@' ${KUBE_TMPDIR}/calico.yaml

#               Calico internal variables
#               USE_POD_CIDR=true

                kubectl apply -f ${KUBE_TMPDIR}/calico.yaml
                check_pod calico-kube-controllers kube-system 30

                CALICOCTL_GITHUB=https://github.com/projectcalico/calicoctl/releases
                CALICOCTL_VERSION=$(curl -w '%{url_effective}' -I -L -s -S ${CALICOCTL_GITHUB}/latest -o /dev/null | sed -e 's|.*/||')

                curl -fsSL -o ${KUBE_TMPDIR}/calicoctl https://github.com/projectcalico/calicoctl/releases/download/${CALICOCTL_VERSION}/calicoctl
                chmod +x ${KUBE_TMPDIR}/calicoctl
                cp -rf ${KUBE_TMPDIR}/calicoctl /usr/local/bin/calicoctl

#               printf '%s\n' "[calico] Applied \"calicoctl\"" >&2
#               kubectl apply -f https://docs.projectcalico.org/manifests/calicoctl.yaml
#               echo 'alias calicoctl="kubectl exec -i -n kube-system calicoctl -- /calicoctl"' >> $HOME/.bashrc;
            else
                printf '%s\n' "[calico] Manifest not found. Continue without calico." >&2
                return 1;
            fi
        ;;
    esac
}

install_metallb() {
    case ${METALLB_INSTALL} in
        yes|on|true)
            printf '%s\n' "[metallb] Writing 'metallb_config.yaml' manifest file." >&2
            cat <<EOF | tee ${KUBE_TMPDIR}/metallb_config.yaml &>/dev/null
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: metallb-system
  name: config
data:
  config: |
    address-pools:
    - name: default
      protocol: layer2
      addresses:
      - ${METALLB_ADDRESS_RANGE}
EOF
            printf '%s\n' "[addons] Applied essential addon: MetalLB" >&2
            kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v${METALLB_VERSION}/manifests/namespace.yaml
            kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v${METALLB_VERSION}/manifests/metallb.yaml

            printf '%s\n' "[metallb] Applied MetalLB ConfigMap." >&2
            kubectl apply -f ${KUBE_TMPDIR}/metallb_config.yaml

            check_pod controller metallb-system
        ;;
    esac
}

spawn_alpinegit() {
    printf '%s\n' "[alpine-git] Launch \"alpine-git\" pod" >&2
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: alpine-git-ssh
type: Opaque
data:
  id_rsa: LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFNd0FBQUF0emMyZ3RaVwpReU5UVXhPUUFBQUNBZWZZdEtmbWwyaVVxdmVEVldjUHdLUmVQRjBNZk83RjZsZDB6MStYaExJUUFBQUtoUlY2UzRVVmVrCnVBQUFBQXR6YzJndFpXUXlOVFV4T1FBQUFDQWVmWXRLZm1sMmlVcXZlRFZXY1B3S1JlUEYwTWZPN0Y2bGQwejErWGhMSVEKQUFBRUFMdGw0aTRuQUpPbHBBRGpsV1g5ZUdFZXg5dWJVOUR6cjRuWlhrSm5OVnRoNTlpMHArYVhhSlNxOTROVlp3L0FwRgo0OFhReDg3c1hxVjNUUFg1ZUVzaEFBQUFIbkp2YjNSQVptRnNZMjl1TVM1dVpXSjFiR0V1Ylc5eVlYUmxiQzVwWkFFQ0F3ClFGQmdjPQotLS0tLUVORCBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K
  known_hosts: Z2l0aHViLmNvbSBzc2gtcnNhIEFBQUFCM056YUMxeWMyRUFBQUFCSXdBQUFRRUFxMkE3aFJHbWRubTl0VURiTzlJRFN3Qks2VGJRYStQWFlQQ1B5NnJiVHJUdHc3UEhrY2NLcnBwMHlWaHA1SGRFSWNLcjZwTGxWREJmT0xYOVFVc3lDT1Ywd3pmaklKTmxHRVlzZGxMSml6SGhibjJtVWp2U0FIUXFaRVRZUDgxZUZ6TFFOblBIdDRFVlZVaDdWZkRFU1U4NEtlem1ENVFsV3BYTG12VTMxL3lNZitTZTh4aEhUdktTQ1pJRkltV3dvRzZtYlVvV2Y5bnpwSW9hU2pCK3dlcXFVVW1wYWFhc1hWYWw3MkorVVgyQisyUlBXM1JjVDBlT3pRZ3FsSkwzUktyVEp2ZHNqRTNKRUF2R3EzbEdIU1pYeTI4RzNza3VhMlNtVmkvdzR5Q0U2Z2JPRHFuVFdsZzcrd0M2MDR5ZEdYQThWSmlTNWFwNDNKWGlVRkZBYVE9PQo=
---
apiVersion: v1
kind: Pod
metadata:
  name: alpine-git
spec:
  containers:
  - name: alpine-git
    image: alpine/git
    command:
    - sleep
    - "7200"
    volumeMounts:
    - name: alpine-git-vol
      mountPath: /data
    - name: ssh-key-vol
      mountPath: /root/.ssh
  volumes:
  - name: alpine-git-vol
    emptyDir: {}
  - name: ssh-key-vol
    secret:
      secretName: alpine-git-ssh
      defaultMode: 256
  restartPolicy: Always
EOF

    check_pod alpine-git default 12

    printf '%s\n' "[alpine-git] Cloning git repository: \"$3\"" >&2
    kubectl exec -it alpine-git -- $*
    sleep 10
}

clone_gukube_gitrepo() {
    printf '%s\n' "[kubernetes] Cloning NGINX Ingress manifest file" >&2
    spawn_alpinegit git clone https://github.com/nginxinc/kubernetes-ingress.git /data/kubernetes-ingress
    sleep 30

    printf '%s\n' "[kubernetes] Cloning other Kubernetes manifest file" >&2
    spawn_alpinegit git clone https://github.com/samsara238/gu-kube.git /data/gu-kube
    sleep 30

    printf '%s\n' "[kubernetes] Writing NGINX Ingress manifest file to \"${KUBE_TMPDIR}/nginx-ingress\"" >&2
    kubectl cp alpine-git:/data/kubernetes-ingress/deployments ${KUBE_TMPDIR}/nginx-ingress
    sleep 30

    printf '%s\n' "[kubernetes] Writing other Kubernetes manifest file to \"${KUBE_TMPDIR}\"" >&2
    kubectl cp alpine-git:/data/gu-kube ${KUBE_TMPDIR}
    sleep 30

    printf '%s\n' "[kubernetes] Delete git clone pod" >&2
    kubectl delete pod -n default alpine-git
}

install_nginx_ingress() {
    case ${NGINX_INGRESS_INSTALL} in
        yes|on|true)
            NGINX_INGRESS_DIR=${KUBE_TMPDIR}/nginx-ingress

            if [ ! -d "${NGINX_INGRESS_DIR}" ]; then mkdir ${NGINX_INGRESS_DIR}; fi

            printf '%s\n' "[nginx-ingress] Fix IngressClass apiVersion" >&2
            sed -i 's/v1beta1$/v1/' ${NGINX_INGRESS_DIR}/common/ingress-class.yaml

            printf '%s\n' "[nginx-ingress] Writing nginx-ingress GlobalConfiguration" >&2
            cat <<EOF | tee ${NGINX_INGRESS_DIR}/common/global-configuration.yaml &>/dev/null
apiVersion: k8s.nginx.org/v1alpha1
kind: GlobalConfiguration 
metadata:
  name: nginx-configuration
  namespace: nginx-ingress
spec:
  listeners:
  - name: tcp_50000
    port: 50000
    protocol: TCP
EOF
            nginx_ingress_manifests=(common/ns-and-sa.yaml rbac/rbac.yaml)
            nginx_ingress_manifests+=(common/default-server-secret.yaml common/nginx-config.yaml common/ingress-class.yaml)
            nginx_ingress_manifests+=(common/crds/k8s.nginx.org_virtualservers.yaml common/crds/k8s.nginx.org_virtualserverroutes.yaml common/crds/k8s.nginx.org_transportservers.yaml common/crds/k8s.nginx.org_policies.yaml)
            nginx_ingress_manifests+=(common/crds/k8s.nginx.org_globalconfigurations.yaml common/global-configuration.yaml)
            nginx_ingress_manifests+=(deployment/nginx-ingress.yaml service/loadbalancer.yaml)

            printf '%s\n' "[addons] Applied essential addon: Nginx-Ingress" >&2
            for i in "${nginx_ingress_manifests[@]}"; do
                printf '%s\n' "[nginx-ingress] Apply $i." >&2
                kubectl apply -f ${NGINX_INGRESS_DIR}/$i &>/dev/null
            done

            check_pod nginx-ingress nginx-ingress 30
            nginx_ingress_status=$pod_result

#           NGINX_INGRESS_CTRLPOD=$(kubectl get pods --namespace nginx-ingress | grep nginx-ingress | awk '{print $1}')
            kubectl patch deploy -n nginx-ingress nginx-ingress --patch "$(cat ${NGINX_INGRESS_DIR}/nginx-ingress-deployment-patch.yaml)"

            unset nginx_ingress_manifests
        ;;
    esac
}

install_kubernetes_dashboard() {
    case ${KUBE_DASHBOARD_INSTALL} in
        yes|on|true)
            if [ ! -d "${KUBE_TMPDIR}/dashboard" ]; then mkdir ${KUBE_TMPDIR}/dashboard; fi
            cat <<EOF | tee ${KUBE_TMPDIR}/dashboard/sa.yaml &>/dev/null
apiVersion: v1
kind: ServiceAccount
metadata:
  name: dashboard-admin
  namespace: kubernetes-dashboard
EOF
            cat <<EOF | tee ${KUBE_TMPDIR}/dashboard/crb.yaml &>/dev/null
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dashboard-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: dashboard-admin
  namespace: kubernetes-dashboard
EOF

            KUBE_DASHBOARD_GITHUB=https://github.com/kubernetes/dashboard/releases
            KUBE_DASHBOARD_VERSION=$(curl -w '%{url_effective}' -I -L -s -S ${KUBE_DASHBOARD_GITHUB}/latest -o /dev/null | sed -e 's|.*/||')

            printf '%s\n' "[addons] Applied Kubernetes Dashboard" >&2
            kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/${KUBE_DASHBOARD_VERSION}/aio/deploy/recommended.yaml
            kubectl apply -f ${KUBE_TMPDIR}/dashboard/sa.yaml -f ${KUBE_TMPDIR}/dashboard/crb.yaml

            check_pod kubernetes-dashboard kubernetes-dashboard

            printf '%s\n' "[kubernetes-dashboard] Patching kubernetes-dashboard Service to \"LoadBalancer\"" >&2
            kubectl patch svc -n kubernetes-dashboard kubernetes-dashboard -p '{"spec":{"type":"LoadBalancer"}}'
            
            kubedashboard_token=$(kubectl -n kubernetes-dashboard get secret $(kubectl -n kubernetes-dashboard get sa/dashboard-admin -o jsonpath="{.secrets[0].name}") -o go-template="{{.data.token | base64decode}}")
            echo ${kubedashboard_token} > ${KUBE_TMPDIR}/kubernetes-dashboard.token
        ;;
    esac
}

install_helm() {
    case ${HELM_INSTALL} in
        yes|on|true)
            HELM_GITHUB=https://github.com/helm/helm/releases
            HELM_VERSION=$(curl -w '%{url_effective}' -I -L -s -S ${HELM_GITHUB}/latest -o /dev/null | sed -e 's|.*/||')

            printf '%s\n' "[helm] Downloading \"helm-${HELM_VERSION}-linux-amd64.tar.gz\"" >&2
            curl -fsSL -o ${KUBE_TMPDIR}/helm-${HELM_VERSION}-linux-amd64.tar.gz https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz
            tar -zxf ${KUBE_TMPDIR}/helm-${HELM_VERSION}-linux-amd64.tar.gz -C ${KUBE_TMPDIR}

            printf '%s\n' "[helm] Installing \"helm-${HELM_VERSION}\"" >&2
            mv -f ${KUBE_TMPDIR}/linux-amd64/helm /usr/local/bin/helm

            /usr/local/bin/helm version
        ;;
    esac
}

install_certmanager() {
    case ${CERT_MANAGER_INSTALL} in
        yes|on|true)
            CERTMANAGER_GITHUB=https://github.com/jetstack/cert-manager/releases
            CERTMANAGER_VERSION=$(curl -w '%{url_effective}' -I -L -s -S ${CERTMANAGER_GITHUB}/latest -o /dev/null | sed -e 's|.*/||')

            printf '%s\n' "[cert-manager] Applied \"cert-manager ${CERTMANAGER_VERSION}\" manifest file" >&2
            kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/${CERTMANAGER_VERSION}/cert-manager.yaml &>/dev/null
        ;;
    esac
}

install_prometheus() {
    case ${PROMETHEUS_INSTALL} in
        yes|on|true)
            PROMETHEUS_DIR=${KUBE_TMPDIR}/prometheus

            printf '%s\n' "[prometheus] Create Prometheus local user and directory" >&2
            adduser prometheus -M -u 2001 -s /sbin/nologin -c Prometheus
            mkdir -p /data/prometheus
            chown prometheus:prometheus /data/prometheus
            chmod 0771 /data/prometheus

#           if [ ! -d "${PROMETHEUS_DIR}" ]; then mkdir ${PROMETHEUS_DIR}; fi
            sed -i 's/prometheus.cluster.local/prometheus\.'${CLUSTER_NAME}'\.'${CLUSTER_DOMAIN}'/' ${PROMETHEUS_DIR}/04-prometheus-deploy.yaml
            kubectl apply -f ${PROMETHEUS_DIR}/01-prometheus-pv.yaml -f ${PROMETHEUS_DIR}/02-prometheus-act.yaml
            kubectl apply -f ${PROMETHEUS_DIR}/03-prometheus-cm.yaml -f ${PROMETHEUS_DIR}/04-prometheus-deploy.yaml

        ;;
    esac
}

install_grafana() {
    case ${GRAFANA_INSTALL} in
        yes|on|true)
            GRAFANA_DIR=${KUBE_TMPDIR}/grafana

            printf '%s\n' "[grafana] Create Grafana local user and directory" >&2
            adduser grafana -M -u 2002 -s /sbin/nologin -c Grafana
            mkdir -p /data/grafana
            chown grafana:grafana /data/grafana
            chmod 0771 /data/grafana

            if [ ! -d "${GRAFANA_DIR}" ]; then mkdir ${GRAFANA_DIR}; fi
            sed -i 's/grafana.cluster.local/grafana\.'${CLUSTER_NAME}'\.'${CLUSTER_DOMAIN}'/' ${GRAFANA_DIR}/04-prometheus-deploy.yaml
            kubectl apply -f ${GRAFANA_DIR}/01-grafana-pv.yaml -f ${GRAFANA_DIR}/02-grafana-deploy.yaml
        ;;
    esac
}

preflight_pkg() {
    printf '%s\n' "[preflight] Installing essential package" >&2

    case ${distro_name} in
        centos|Centos|CentOS)
            dnf -y -q update && yum -y -q install nano wget rsyslog bash-completion
            systemctl enable --now rsyslog
        ;;
        ubuntu|Ubuntu)
            apt-get -qq -o Dpkg::Use-Pty=0 update && apt-get -qq -o Dpkg::Use-Pty=0 install policycoreutils firewalld
        ;;
    esac
}

preflight_host() {
    printf '%s\n' "[preflight] Adjust SELinux" >&2
    setenforce Permissive
    sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config

    timedatectl set-timezone Asia/Jakarta

    #Bug 1871139 - [systemd] systemd-resolved.service:33: Unknown lvalue 'ProtectSystems' in section  'Service'
    sed -i 's/^ProtectSystems=strict$/ProtectSystem=strict/' /usr/lib/systemd/system/systemd-resolved.service

    if [[ $HOSTNAME != ${HOST_FQDN} ]]; then
        printf '%s\n'  "[preflight] Change hostname from '$(cat /proc/sys/kernel/hostname)' to '${HOST_FQDN}'"  >&2
        hostnamectl set-hostname "${HOST_FQDN}" --static
    fi
    echo "$HOST_VIF_IP  $HOST_FQDN kubernetes kubernetes.default kubernetes.default.svc kubernetes.default.svc.${CLUSTER_NAME}.${CLUSTER_DOMAIN}" >> /etc/hosts
    echo "127.0.0.1     $HOST_FQDN" >> /etc/hosts
    #echo "$HOST_VIF_IP    $(cat /proc/sys/kernel/hostname)" >> /etc/hosts

    printf '%s\n' "Enable kernel modules." >&2
    modprobe overlay
    modprobe 8021q
    modprobe br_netfilter

    # Create the .conf file to load the modules at bootup
    cat <<EOF | sudo tee /etc/modules-load.d/kubernetes.conf &>/dev/null
overlay
br_netfilter
8021q
EOF

    printf '\n%s\n' "[system] Disable swap partition." >&2
    swapoff -a
    sed -i 's/^\(.*swap.*\)$/#\1/' /etc/fstab

    printf '%s\n' "[preflight] Add sysctl." >&2
    # Set up required sysctl params, these persist across reboots.
    cat <<EOF | sudo tee /etc/sysctl.d/99-kubernetes.conf &>/dev/null
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

    sysctl --system

    case ${distro_name} in
        centos|Centos|CentOS) firewalld_rules ;;
        ubuntu|Ubuntu) ufw_rules ;;
    esac

    if [ ! -d "${KUBE_TMPDIR}" ]; then mkdir ${KUBE_TMPDIR}; fi
}



if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

get_distro
get_wanif
preflight_pkg
preflight_host

install_vif
install_crio
install_kube

### Post Install Kubernetes
printf '\n%s\n' "Add bash completion." >&2
export KUBECONFIG=/etc/kubernetes/admin.conf
if ! grep -Fq "KUBECONFIG=" $HOME/.bashrc; then echo export KUBECONFIG=/etc/kubernetes/admin.conf >> $HOME/.bashrc; fi
echo alias k='kubectl' >> $HOME/.bashrc
kubectl completion bash >/etc/bash_completion.d/kubectl
#. $HOME/.bashrc

if [ ! -f "/etc/kubernetes/admin.conf" ]; then 
    printf '\n%s\n' "[kubernetes] Cluster is not running. Exiting!" >&2
    exit 1;
fi

printf '%s\n' "Untaint this host." >&2
kubectl taint nodes --all node-role.kubernetes.io/master:NoSchedule-

### Install Kubernetes services
install_storageclass_localhostpath
install_calico
install_helm
install_dnsutils
install_metallb
install_nginx_ingress
install_kubernetes_dashboard
install_certmanager
install_prometheus
install_grafana

printf '%s\n\n' "[kubernetes] Installation completed" >&2
kubectl get pods -A -o wide

printf '%s\n' "Kubernetes Dashboard Bearer Token: ${kubedashboard_token}" >&2