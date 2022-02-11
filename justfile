cert_fs := "credstore.chamelon"
webapp_fs := "webapp.chamelon"
guest_ip := "10.0.0.2"
fqdn := "we-have.legitcreds.us"
hypervisor_ip := "10.0.0.1"
hypervisor_uplink := "eth0"
hypervisor_tap := "tap100"
path := "/etsy"

start :
	sudo solo5-hvt --net:service={{hypervisor_tap}} --block:webapp={{webapp_fs}} --block:certs={{cert_fs}} -- dist/oauth2.hvt --backtrace=true -l "application:debug" --host={{fqdn}} --path={{path}} --ipv4-gateway={{hypervisor_ip}}

creds :
	dd if=/dev/zero of={{cert_fs}} bs=4K count=4
	format --block-size=512 {{cert_fs}}
	cat ~/oauth2_test_creds/keystring | tr -d '\n' | lfs_write --verbosity=debug {{cert_fs}} 512 /keystring -

newdb :
	dd if=/dev/zero of={{webapp_fs}} bs=1M count=1
	format --block-size=512 {{webapp_fs}}

tap :
	sudo ip tuntap add {{hypervisor_tap}} mode tap
	sudo ip addr add {{hypervisor_ip}}/24 dev tap100
	sudo ip link set dev {{hypervisor_tap}} up

forward :
	# kernel: allow ipv4 forwarding
	sudo sysctl net.ipv4.ip_forward=1
	# set up NAT
	sudo iptables -t nat -A POSTROUTING -o {{hypervisor_uplink}} -j MASQUERADE
	# forward traffic on 80/443 to the guest IP
	sudo iptables -t nat -A PREROUTING -i {{hypervisor_uplink}} -p tcp --dport 443 -j DNAT --to-destination {{guest_ip}}:443
	sudo iptables -t nat -A PREROUTING -i {{hypervisor_uplink}} -p tcp --dport 80 -j DNAT --to-destination {{guest_ip}}:80
	# allow the forwarded traffic to reach the guest IP
	sudo iptables -A FORWARD -i {{hypervisor_uplink}} -o {{hypervisor_tap}} -p tcp --dport 443 -j ACCEPT
	sudo iptables -A FORWARD -i {{hypervisor_uplink}} -o {{hypervisor_tap}} -p tcp --dport 80 -j ACCEPT
	sudo iptables -A FORWARD -i {{hypervisor_uplink}} -o {{hypervisor_tap}} -p udp --sport 53 -j ACCEPT
	# allow any return traffic for connections initiated by the guest
	sudo iptables -A FORWARD -i {{hypervisor_uplink}} -o {{hypervisor_tap}} -p tcp -m state --state RELATED,ESTABLISHED -j ACCEPT
	# allow any traffic from the guest
	sudo iptables -A FORWARD -o {{hypervisor_uplink}} -i {{hypervisor_tap}} -s {{guest_ip}} -j ACCEPT

unforward :
	sudo sysctl net.ipv4.ip_forward=0
	sudo iptables -t nat -F POSTROUTING
	sudo iptables -t nat -F PREROUTING
	sudo iptables -F FORWARD

churn :
	make clean
	mirage configure -t hvt
	make

new :
	#!/bin/bash
	loc=$(curl -v -k --data uuid=$(dd if=/dev/urandom bs=16 count=1|base64) https://{{guest_ip}}/auth 2>&1 | grep location|cut -f3 -d' ')
	echo "loc: $loc"

extant :
	#!/bin/bash
	id=$(lfs_ls {{webapp_fs}} 512 /|head -1|cut -d' ' -f1)
	curl -k --data state=${id} https://{{guest_ip}}/token

loadtest :
	#!/bin/bash
	echo "uuid=16charsnwdyaget" > loadtest
	vegeta_content="POST https://{{fqdn}}/auth"
	echo "$vegeta_content" | vegeta attack -body loadtest -duration 5s | vegeta report
	rm loadtest || true
