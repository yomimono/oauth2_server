cert_fs := "credstore.chamelon"
webapp_fs := "webapp.chamelon"
guest_ip := "10.0.0.2"
fqdn := "we-have.legitcreds.us"
hypervisor_ip := "10.0.0.1"
hypervisor_uplink := "eth0"
hypervisor_tap := "tap100"

creds :
	dd if=/dev/zero of={{cert_fs}} bs=4K count=4
	format --block-size=512 {{cert_fs}}
	cat ~/oauth2_test_creds/pk | lfs_write --verbosity=debug {{cert_fs}} 512 /pk -
	cat ~/oauth2_test_creds/certificate | lfs_write --verbosity=debug {{cert_fs}} 512 /certificate -
	cat ~/oauth2_test_creds/keystring | lfs_write --verbosity=debug {{cert_fs}} 512 /keystring -
	cat ~/oauth2_test_creds/shared_secret | lfs_write --verbosity=debug {{cert_fs}} 512 /shared_secret -

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

start :
	sudo solo5-hvt --net:service={{hypervisor_tap}} --block:webapp={{webapp_fs}} --block:certs={{cert_fs}} -- oauth2.hvt --backtrace=true -l "application:debug" --host={{fqdn}} --ipv4-gateway={{hypervisor_ip}}
