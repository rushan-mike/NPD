sudo ip tuntap add dev asa0 mode tun
sudo ip addr add 10.0.1.1/24 dev asa0
sudo ip link set dev asa0 up
ip route get 10.0.1.1
ip addr show

sudo ip tuntap add dev asa0 mode tun
sudo ip addr add 10.0.1.2/24 dev asa0
sudo ip link set dev asa0 up
ip route get 10.0.1.2
ip addr show

ping -I 10.0.1.1 10.0.1.2

