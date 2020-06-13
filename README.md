This iptables module changes TCP window header field.

The purpose is only testing and debugging because of changing TCP window
usualy is very bad idea.

modified from (https://github.com/HanabishiRecca/ipt_tcpwin)

Usage example:

- make modules and put them to proper places
- modprobe xt_TCPWIN
- iptables -t mangle -I OUTPUT -p tcp --sport 80 --tcp-flags SYN,ACK SYN,ACK -j TCPWIN --tcpwin-set 0
