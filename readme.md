# Internet on your Ti-84+CE and Ti-83 Premium CE

This is a high-level library for interfacing with the internet on Ti-84+CE and Ti-83 Premium CE.

## The scope of the library
**What InternetCE can do:**
 * Acquire an IP address with DHCP.
 * Make HTTP Get and Post requests.
 * Send DNS requests.
 * Send UDP/TCP/IPv4/Ethernet. In particular, you can handle any web protocol that the lib don't, such as IRC, SSH, etc.
 * Send an ICMP echo reply when receiving an echo request (ping).  

**What InternetCE canNOT do:**
 * Make HTTPS requests as TLS is not supported yet.
 * Display the content of the accessed URL (it only provides you the data).
 * Handle IPv6.
 * Download resources bigger than 65535 bytes.  

## Getting started
  * Plug the calculator to any RNDIS device (basically your phone). To this end, you may need to buy an adapter. The "final cable" you need is something that has a male mini USB Type A at one end (for the calculator) and a male micro USB or USB Type C at the other end (for your phone). You can use for example :
	* The charger of your phone (USB <-> Micro USB or USB Type C) (you should already have this).
	* A Mini USB Type A Male <-> USB Female cable - For example :  https://aliexpress.com/item/32780744354.html  
	Warning : Make sure you choose the Mini A cable (in the color section)!
* Transfer a program that has been compiled with the library.
* Run it, and enable the USB internet connection sharing. On Android, it should be near the Wi-Fi Tethering menu.

## Example of use
`git clone` this project and put the `include/internet.h` file into the `include` folder of your toolchain.
Then modify the file `src/minimal.c` as you wish. You can find other examples of what you can do with the lib in the `examples` folder.
For information, the minimal program using this library would be:
```c
#include <internet.h>

int main(void) {
	web_Init();
	while(!web_Connected()) {
		web_WaitForEvents();
	}
	// Do whatever you want
	web_Cleanup();
	return 0;
}
```

## Help & Bug report
As mentionned, some examples of use are available in the [examples folder](examples/). You can draw inspiration from those programs.
If you can't find what you want, feel free to ask your questions on forums such as Ti-Planet or Cemetech.
This library may contain bugs. If you encounter one, please contact me on www.tiplanet.org or www.cemetech.net (Epharius).
