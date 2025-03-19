# Internet on your Ti-84+CE and Ti-83 Premium CE

This is a high-level library for interfacing with the internet on Ti-84+CE and Ti-83 Premium CE.

## The scope of the library
**What InternetCE can do:**
 * Acquire an IP address with DHCP.
 * Make HTTP Get and Post requests.
 * Make HTTPS (Secured HTTP) Get and Post requests.
 * Send DNS requests.
 * Send UDP/TCP/IPv4/Ethernet. In particular, you can handle any web protocol that the lib don't, such as IRC, SSH, etc.
 * Handle ICMP and ping requests (however, you won't be able to receive ping requests because of the way USB tethering works)

**What InternetCE canNOT do:**
 * Display the content of the accessed URL (it only provides you the data).
 * Handle IPv6.
 * Download resources bigger than 25KB (I'm trying to increase this value but it won't be bigger than 64KiB).  

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

## HTTPS ?
HTTPS is made possible thanks to the support of the TLS 1.3 protocol that is between the TCP and the HTTP layer.

**WARNING: THIS DOES NOT MEAN YOU ARE SAFE!!!**

Please, be aware that implementing cryptography primitives is NOT something that anyone can do alone in their room. Good cryptography libraries such as OpenSSL are made by hundreds of experts and is not completely safe either. Moreover, this implementation does not even check the certificate of the server. Anyone can make a Man In The Middle attack and you wouldn't even know you've been stolen.

**THAT'S WHY YOU MUST NOT SEND SENSITIVE DATA THROUGH AN HTTPS CONNECTION WITH THIS LIBRARY**

You are warned.

## Help & Bug report
As mentioned, some examples of use are available in the [examples folder](examples/). You can draw inspiration from those programs.
If you can't find what you want, feel free to ask your questions on forums such as Ti-Planet or Cemetech.
This library may contain bugs. If you encounter one, please contact me on www.tiplanet.org or www.cemetech.net (Epharius).
