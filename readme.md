# Internet on your Ti-84+CE and Ti-83 Premium CE

This is a high-level library for interfacing with the internet on Ti-84+CE and Ti-83 Premium CE.

## The scope of the library
**What InternetCE can do:**
 * Acquire an IP address with DHCP.
 * Make HTTP Get and Post requests.
 * Send DNS requests.
 * Send UDP/TCP/IPv4/Ethernet. In particular, you can handle any web protocol that the lib don't, such as IRC, SSH, etc).
 * Send a pong when receiving a ping (ICMPv4).  

**What InternetCE canNOT do:**
 * Make HTTPS requests.
 * Use some compression algorithms such as Gzip.
 * Display the content of the accessed URL (it only provides you the data).
 * Handle IPv6.
 * Download resources of more than 65535 bytes.  

## Getting started
  * Plug the calculator to a RNDIS device (basically your phone). To this end, you may need to buy an adapter. The "final cable" you need is something that has a male mini USB Type A at one end (for the calculator) and a male micro USB or USB Type C at the other end (for your phone). You can use for example :
	* The charger of your phone (USB <-> Micro USB or USB Type C) (you may already have this).
	* And A Mini USB Type A Male <-> USB Female cable - For example :  https://aliexpress.com/item/32780744354.html  
	Warning : Make sure you choose the Mini A cable (in the color section)!
* Transfer a program that has been compiled with the library.
* Run it, and enable the USB internet connection sharing. On Android, it should be in `Settings->Tethering & portable hotspot->USB tethering`.

## Example of use
First, create a project in your toolchain folder (the toolchain v10.2 is strongly recommended).
Then :
 * Put `src/internet.c` and `src/utils.asm` in the `src/` folder.
 * Put `include/internetstatic.h` in your `include/` folder.
 * Put `include/internet.h` **in the `include/` folder of the toolchain**
 * At last, create a file in the `src/` folder with your main() (you can use one of the programs in the [examples folder](examples/))  
The minimal program using this lib can be :
```c
#include <internet.h>

int main(void) {
	web_Init();
	while(!web_Connected())
		web_WaitForEvents();
	// Do whatever you want
	web_Cleanup();
	return 0;
}
```
***Warning :*** You will need the USBDRVCE lib from the toolchain to make it work! *(See the [corresponding branch](https://github.com/CE-Programming/toolchain/tree/usbdrvce))*  
For now, USBDRVCE is under development and thus, not included in the toolchain releases. But don't worry: a way to install the lib, in order to be able to use it for InternetCE, is explained in the [resources folder](resources/) of this repository.

## Help & Bug report
Some examples of use are available in the [examples folder](examples/). You can draw inspiration from those programs. If you can't find what you want, feel free to ask your questions on forums such as Ti-Planet or Cemetech.
This library may contain bugs. If you encounter one, please contact me on www.tiplanet.org or www.cemetech.net (Epharius).
