# Internet on your Ti-84+CE and Ti-83 Premium CE

This is a high-level library for interfacing with the internet on Ti-84+CE and Ti-83 Premium CE.

## Getting started
  * Plug the calculator to a RNDIS device (basically your phone). To this end, you may need to buy an adapter. The "final cable" you need is something that has a male mini USB Type A at one end (for the calculator) and a male micro USB or USB Type C at the other end (for your phone). You can use for example :
	* The charger of your phone (USB <-> Micro USB or USB Type C) (you may already have this).
	* And A Mini USB Type A Male <-> USB Female cable - For example :  https://aliexpress.com/item/32780744354.html  
	Warning : Make sure you choose the Mini A cable (in the color section)!
* Transfer a program that has been compiled with the library.
* Run it, and enable the USB internet connection sharing. On Android, it should be in `Settings->Tethering & portable hotspot->USB tethering`.

## Example of use
First, create a project in your toolchain folder.
Then :
 * Put src/internet.c in the src/ folder.
 * Put include/internetstatic.h in your include/ folder.
 * Put include/internet.h **in the include/ folder of the toolchain**
 * At last, create a file in the src/ folder with your main()  
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

## Help & Bug report
Some examples of use are available in the tests/ folder. You can draw inspiration from those programs. If you can't find what you want, feel free to ask your questions on forums such as tiplanet.org or cemetech.net.
This library may contain bugs. If you encounter one, please contact me on www.tiplanet.org or www.cemetech.net (Epharius).
