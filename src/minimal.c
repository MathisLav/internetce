/**
 *	Modify this file as you want.
 */


#include <internet.h>


int main(void)
{
	web_Init();
	while(!web_Connected())
		web_WaitForEvents();
	// Do whatever you want
	web_Cleanup();
	return 0;
}
