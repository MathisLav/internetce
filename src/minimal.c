/**
 *	Modify this file as you want.
 */


#include <internet.h>
#include <tice.h>


int main(void)
{
	os_ClrHome();

	web_Init();
	while(!web_Connected() && !os_GetCSC()) {
        web_WaitForEvents();
    }

	// Do whatever you want

	web_Cleanup();
	return 0;
}