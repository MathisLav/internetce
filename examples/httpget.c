/**
 *	Performs a HTTP GET request to www.perdu.com. Used features :
 *		- Initializing and cleaning up the library.
 *		- Performing a HTTP GET request.
 */


#include <internet.h>
#include <stdlib.h>
#include <string.h>

void putStrnFull(const void *str, size_t len);


int main(void)
{
	os_ClrHome();
	os_PutStrFull("WEB Connection... ");
	
	web_Init();
	while(!web_Connected() && !os_GetCSC())
		web_WaitForEvents();
	if(!web_Connected()) {
		boot_NewLine();
		os_PutStrFull("Canceled!");
		while(!os_GetCSC()) {}
		goto _end;
	}
	os_PutStrFull("Done!");
	boot_NewLine();

	os_PutStrFull("HTTP Request...");
	http_data_t *data = NULL;
	web_HTTPGet("www.perdu.com", &data, false);
	os_ClrHome();
	putStrnFull(data->data, data->size);
	while(!os_GetCSC()) {}

	_end:
	web_Cleanup();
	return 0;
}


void putStrnFull(const void *str, size_t len) {
	char *tmp = calloc(1, len+1);
	strncpy(tmp, str, len);
	os_PutStrFull(tmp);
	boot_NewLine();
	free(tmp);
}
