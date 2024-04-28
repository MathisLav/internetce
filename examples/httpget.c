/**
 *	Performs an HTTP GET request to www.perdu.com. Used features :
 *		- Initializing and cleaning up the library.
 *		- Performing an HTTP GET request.
 */


#include <internet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


int main(void)
{
	os_ClrHome();
	printf("WEB Connection... ");
	
	web_Init();
	while(!web_Connected()) {
		web_WaitForEvents();
		if(os_GetCSC()) {
			printf("Canceled!\n");
			goto _end;
		}
	}
	printf("Done!\n");

	printf("HTTP Request...\n");
	http_data_t *data = NULL;
	web_status_t status = web_HTTPGet("geometrydash.fr.nf", &data, false);
	if(status == HTTP_STATUS_OK) {
		os_ClrHome();
		printf("%.*s", data->size, data->data);
	} else {
		printf("Err %u: couldn't retrieve foreign data\n", status);
	}

	_end:
	while(!os_GetCSC()) {}
	web_Cleanup();
	return 0;
}
