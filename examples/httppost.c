/**
 *	Performs a HTTP POST request to a custom website. Used features :
 *		- Performing a HTTP POST request.
 *
 *	This is the content of the target file (post.php) :
 *	\code
 *		<?php
 *			print_r($_POST);
 *		?>
 *	\endcode
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
	while(!web_Connected() && !os_GetCSC()) {
		web_WaitForEvents();
	}
	if(!web_Connected()) {
		printf("\nCanceled!\n");
		goto _end;
	}
	printf("Done!\n");

	printf("HTTP Request...");
	http_data_t *data = NULL;
	web_status_t status = web_HTTPPost("geometrydash.fr.nf/internetce/post.php", &data, false, 2, "azer", "wesh",
									   "83pce", "yeet");
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
