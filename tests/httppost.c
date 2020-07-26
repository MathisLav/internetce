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
	web_HTTPPost("assemblyschool.alwaysdata.net/cewireless/post.php", &data, false, 2, "azer", "wesh", "83pce", "oui-oui");
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
