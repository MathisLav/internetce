/**
 * Debugging stuffs
 */

#ifndef INTERNET_DEBUG
#define INTERNET_DEBUG


#define NO_DEBUG		0
#define DEBUG_ERRORS	1
#define DEBUG_WARNINGS	2
#define DEBUG_INFO		3
#define DEBUG_VERBOSE	4

/**
 * Change this define to make the lib more or less verbose
 */
#define DEBUG_LEVEL NO_DEBUG


#if DEBUG_LEVEL == NO_DEBUG
	#define debug(...)
	#define pause(...)
	#define printf_xy(...)
	#define print_tcp_info(...)
	#define monitor_usb_connection(...)
	#define dbg_err(...)
	#define dbg_warn(...)
	#define dbg_info(...)
	#define dbg_verb(...)
#elif DEBUG_LEVEL == DEBUG_ERRORS
	void debug(const void *addr, size_t len);
	void printf_xy(unsigned int xpos, unsigned int ypos, const char *format, ...);
	void print_tcp_info(const tcp_segment_t *seg, tcp_exchange_t *tcp_exch, size_t length);
	#define monitor_usb_connection(...)
	#define pause() while(!os_GetCSC()) {}
	#define dbg_err(...) printf("E: " __VA_ARGS__); printf("\n")
	#define dbg_warn(...)
	#define dbg_info(...)
	#define dbg_verb(...)
#elif DEBUG_LEVEL == DEBUG_WARNINGS
	void debug(const void *addr, size_t len);
	void printf_xy(unsigned int xpos, unsigned int ypos, const char *format, ...);
	void print_tcp_info(const tcp_segment_t *seg, tcp_exchange_t *tcp_exch, size_t length);
	#define monitor_usb_connection(...)
	#define pause() while(!os_GetCSC()) {}
	#define dbg_err(...) printf("E: " __VA_ARGS__); printf("\n")
	#define dbg_warn(...) printf("W: " __VA_ARGS__); printf("\n")
	#define dbg_info(...)
	#define dbg_verb(...)
#elif DEBUG_LEVEL == DEBUG_INFO
	void debug(const void *addr, size_t len);
	void printf_xy(unsigned int xpos, unsigned int ypos, const char *format, ...);
	void print_tcp_info(const tcp_segment_t *seg, tcp_exchange_t *tcp_exch, size_t length);
	#define monitor_usb_connection(...)
	#define pause() while(!os_GetCSC()) {}
	#define dbg_err(...) printf("E: " __VA_ARGS__); printf("\n")
	#define dbg_warn(...) printf("W: " __VA_ARGS__); printf("\n")
	#define dbg_info(...) printf("I: " __VA_ARGS__); printf("\n")
	#define dbg_verb(...)
#elif DEBUG_LEVEL == DEBUG_VERBOSE
	void debug(const void *addr, size_t len);
	void printf_xy(unsigned int xpos, unsigned int ypos, const char *format, ...);
	void print_tcp_info(const tcp_segment_t *seg, tcp_exchange_t *tcp_exch, size_t length);
	void monitor_usb_connection(usb_event_t event, device_state_t state);
	#define pause() while(!os_GetCSC()) {}
	#define dbg_err(...) printf("E: " __VA_ARGS__); printf("\n")
	#define dbg_warn(...) printf("W: " __VA_ARGS__); printf("\n")
	#define dbg_info(...) printf("I: " __VA_ARGS__); printf("\n")
	#define dbg_verb(...) printf("V: " __VA_ARGS__); printf("\n")
#endif


#endif // INTERNET_DEBUG
