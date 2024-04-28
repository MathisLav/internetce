/**
 * Scheduling utility functions
 */

#ifndef INTERNET_SCHEDULER
#define INTERNET_SCHEDULER

#include <internet.h>

#define MS_TO_TICK(x)    (x * 375 / 2)  /* <=> x*48000/256 */

/**
 * Constants
 */

#define SEND_KEEPALIVE_SCHED_ID     ((web_callback_data_t *)0x01)


/**
 * Enums & structs
 */

typedef struct schedule_list {
    uint24_t date;
    uint24_t every;
    web_schedule_callback_t *schedule_callback;
    web_destructor_callback_t *destructor_callback;
    web_callback_data_t *user_data;
    struct schedule_list *next;
} schedule_list_t;


/**
 * Internal functions prototype
 */

void insert_event(schedule_list_t *new_event);

void update_event_time();

web_status_t dispatch_time_events();

void schedule(uint24_t every, web_schedule_callback_t *schedule_callback,
              web_destructor_callback_t *destructor_callback, web_callback_data_t *user_data);

void delay_event(uint24_t offset_ms, web_schedule_callback_t *schedule_callback,
                 web_destructor_callback_t *destructor_callback, web_callback_data_t *user_data);

web_status_t remove_event(web_callback_data_t *user_data);

void flush_event_list();

void reset_event(web_callback_data_t *user_data);

web_status_t boolean_scheduler(web_callback_data_t *user_data);

void boolean_destructor(web_callback_data_t *user_data);


#endif // INTERNET_SCHEDULER
