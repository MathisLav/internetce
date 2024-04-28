#include <stdlib.h>
#include <stdio.h>

#include "include/scheduler.h"
#include "include/debug.h"


/**********************************************************************************************************************\
 *                                                  Global Variables                                                  *
\**********************************************************************************************************************/

schedule_list_t *event_list = NULL;


/**********************************************************************************************************************\
 *                                                   Private functions                                                *
\**********************************************************************************************************************/

/* Note: This file has only internal functions */

void schedule(uint24_t every, web_schedule_callback_t *schedule_callback,
              web_destructor_callback_t *destructor_callback, web_callback_data_t *user_data) {
    /*
        Preconditions:
            - user_data is a unique number (among all currently valid events)
            - every is in range [1, 44*1000] as counter overflows every ~ 90s
    */
    if(every == 0 || every > 44 * 1000) {
        dbg_err("schedule has been given bad arguments");
        return;
    }
    schedule_list_t *new_event = malloc(sizeof(schedule_list_t));
    new_event->every = MS_TO_TICK(every);
    new_event->schedule_callback = schedule_callback;
    new_event->destructor_callback = destructor_callback;
    new_event->user_data = user_data;
    new_event->date = usb_GetCounter();

    insert_event(new_event);
}

void delay_event(uint24_t offset_ms, web_schedule_callback_t *schedule_callback,
                 web_destructor_callback_t *destructor_callback, web_callback_data_t *user_data) {
    /*
        Preconditions:
            - user_data is a unique number (among all currently valid events)
            - offset_ms is in range [1, 44*1000] as counter overflows every ~ 90s
    */
    if(offset_ms == 0 || offset_ms > 44 * 1000) {
        dbg_err("delay has been given bad arguments");
        return;
    }

    schedule_list_t *new_event = malloc(sizeof(schedule_list_t));
    new_event->every = 0;  /* only once */
    new_event->schedule_callback = schedule_callback;
    new_event->destructor_callback = destructor_callback;
    new_event->user_data = user_data;
    new_event->date = usb_GetCounter() + MS_TO_TICK(offset_ms);

    insert_event(new_event);
}

web_status_t remove_event(web_callback_data_t *user_data) {
    schedule_list_t *cur_event = event_list;
    schedule_list_t *prv_event = NULL;
    while(cur_event != NULL) {
        if(cur_event->user_data == user_data) {
            if(prv_event != NULL) {
                prv_event->next = cur_event->next;
            } else {
                event_list = cur_event->next;
            }
            if(cur_event->destructor_callback != NULL) {
                cur_event->destructor_callback(cur_event->user_data);
            }
            free(cur_event);
            return WEB_SUCCESS;
        }
        prv_event = cur_event;
        cur_event = cur_event->next;
    }
    return WEB_ERROR_FAILED;
}

void flush_event_list() {
    schedule_list_t *cur_event = event_list;
    schedule_list_t *next_event;
    while(cur_event != NULL) {
        next_event = cur_event->next;
        if(cur_event->destructor_callback != NULL) {
            cur_event->destructor_callback(cur_event->user_data);
        }
        free(cur_event);
        cur_event = next_event;
    }
    event_list = NULL;
}

void reset_event(web_callback_data_t *user_data) {
    schedule_list_t *prv_event = NULL;
    schedule_list_t *cur_event = event_list;
    while(cur_event != NULL) {
        if(cur_event->user_data == user_data) {
            cur_event->date = usb_GetCounter();
            if(prv_event != NULL) {
                prv_event->next = cur_event->next;
            } else {
                event_list = cur_event->next;
            }
            insert_event(cur_event);
            break;
        }
        prv_event = cur_event;
        cur_event = cur_event->next;
    }
}

void insert_event(schedule_list_t *new_event) {
    schedule_list_t *cur_event = event_list;
    schedule_list_t *prv_event = NULL;
    while(cur_event != NULL && (int24_t)(new_event->date - cur_event->date) > 0) {
        prv_event = cur_event;
        cur_event = cur_event->next;
    }
    if(prv_event != NULL) {
        new_event->next = prv_event->next;
        prv_event->next = new_event;
    } else {
        new_event->next = event_list;
        event_list = new_event;
    }
}

void update_event_time() {
    schedule_list_t *cur_event = event_list;
    event_list = cur_event->next;
    if(cur_event->every != 0) {
        cur_event->date = usb_GetCounter() + cur_event->every;
        insert_event(cur_event);
    } else {
        if(cur_event->destructor_callback != NULL) {
            cur_event->destructor_callback(cur_event->user_data);
         }
        free(cur_event);
    }
}

web_status_t dispatch_time_events() {
    const uint24_t now = usb_GetCounter();
    web_status_t status;
    schedule_list_t *cur_event;
    while(event_list != NULL && (int24_t)(now - event_list->date) > 0) {
        cur_event = event_list;
        update_event_time();
        status = cur_event->schedule_callback(cur_event->user_data);
        if(status != WEB_SUCCESS) {
            return status;
        }
    }
    return WEB_SUCCESS;
}

web_status_t boolean_scheduler(web_callback_data_t *user_data) {
	bool *is_timeout = (bool *)user_data;
	*is_timeout = true;
	return WEB_SUCCESS;
}

void boolean_destructor(web_callback_data_t *user_data) {
	bool *is_timeout = (bool *)user_data;
	*is_timeout = true;
}
