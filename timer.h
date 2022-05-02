
#ifndef TIMER_H__

#define TIMER_H__ "timer.h"

#include "list.h"


struct timer_list {
	struct list_head entry;	
	unsigned long expires;
	void (*function)(unsigned long);
	unsigned long data;
};

void  init_timer(struct timer_list * timer);
static inline void setup_timer(struct timer_list * timer,
				void (*function)(unsigned long),
				unsigned long data)
{
	timer->function = function;
	timer->data = data;
	init_timer(timer);
}



static inline int timer_pending(const struct timer_list * timer)
{
	return timer->entry.next != NULL;
}

int  init_timers_cpu(void);
void run_timers(void);

void add_timer(struct timer_list *timer);
int del_timer(struct timer_list * timer);
int __mod_timer(struct timer_list *timer, unsigned long expires);
int mod_timer(struct timer_list *timer, unsigned long expires);

void jiffies_init();
unsigned long  jiffies_get();

#ifdef HZ
#undef HZ
#endif

#define HZ 1000


#define jiffies  jiffies_get()

#endif /*TIMER_H__*/
