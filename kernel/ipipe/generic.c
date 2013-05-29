/* -*- linux-c -*-
 * linux/kernel/ipipe/generic.c
 *
 * Copyright (C) 2002-2005 Philippe Gerum.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 * USA; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Architecture-independent I-PIPE services.
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#endif	/* CONFIG_PROC_FS */
#include <linux/interrupt.h>
#include <asm/hw_irq.h>

MODULE_DESCRIPTION("I-pipe");
MODULE_LICENSE("GPL");

static int __ipipe_ptd_key_count;

static unsigned long __ipipe_ptd_key_map;

/* ipipe_register_domain() -- Link a new domain to the pipeline. */

int ipipe_register_domain(struct ipipe_domain *ipd,
			  struct ipipe_domain_attr *attr)
{
	struct list_head *pos;
	unsigned long flags;

	if (ipipe_current_domain != ipipe_root_domain) {
		printk(KERN_WARNING
		       "I-pipe: Only the root domain may register a new domain.\n");
		return -EPERM;
	}

	if (attr->priority == IPIPE_HEAD_PRIORITY &&
	    test_bit(IPIPE_AHEAD_FLAG,&__ipipe_pipeline_head()->flags))
		return -EAGAIN;	/* Cannot override current head. */

	flags = ipipe_critical_enter(NULL);

	list_for_each(pos, &__ipipe_pipeline) {
		struct ipipe_domain *_ipd =
			list_entry(pos, struct ipipe_domain, p_link);
		if (_ipd->domid == attr->domid)
			break;
	}

	ipipe_critical_exit(flags);

	if (pos != &__ipipe_pipeline)
		/* A domain with the given id already exists -- fail. */
		return -EBUSY;

	ipd->name = attr->name;
	ipd->domid = attr->domid;
	ipd->pdd = attr->pdd;
	ipd->flags = 0;

	if (attr->priority == IPIPE_HEAD_PRIORITY) {
		ipd->priority = INT_MAX;
		__set_bit(IPIPE_AHEAD_FLAG,&ipd->flags);
	}
	else
		ipd->priority = attr->priority;

	__ipipe_init_stage(ipd);

	INIT_LIST_HEAD(&ipd->p_link);

#ifdef CONFIG_PROC_FS
	__ipipe_add_domain_proc(ipd);
#endif /* CONFIG_PROC_FS */

	flags = ipipe_critical_enter(NULL);

	list_for_each(pos, &__ipipe_pipeline) {
		struct ipipe_domain *_ipd =
			list_entry(pos, struct ipipe_domain, p_link);
		if (ipd->priority > _ipd->priority)
			break;
	}

	list_add_tail(&ipd->p_link, pos);

	ipipe_critical_exit(flags);

	printk(KERN_WARNING "I-pipe: Domain %s registered.\n", ipd->name);

	/*
	 * Finally, allow the new domain to perform its initialization
	 * chores.
	 */

	if (attr->entry != NULL) {
		ipipe_declare_cpuid;

		ipipe_lock_cpu(flags);

		ipipe_percpu_domain[cpuid] = ipd;
		attr->entry();
		ipipe_percpu_domain[cpuid] = ipipe_root_domain;

		ipipe_load_cpuid();	/* Processor might have changed. */

		if (ipipe_root_domain->cpudata[cpuid].irq_pending_hi != 0 &&
		    !test_bit(IPIPE_STALL_FLAG,
			      &ipipe_root_domain->cpudata[cpuid].status))
			__ipipe_sync_stage(IPIPE_IRQMASK_ANY);

		ipipe_unlock_cpu(flags);
	}

	return 0;
}

/* ipipe_unregister_domain() -- Remove a domain from the pipeline. */

int ipipe_unregister_domain(struct ipipe_domain *ipd)
{
	unsigned long flags;

	if (ipipe_current_domain != ipipe_root_domain) {
		printk(KERN_WARNING
		       "I-pipe: Only the root domain may unregister a domain.\n");
		return -EPERM;
	}

	if (ipd == ipipe_root_domain) {
		printk(KERN_WARNING
		       "I-pipe: Cannot unregister the root domain.\n");
		return -EPERM;
	}
#ifdef CONFIG_SMP
	{
		int nr_cpus = num_online_cpus(), _cpuid;
		unsigned irq;

		/*
		 * In the SMP case, wait for the logged events to drain on
		 * other processors before eventually removing the domain
		 * from the pipeline.
		 */

		ipipe_unstall_pipeline_from(ipd);

		flags = ipipe_critical_enter(NULL);

		for (irq = 0; irq < IPIPE_NR_IRQS; irq++) {
			clear_bit(IPIPE_HANDLE_FLAG, &ipd->irqs[irq].control);
			clear_bit(IPIPE_STICKY_FLAG, &ipd->irqs[irq].control);
			set_bit(IPIPE_PASS_FLAG, &ipd->irqs[irq].control);
		}

		ipipe_critical_exit(flags);

		for (_cpuid = 0; _cpuid < nr_cpus; _cpuid++)
			for (irq = 0; irq < IPIPE_NR_IRQS; irq++)
				while (ipd->cpudata[_cpuid].irq_counters[irq].pending_hits > 0)
					cpu_relax();
	}
#endif	/* CONFIG_SMP */

#ifdef CONFIG_PROC_FS
	__ipipe_remove_domain_proc(ipd);
#endif /* CONFIG_PROC_FS */

	/*
	 * Simply remove the domain from the pipeline and we are almost done.
	 */

	flags = ipipe_critical_enter(NULL);
	list_del_init(&ipd->p_link);
	ipipe_critical_exit(flags);

	__ipipe_cleanup_domain(ipd);

	printk(KERN_WARNING "I-pipe: Domain %s unregistered.\n", ipd->name);

	return 0;
}

/*
 * ipipe_propagate_irq() -- Force a given IRQ propagation on behalf of
 * a running interrupt handler to the next domain down the pipeline.
 * ipipe_schedule_irq() -- Does almost the same as above, but attempts
 * to pend the interrupt for the current domain first.
 */
int fastcall __ipipe_schedule_irq(unsigned irq, struct list_head *head)
{
	struct list_head *ln;
	unsigned long flags;
	ipipe_declare_cpuid;

	if (irq >= IPIPE_NR_IRQS ||
	    (ipipe_virtual_irq_p(irq)
	     && !test_bit(irq - IPIPE_VIRQ_BASE, &__ipipe_virtual_irq_map)))
		return -EINVAL;

	ipipe_lock_cpu(flags);

	ln = head;

	while (ln != &__ipipe_pipeline) {
		struct ipipe_domain *ipd =
			list_entry(ln, struct ipipe_domain, p_link);

		if (test_bit(IPIPE_HANDLE_FLAG, &ipd->irqs[irq].control)) {
			ipd->cpudata[cpuid].irq_counters[irq].total_hits++;
			ipd->cpudata[cpuid].irq_counters[irq].pending_hits++;
			__ipipe_set_irq_bit(ipd, cpuid, irq);
			ipipe_unlock_cpu(flags);
			return 1;
		}

		ln = ipd->p_link.next;
	}

	ipipe_unlock_cpu(flags);

	return 0;
}

/* ipipe_free_virq() -- Release a virtual/soft interrupt. */

int ipipe_free_virq(unsigned virq)
{
	if (!ipipe_virtual_irq_p(virq))
		return -EINVAL;

	clear_bit(virq - IPIPE_VIRQ_BASE, &__ipipe_virtual_irq_map);

	return 0;
}

void ipipe_init_attr(struct ipipe_domain_attr *attr)
{
	attr->name = "anon";
	attr->domid = 1;
	attr->entry = NULL;
	attr->priority = IPIPE_ROOT_PRIO;
	attr->pdd = NULL;
}

/*
 * ipipe_catch_event() -- Interpose or remove an event handler for a
 * given domain.
 */
ipipe_event_handler_t ipipe_catch_event(struct ipipe_domain *ipd,
					unsigned event,
					ipipe_event_handler_t handler)
{
	ipipe_event_handler_t old_handler;
	unsigned long flags;
	int self = 0, cpuid;

	if (event & IPIPE_EVENT_SELF) {
		event &= ~IPIPE_EVENT_SELF;
		self = 1;
	}

	if (event >= IPIPE_NR_EVENTS)
		return NULL;

	flags = ipipe_critical_enter(NULL);

	if (!(old_handler = xchg(&ipd->evhand[event],handler)))	{
		if (handler) {
			if (self)
				ipd->evself |= (1LL << event);
			else
				__ipipe_event_monitors[event]++;
		}
	}
	else if (!handler) {
		if (ipd->evself & (1LL << event))
			ipd->evself &= ~(1LL << event);
		else
			__ipipe_event_monitors[event]--;
	} else if ((ipd->evself & (1LL << event)) && !self) {
			__ipipe_event_monitors[event]++;
			ipd->evself &= ~(1LL << event);
	} else if (!(ipd->evself & (1LL << event)) && self) {
			__ipipe_event_monitors[event]--;
			ipd->evself |= (1LL << event);
	}
	
	ipipe_critical_exit(flags);

	if (!handler && ipipe_root_domain_p) {
		/*
		 * If we cleared a handler on behalf of the root
		 * domain, we have to wait for any current invocation
		 * to drain, since our caller might subsequently unmap
		 * the target domain. To this aim, this code
		 * synchronizes with __ipipe_dispatch_event(),
		 * guaranteeing that either the dispatcher sees a null
		 * handler in which case it discards the invocation
		 * (which also prevents from entering a livelock), or
		 * finds a valid handler and calls it. Symmetrically,
		 * ipipe_catch_event() ensures that the called code
		 * won't be unmapped under our feet until the event
		 * synchronization flag is cleared for the given event
		 * on all CPUs.
		 */

		for_each_online_cpu(cpuid) {
			while (ipd->cpudata[cpuid].evsync & (1LL << event)) {
				set_current_state(TASK_INTERRUPTIBLE);
				schedule_timeout(HZ / 50);
			}
		}
	}

	return old_handler;
}

cpumask_t ipipe_set_irq_affinity (unsigned irq, cpumask_t cpumask)
{
#ifdef CONFIG_SMP
	if (irq >= IPIPE_NR_XIRQS)
		/* Allow changing affinity of external IRQs only. */
		return CPU_MASK_NONE;

	if (num_online_cpus() > 1)
		/* Allow changing affinity of external IRQs only. */
		return __ipipe_set_irq_affinity(irq,cpumask);
#endif /* CONFIG_SMP */

	return CPU_MASK_NONE;
}

int fastcall ipipe_send_ipi (unsigned ipi, cpumask_t cpumask)

{
#ifdef CONFIG_SMP
	switch (ipi) {

	case IPIPE_SERVICE_IPI0:
	case IPIPE_SERVICE_IPI1:
	case IPIPE_SERVICE_IPI2:
	case IPIPE_SERVICE_IPI3:

		break;

	default:

		return -EINVAL;
	}

	return __ipipe_send_ipi(ipi,cpumask);
#endif /* CONFIG_SMP */

	return -EINVAL;
}

int ipipe_alloc_ptdkey (void)
{
	unsigned long flags;
	int key = -1;

	spin_lock_irqsave_hw(&__ipipe_pipelock,flags);

	if (__ipipe_ptd_key_count < IPIPE_ROOT_NPTDKEYS) {
		key = ffz(__ipipe_ptd_key_map);
		set_bit(key,&__ipipe_ptd_key_map);
		__ipipe_ptd_key_count++;
	}

	spin_unlock_irqrestore_hw(&__ipipe_pipelock,flags);

	return key;
}

int ipipe_free_ptdkey (int key)
{
	unsigned long flags;

	if (key < 0 || key >= IPIPE_ROOT_NPTDKEYS)
		return -EINVAL;

	spin_lock_irqsave_hw(&__ipipe_pipelock,flags);

	if (test_and_clear_bit(key,&__ipipe_ptd_key_map))
		__ipipe_ptd_key_count--;

	spin_unlock_irqrestore_hw(&__ipipe_pipelock,flags);

	return 0;
}

int fastcall ipipe_set_ptd (int key, void *value)

{
	if (key < 0 || key >= IPIPE_ROOT_NPTDKEYS)
		return -EINVAL;

	current->ptd[key] = value;

	return 0;
}

void *fastcall ipipe_get_ptd (int key)

{
	if (key < 0 || key >= IPIPE_ROOT_NPTDKEYS)
		return NULL;

	return current->ptd[key];
}

EXPORT_SYMBOL(ipipe_register_domain);
EXPORT_SYMBOL(ipipe_unregister_domain);
EXPORT_SYMBOL(ipipe_free_virq);
EXPORT_SYMBOL(ipipe_init_attr);
EXPORT_SYMBOL(ipipe_catch_event);
EXPORT_SYMBOL(ipipe_alloc_ptdkey);
EXPORT_SYMBOL(ipipe_free_ptdkey);
EXPORT_SYMBOL(ipipe_set_ptd);
EXPORT_SYMBOL(ipipe_get_ptd);
EXPORT_SYMBOL(ipipe_set_irq_affinity);
EXPORT_SYMBOL(ipipe_send_ipi);
EXPORT_SYMBOL(__ipipe_schedule_irq);
