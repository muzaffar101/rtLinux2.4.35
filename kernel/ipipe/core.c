/* -*- linux-c -*-
 * linux/kernel/ipipe/core.c
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
 * Architecture-independent I-PIPE core support.
 */

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/bitops.h>
#include <linux/ipipe.h>
#include <linux/interrupt.h>
#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#endif	/* CONFIG_PROC_FS */

struct ipipe_domain ipipe_root =
	{ .cpudata = {[0 ... IPIPE_NR_CPUS-1] =
		{ .status = (1<<IPIPE_STALL_FLAG) } } };

struct ipipe_domain *ipipe_percpu_domain[IPIPE_NR_CPUS] =
	{[0 ... IPIPE_NR_CPUS - 1] = &ipipe_root };

ipipe_spinlock_t __ipipe_pipelock = IPIPE_SPIN_LOCK_UNLOCKED;

struct list_head __ipipe_pipeline;

unsigned long __ipipe_virtual_irq_map = 0;

unsigned __ipipe_printk_virq;

int __ipipe_event_monitors[IPIPE_NR_EVENTS];

/*
 * ipipe_init() -- Initialization routine of the IPIPE layer. Called
 * by the host kernel early during the boot procedure.
 */
void ipipe_init(void)
{
	struct ipipe_domain *ipd = &ipipe_root;

	__ipipe_check_platform();	/* Do platform dependent checks first. */

	/*
	 * A lightweight registration code for the root domain. We are
	 * running on the boot CPU, hw interrupts are off, and
	 * secondary CPUs are still lost in space.
	 */

	INIT_LIST_HEAD(&__ipipe_pipeline);

	ipd->name = "Linux";
	ipd->domid = IPIPE_ROOT_ID;
	ipd->priority = IPIPE_ROOT_PRIO;

	__ipipe_init_stage(ipd);

	INIT_LIST_HEAD(&ipd->p_link);
	list_add_tail(&ipd->p_link, &__ipipe_pipeline);

	__ipipe_init_platform();

	__ipipe_printk_virq = ipipe_alloc_virq();	/* Cannot fail here. */
	ipd->irqs[__ipipe_printk_virq].handler = &__ipipe_flush_printk;
	ipd->irqs[__ipipe_printk_virq].cookie = NULL;
	ipd->irqs[__ipipe_printk_virq].acknowledge = NULL;
	ipd->irqs[__ipipe_printk_virq].control = IPIPE_HANDLE_MASK;

	__ipipe_enable_pipeline();

	printk(KERN_INFO "I-pipe %s: pipeline enabled.\n",
	       IPIPE_VERSION_STRING);
}

void __ipipe_init_stage(struct ipipe_domain *ipd)
{
	int cpuid, n;

	for (cpuid = 0; cpuid < IPIPE_NR_CPUS; cpuid++) {
		ipd->cpudata[cpuid].irq_pending_hi = 0;

		for (n = 0; n < IPIPE_IRQ_IWORDS; n++)
			ipd->cpudata[cpuid].irq_pending_lo[n] = 0;

		for (n = 0; n < IPIPE_NR_IRQS; n++) {
			ipd->cpudata[cpuid].irq_counters[n].pending_hits = 0;
			ipd->cpudata[cpuid].irq_counters[n].total_hits = 0;
		}
		ipd->cpudata[cpuid].evsync = 0;
	}

	for (n = 0; n < IPIPE_NR_IRQS; n++) {
		ipd->irqs[n].acknowledge = NULL;
		ipd->irqs[n].handler = NULL;
		ipd->irqs[n].control = IPIPE_PASS_MASK;	/* Pass but don't handle */
	}

	for (n = 0; n < IPIPE_NR_EVENTS; n++)
		ipd->evhand[n] = NULL;

	ipd->evself = 0;

#ifdef CONFIG_SMP
	ipd->irqs[IPIPE_CRITICAL_IPI].acknowledge = &__ipipe_ack_system_irq;
	ipd->irqs[IPIPE_CRITICAL_IPI].handler = &__ipipe_do_critical_sync;
	ipd->irqs[IPIPE_CRITICAL_IPI].cookie = NULL;
	/* Immediately handle in the current domain but *never* pass */
	ipd->irqs[IPIPE_CRITICAL_IPI].control =
		IPIPE_HANDLE_MASK|IPIPE_STICKY_MASK|IPIPE_SYSTEM_MASK;
#endif	/* CONFIG_SMP */
}

void __ipipe_cleanup_domain(struct ipipe_domain *ipd)
{
	ipipe_unstall_pipeline_from(ipd);

#ifdef CONFIG_SMP
	{
		int cpu;

		for_each_online_cpu(cpu) {
			while (ipd->cpudata[cpu].irq_pending_hi != 0)
				cpu_relax();
		}
	}
#endif	/* CONFIG_SMP */
}

void __ipipe_stall_root(void)
{
	ipipe_declare_cpuid;
	unsigned long flags;

	ipipe_get_cpu(flags); /* Care for migration. */
	set_bit(IPIPE_STALL_FLAG, &ipipe_root_domain->cpudata[cpuid].status);
	ipipe_put_cpu(flags);
}

void __ipipe_unstall_root(void)
{
	ipipe_declare_cpuid;

	local_irq_disable_hw();

	ipipe_load_cpuid();

	__clear_bit(IPIPE_STALL_FLAG, &ipipe_root_domain->cpudata[cpuid].status);

	if (unlikely(ipipe_root_domain->cpudata[cpuid].irq_pending_hi != 0))
		__ipipe_sync_pipeline(IPIPE_IRQMASK_ANY);

	local_irq_enable_hw();
}

unsigned long __ipipe_test_root(void)
{
	unsigned long flags, x;
	ipipe_declare_cpuid;

	ipipe_get_cpu(flags); /* Care for migration. */
	x = test_bit(IPIPE_STALL_FLAG, &ipipe_root_domain->cpudata[cpuid].status);
	ipipe_put_cpu(flags);

	return x;
}

unsigned long __ipipe_test_and_stall_root(void)
{
	unsigned long flags, x;
	ipipe_declare_cpuid;

	ipipe_get_cpu(flags); /* Care for migration. */
	x = test_and_set_bit(IPIPE_STALL_FLAG,
			     &ipipe_root_domain->cpudata[cpuid].status);
	ipipe_put_cpu(flags);

	return x;
}

void fastcall __ipipe_restore_root(unsigned long x)
{
	if (x)
		__ipipe_stall_root();
	else
		__ipipe_unstall_root();
}

void fastcall ipipe_stall_pipeline_from(struct ipipe_domain *ipd)
{
	ipipe_declare_cpuid;
#ifdef CONFIG_SMP
	unsigned long flags;

	ipipe_lock_cpu(flags); /* Care for migration. */

	__set_bit(IPIPE_STALL_FLAG, &ipd->cpudata[cpuid].status);

	if (!__ipipe_pipeline_head_p(ipd))
		ipipe_unlock_cpu(flags);
#else	/* CONFIG_SMP */
	set_bit(IPIPE_STALL_FLAG, &ipd->cpudata[cpuid].status);

	if (__ipipe_pipeline_head_p(ipd))
		local_irq_disable_hw();
#endif	/* CONFIG_SMP */
}

unsigned long fastcall ipipe_test_and_stall_pipeline_from(struct ipipe_domain *ipd)
{
	ipipe_declare_cpuid;
	unsigned long s;
#ifdef CONFIG_SMP
	unsigned long flags;

	ipipe_lock_cpu(flags); /* Care for migration. */

	s = __test_and_set_bit(IPIPE_STALL_FLAG, &ipd->cpudata[cpuid].status);

	if (!__ipipe_pipeline_head_p(ipd))
		ipipe_unlock_cpu(flags);
#else	/* CONFIG_SMP */
	s = test_and_set_bit(IPIPE_STALL_FLAG, &ipd->cpudata[cpuid].status);

	if (__ipipe_pipeline_head_p(ipd))
		local_irq_disable_hw();
#endif	/* CONFIG_SMP */

	return s;
}

/*
 * ipipe_unstall_pipeline_from() -- Unstall the pipeline and
 * synchronize pending interrupts for a given domain. See
 * __ipipe_walk_pipeline() for more information.
 */
void fastcall ipipe_unstall_pipeline_from(struct ipipe_domain *ipd)
{
	struct list_head *pos;
	unsigned long flags;
	ipipe_declare_cpuid;

	ipipe_lock_cpu(flags);

	__clear_bit(IPIPE_STALL_FLAG, &ipd->cpudata[cpuid].status);

	if (ipd == ipipe_percpu_domain[cpuid])
		pos = &ipd->p_link;
	else
		pos = __ipipe_pipeline.next;

	__ipipe_walk_pipeline(pos, cpuid);

	if (__ipipe_pipeline_head_p(ipd))
		local_irq_enable_hw();
	else
		ipipe_unlock_cpu(flags);
}

unsigned long fastcall ipipe_test_and_unstall_pipeline_from(struct ipipe_domain *ipd)
{
	unsigned long flags, x;
	ipipe_declare_cpuid;

	ipipe_get_cpu(flags);
	x = test_bit(IPIPE_STALL_FLAG, &ipd->cpudata[cpuid].status);
	ipipe_unstall_pipeline_from(ipd);
	ipipe_put_cpu(flags);

	return x;
}

void fastcall ipipe_restore_pipeline_from(struct ipipe_domain *ipd,
					  unsigned long x)
{
	if (x)
		ipipe_stall_pipeline_from(ipd);
	else
		ipipe_unstall_pipeline_from(ipd);
}

void ipipe_unstall_pipeline_head(void)
{
	struct ipipe_domain *head;
	unsigned long flags;
	ipipe_declare_cpuid;

	ipipe_lock_cpu(flags);
	head = __ipipe_pipeline_head();
	__clear_bit(IPIPE_STALL_FLAG, &head->cpudata[cpuid].status);

	if (unlikely(head->cpudata[cpuid].irq_pending_hi != 0)) {
		if (likely(head == ipipe_percpu_domain[cpuid]))
			__ipipe_sync_pipeline(IPIPE_IRQMASK_ANY);
		else
			__ipipe_walk_pipeline(&head->p_link, cpuid);
        }

	local_irq_enable_hw();
}

void fastcall __ipipe_restore_pipeline_head(struct ipipe_domain *head, unsigned long x)
{
	ipipe_declare_cpuid;
	unsigned long flags;

	ipipe_get_cpu(flags);

	if (x) {
#ifdef CONFIG_DEBUG_KERNEL
		static int warned;
		if (!warned && test_and_set_bit(IPIPE_STALL_FLAG, &head->cpudata[cpuid].status)) {
			/*
			 * Already stalled albeit ipipe_restore_pipeline_head()
			 * should have detected it? Send a warning once.\n");
			 */
			warned = 1;
			printk(KERN_WARNING
				   "I-pipe: ipipe_restore_pipeline_head() optimization failed.\n");
			dump_stack();
		}
#else /* !CONFIG_DEBUG_KERNEL */
		set_bit(IPIPE_STALL_FLAG, &head->cpudata[cpuid].status);
#endif /* CONFIG_DEBUG_KERNEL */
	}
	else {
		/* Hw interrupts must be off already. */
		__clear_bit(IPIPE_STALL_FLAG, &head->cpudata[cpuid].status);
		if (unlikely(head->cpudata[cpuid].irq_pending_hi != 0)) {
			if (likely(head == ipipe_percpu_domain[cpuid]))
				__ipipe_sync_pipeline(IPIPE_IRQMASK_ANY);
			else
				__ipipe_walk_pipeline(&head->p_link, cpuid);
		}
		local_irq_enable_hw();
	}
}

/* __ipipe_walk_pipeline(): Plays interrupts pending in the log. Must
   be called with local hw interrupts disabled. */

void fastcall __ipipe_walk_pipeline(struct list_head *pos, int cpuid)
{
	struct ipipe_domain *this_domain = ipipe_percpu_domain[cpuid];

	while (pos != &__ipipe_pipeline) {
		struct ipipe_domain *next_domain =
		    list_entry(pos, struct ipipe_domain, p_link);

		if (test_bit
		    (IPIPE_STALL_FLAG, &next_domain->cpudata[cpuid].status))
			break;	/* Stalled stage -- do not go further. */

		if (next_domain->cpudata[cpuid].irq_pending_hi != 0) {

			if (next_domain == this_domain)
				__ipipe_sync_stage(IPIPE_IRQMASK_ANY);
			else {
				__ipipe_switch_to(this_domain, next_domain,
						  cpuid);

				ipipe_load_cpuid();	/* Processor might have changed. */

				if (this_domain->cpudata[cpuid].
				    irq_pending_hi != 0
				    && !test_bit(IPIPE_STALL_FLAG,
						 &this_domain->cpudata[cpuid].status))
					__ipipe_sync_stage(IPIPE_IRQMASK_ANY);
			}

			break;
		} else if (next_domain == this_domain)
			break;

		pos = next_domain->p_link.next;
	}
}

/*
 * ipipe_suspend_domain() -- Suspend the current domain, switching to
 * the next one which has pending work down the pipeline.
 */
void ipipe_suspend_domain(void)
{
	struct ipipe_domain *this_domain, *next_domain;
	struct list_head *ln;
	unsigned long flags;
	ipipe_declare_cpuid;

	ipipe_lock_cpu(flags);

	this_domain = next_domain = ipipe_percpu_domain[cpuid];

	__clear_bit(IPIPE_STALL_FLAG, &this_domain->cpudata[cpuid].status);

	if (this_domain->cpudata[cpuid].irq_pending_hi != 0)
		goto sync_stage;

	for (;;) {
		ln = next_domain->p_link.next;

		if (ln == &__ipipe_pipeline)
			break;

		next_domain = list_entry(ln, struct ipipe_domain, p_link);

		if (test_bit(IPIPE_STALL_FLAG,
			     &next_domain->cpudata[cpuid].status))
			break;

		if (next_domain->cpudata[cpuid].irq_pending_hi == 0)
			continue;

		ipipe_percpu_domain[cpuid] = next_domain;

sync_stage:

		__ipipe_sync_stage(IPIPE_IRQMASK_ANY);

		ipipe_load_cpuid();	/* Processor might have changed. */

		if (ipipe_percpu_domain[cpuid] != next_domain)
			/*
			 * Something has changed the current domain under our
			 * feet, recycling the register set; take note.
			 */
			this_domain = ipipe_percpu_domain[cpuid];
	}

	ipipe_percpu_domain[cpuid] = this_domain;

	ipipe_unlock_cpu(flags);
}

/* ipipe_alloc_virq() -- Allocate a pipelined virtual/soft interrupt.
 * Virtual interrupts are handled in exactly the same way than their
 * hw-generated counterparts wrt pipelining.
 */
unsigned ipipe_alloc_virq(void)
{
	unsigned long flags, irq = 0;
	int ipos;

	spin_lock_irqsave_hw(&__ipipe_pipelock, flags);

	if (__ipipe_virtual_irq_map != ~0) {
		ipos = ffz(__ipipe_virtual_irq_map);
		set_bit(ipos, &__ipipe_virtual_irq_map);
		irq = ipos + IPIPE_VIRQ_BASE;
	}

	spin_unlock_irqrestore_hw(&__ipipe_pipelock, flags);

	return irq;
}

/*
 * ipipe_virtualize_irq() -- Attach a handler (and optionally a hw
 * acknowledge routine) to an interrupt for the given domain.
 */

int ipipe_virtualize_irq(struct ipipe_domain *ipd,
			 unsigned irq,
			 ipipe_irq_handler_t handler,
			 void *cookie,
			 ipipe_irq_ackfn_t acknowledge,
			 unsigned modemask)
{
	unsigned long flags;
	int err;

	if (irq >= IPIPE_NR_IRQS)
		return -EINVAL;

	if (ipd->irqs[irq].control & IPIPE_SYSTEM_MASK)
		return -EPERM;

	if (!test_bit(IPIPE_AHEAD_FLAG, &ipd->flags))
		/* Silently unwire interrupts for non-heading domains. */
		modemask &= ~IPIPE_WIRED_MASK;

	spin_lock_irqsave_hw(&__ipipe_pipelock, flags);

	if (handler != NULL) {

		if (handler == IPIPE_SAME_HANDLER) {
			handler = ipd->irqs[irq].handler;
			cookie = ipd->irqs[irq].cookie;

			if (handler == NULL) {
				err = -EINVAL;
				goto unlock_and_exit;
			}
		} else if ((modemask & IPIPE_EXCLUSIVE_MASK) != 0 &&
			   ipd->irqs[irq].handler != NULL) {
			err = -EBUSY;
			goto unlock_and_exit;
		}

		if ((modemask & (IPIPE_SHARED_MASK | IPIPE_PASS_MASK)) ==
		    IPIPE_SHARED_MASK) {
			err = -EINVAL;
			goto unlock_and_exit;
		}

		/* Wired interrupts can only be delivered to domains
		 * always heading the pipeline. */

		if ((modemask & IPIPE_WIRED_MASK) != 0) {
			if ((modemask & (IPIPE_SHARED_MASK | IPIPE_PASS_MASK | IPIPE_STICKY_MASK)) != 0) {
				err = -EINVAL;
				goto unlock_and_exit;
			}
			modemask |= (IPIPE_HANDLE_MASK);
		}

		if ((modemask & IPIPE_STICKY_MASK) != 0)
			modemask |= IPIPE_HANDLE_MASK;
	} else
		modemask &=
		    ~(IPIPE_HANDLE_MASK | IPIPE_STICKY_MASK |
		      IPIPE_SHARED_MASK | IPIPE_EXCLUSIVE_MASK | IPIPE_WIRED_MASK);

	if (acknowledge == NULL) {
		if ((modemask & IPIPE_SHARED_MASK) == 0) {
			if (!ipipe_virtual_irq_p(irq)) {
				/* Acknowledge handler unspecified for a hw
				   interrupt -- this is ok in non-shared
				   management mode, but we will force the use
				   of the Linux-defined handler instead. */
				acknowledge = ipipe_root_domain->irqs[irq].acknowledge;
			}
		}
		else {
			/* A valid acknowledge handler to be called in shared mode
			   is required when declaring a shared IRQ. */
			err = -EINVAL;
			goto unlock_and_exit;
		}
	}

	ipd->irqs[irq].handler = handler;
	ipd->irqs[irq].cookie = cookie;
	ipd->irqs[irq].acknowledge = acknowledge;
	ipd->irqs[irq].control = modemask;

	if (irq < NR_IRQS && handler != NULL && !ipipe_virtual_irq_p(irq)) {
		__ipipe_enable_irqdesc(irq);

		if ((modemask & IPIPE_ENABLE_MASK) != 0) {
			if (ipd != ipipe_current_domain) {
				/* IRQ enable/disable state is domain-sensitive, so we may
				   not change it for another domain. What is allowed
				   however is forcing some domain to handle an interrupt
				   source, by passing the proper 'ipd' descriptor which
				   thus may be different from ipipe_current_domain. */
				err = -EPERM;
				goto unlock_and_exit;
			}
			
			__ipipe_enable_irq(irq);
		}
	}

	err = 0;

      unlock_and_exit:

	spin_unlock_irqrestore_hw(&__ipipe_pipelock, flags);

	return err;
}

/* ipipe_control_irq() -- Change modes of a pipelined interrupt for
 * the current domain. */

int ipipe_control_irq(unsigned irq, unsigned clrmask, unsigned setmask)
{
	unsigned long flags;

	if (irq >= IPIPE_NR_IRQS)
		return -EINVAL;

	if (ipipe_current_domain->irqs[irq].control & IPIPE_SYSTEM_MASK)
		return -EPERM;

	if (((setmask | clrmask) & IPIPE_SHARED_MASK) != 0)
		return -EINVAL;

	if (ipipe_current_domain->irqs[irq].handler == NULL)
		setmask &= ~(IPIPE_HANDLE_MASK | IPIPE_STICKY_MASK);

	if ((setmask & IPIPE_STICKY_MASK) != 0)
		setmask |= IPIPE_HANDLE_MASK;

	if ((clrmask & (IPIPE_HANDLE_MASK | IPIPE_STICKY_MASK)) != 0)	/* If one goes, both go. */
		clrmask |= (IPIPE_HANDLE_MASK | IPIPE_STICKY_MASK);

	spin_lock_irqsave_hw(&__ipipe_pipelock, flags);

	ipipe_current_domain->irqs[irq].control &= ~clrmask;
	ipipe_current_domain->irqs[irq].control |= setmask;

	if ((setmask & IPIPE_ENABLE_MASK) != 0)
		__ipipe_enable_irq(irq);
	else if ((clrmask & IPIPE_ENABLE_MASK) != 0)
		__ipipe_disable_irq(irq);

	spin_unlock_irqrestore_hw(&__ipipe_pipelock, flags);

	return 0;
}

/* __ipipe_dispatch_event() -- Low-level event dispatcher. */

int fastcall __ipipe_dispatch_event (unsigned event, void *data)
{
	struct ipipe_domain *start_domain, *this_domain, *next_domain;
	ipipe_event_handler_t evhand;
	struct list_head *pos, *npos;
	unsigned long flags;
	ipipe_declare_cpuid;
	int propagate = 1;

	ipipe_lock_cpu(flags);

	start_domain = this_domain = ipipe_percpu_domain[cpuid];

	list_for_each_safe(pos,npos,&__ipipe_pipeline) {

		/*
		 * Note: Domain migration may occur while running
		 * event or interrupt handlers, in which case the
		 * current register set is going to be recycled for a
		 * different domain than the initiating one. We do
		 * care for that, always tracking the current domain
		 * descriptor upon return from those handlers.
		 */
		next_domain = list_entry(pos,struct ipipe_domain,p_link);

		/*
		 * Keep a cached copy of the handler's address since
		 * ipipe_catch_event() may clear it under our feet.
		 */

		evhand = next_domain->evhand[event];

		if (evhand != NULL) {
			ipipe_percpu_domain[cpuid] = next_domain;
			next_domain->cpudata[cpuid].evsync |= (1LL << event);
			ipipe_unlock_cpu(flags);
			propagate = !evhand(event,start_domain,data);
			ipipe_lock_cpu(flags);
			next_domain->cpudata[cpuid].evsync &= ~(1LL << event);
			if (ipipe_percpu_domain[cpuid] != next_domain)
				this_domain = ipipe_percpu_domain[cpuid];
		}

		if (next_domain != ipipe_root_domain &&	/* NEVER sync the root stage here. */
		    next_domain->cpudata[cpuid].irq_pending_hi != 0 &&
		    !test_bit(IPIPE_STALL_FLAG,&next_domain->cpudata[cpuid].status)) {
			ipipe_percpu_domain[cpuid] = next_domain;
			__ipipe_sync_pipeline(IPIPE_IRQMASK_ANY);
			ipipe_load_cpuid();
			if (ipipe_percpu_domain[cpuid] != next_domain)
				this_domain = ipipe_percpu_domain[cpuid];
		}

		ipipe_percpu_domain[cpuid] = this_domain;

		if (next_domain == this_domain || !propagate)
			break;
	}

	ipipe_unlock_cpu(flags);

	return !propagate;
}

/*
 * __ipipe_dispatch_wired -- Wired interrupt dispatcher. Wired
 * interrupts are immediately and unconditionally delivered to the
 * domain heading the pipeline upon receipt, and such domain must have
 * been registered as an invariant head for the system (priority ==
 * IPIPE_HEAD_PRIORITY). The motivation for using wired interrupts is
 * to get an extra-fast dispatching path for those IRQs, by relying on
 * a straightforward logic based on assumptions that must always be
 * true for invariant head domains.  The following assumptions are
 * made when dealing with such interrupts:
 *
 * 1- Wired interrupts are purely dynamic, i.e. the decision to
 * propagate them down the pipeline must be done from the head domain
 * ISR.
 * 2- Wired interrupts cannot be shared or sticky.
 * 3- The root domain cannot be an invariant pipeline head, in
 * consequence of what the root domain cannot handle wired
 * interrupts.
 * 4- Wired interrupts must have a valid acknowledge handler for the
 * head domain (if needed), and in any case, must not rely on handlers
 * provided by lower priority domains during the acknowledge cycle
 * (see __ipipe_handle_irq).
 *
 * Called with hw interrupts off.
 */
int fastcall __ipipe_dispatch_wired(struct ipipe_domain *head, unsigned irq)
{
	struct ipcpudata *cpudata;
	struct ipipe_domain *old;
	ipipe_declare_cpuid;

	ipipe_load_cpuid();

	if (head->irqs[irq].acknowledge != NULL)
		head->irqs[irq].acknowledge(irq);

	cpudata = &head->cpudata[cpuid];
	cpudata->irq_counters[irq].total_hits++;

	if (test_bit(IPIPE_LOCK_FLAG, &head->irqs[irq].control)) {
		/* If we can't process this IRQ right now, we must
		 * mark it as pending, so that it will get played
		 * during normal log sync when the corresponding
		 * interrupt source is eventually unlocked. */
		cpudata->irq_counters[irq].pending_hits++;
		return 0;
	}

	if (test_bit(IPIPE_STALL_FLAG, &cpudata->status)) {
		cpudata->irq_counters[irq].pending_hits++;
		__ipipe_set_irq_bit(head, cpuid, irq);
		return 0;
	}

	old = ipipe_percpu_domain[cpuid];
	ipipe_percpu_domain[cpuid] = head; /* Switch to the head domain. */

	__set_bit(IPIPE_STALL_FLAG, &cpudata->status);
	head->irqs[irq].handler(irq,head->irqs[irq].cookie); /* Call the ISR. */
	__ipipe_run_irqtail();
	__clear_bit(IPIPE_STALL_FLAG, &cpudata->status);

	/* We expect the caller to start a complete pipeline walk upon
	 * return, so that propagated interrupts will get played. */

	if (ipipe_percpu_domain[cpuid] == head)
		ipipe_percpu_domain[cpuid] = old; /* Back to the preempted domain. */

	return 1;
}

/*
 * __ipipe_sync_stage() -- Flush the pending IRQs for the current
 * domain (and processor). This routine flushes the interrupt log
 * (see "Optimistic interrupt protection" from D. Stodolsky et al. for
 * more on the deferred interrupt scheme). Every interrupt that
 * occurred while the pipeline was stalled gets played. WARNING:
 * callers on SMP boxen should always check for CPU migration on
 * return of this routine. One can control the kind of interrupts
 * which are going to be sync'ed using the syncmask
 * parameter. IPIPE_IRQMASK_ANY plays them all, IPIPE_IRQMASK_VIRT
 * plays virtual interrupts only.
 *
 * This routine must be called with hw interrupts off.
 */
void fastcall __ipipe_sync_stage(unsigned long syncmask)
{
	unsigned long mask, submask;
	struct ipcpudata *cpudata;
	struct ipipe_domain *ipd;
	ipipe_declare_cpuid;
	int level, rank;
	unsigned irq;

	ipipe_load_cpuid();
	ipd = ipipe_percpu_domain[cpuid];
	cpudata = &ipd->cpudata[cpuid];

	if (__test_and_set_bit(IPIPE_SYNC_FLAG, &cpudata->status))
		return;

	/*
	 * The policy here is to keep the dispatching code interrupt-free
	 * by stalling the current stage. If the upper domain handler
	 * (which we call) wants to re-enable interrupts while in a safe
	 * portion of the code (e.g. SA_INTERRUPT flag unset for Linux's
	 * sigaction()), it will have to unstall (then stall again before
	 * returning to us!) the stage when it sees fit.
	 */
	while ((mask = (cpudata->irq_pending_hi & syncmask)) != 0) {
		level = __ipipe_ffnz(mask);

		while ((submask = cpudata->irq_pending_lo[level]) != 0) {
			rank = __ipipe_ffnz(submask);
			irq = (level << IPIPE_IRQ_ISHIFT) + rank;

			if (test_bit(IPIPE_LOCK_FLAG, &ipd->irqs[irq].control)) {
				__clear_bit(rank, &cpudata->irq_pending_lo[level]);
				continue;
			}

			if (--cpudata->irq_counters[irq].pending_hits == 0) {
				__clear_bit(rank, &cpudata->irq_pending_lo[level]);
				if (cpudata->irq_pending_lo[level] == 0)
					__clear_bit(level, &cpudata->irq_pending_hi);
			}

			__set_bit(IPIPE_STALL_FLAG, &cpudata->status);
			__ipipe_run_isr(ipd, irq, cpuid);
#ifdef CONFIG_SMP
			{
				int _cpuid = ipipe_processor_id();

				if (_cpuid != cpuid) {	/* Handle CPU migration. */
					/*
					 * We expect any domain to clear the SYNC bit each
					 * time it switches in a new task, so that preemptions
					 * and/or CPU migrations (in the SMP case) over the
					 * ISR do not lock out the log syncer for some
					 * indefinite amount of time. In the Linux case,
					 * schedule() handles this (see kernel/sched.c). For
					 * this reason, we don't bother clearing it here for
					 * the source CPU in the migration handling case,
					 * since it must have scheduled another task in by
					 * now.
					 */
					cpuid = _cpuid;
					cpudata = &ipd->cpudata[cpuid];
					__set_bit(IPIPE_SYNC_FLAG, &cpudata->status);
				}
			}
#endif	/* CONFIG_SMP */

			__clear_bit(IPIPE_STALL_FLAG, &cpudata->status);
		}
	}

	__clear_bit(IPIPE_SYNC_FLAG, &cpudata->status);
}

#ifdef CONFIG_PROC_FS

#include <linux/proc_fs.h>

static struct proc_dir_entry *ipipe_proc_root;

static int __ipipe_version_info_proc(char *page,
				     char **start,
				     off_t off, int count, int *eof, void *data)
{
	int len = sprintf(page, "%s\n", IPIPE_VERSION_STRING);

	len -= off;

	if (len <= off + count)
		*eof = 1;

	*start = page + off;

	if(len > count)
		len = count;

	if(len < 0)
		len = 0;

	return len;
}

static int __ipipe_common_info_proc(char *page,
				    char **start,
				    off_t off, int count, int *eof, void *data)
{
	struct ipipe_domain *ipd = (struct ipipe_domain *)data;
	unsigned long ctlbits;
	unsigned irq, _irq;
	char *p = page;
	int len;

	spin_lock(&__ipipe_pipelock);

	if (test_bit(IPIPE_AHEAD_FLAG,&ipd->flags))
		p += sprintf(p, "Invariant head");
	else
		p += sprintf(p, "Priority=%d", ipd->priority);

	p += sprintf(p, ", Id=0x%.8x\n", ipd->domid);

	irq = 0;

	while (irq < IPIPE_NR_IRQS) {
		ctlbits =
			(ipd->irqs[irq].
			 control & (IPIPE_HANDLE_MASK | IPIPE_PASS_MASK |
				    IPIPE_STICKY_MASK | IPIPE_WIRED_MASK));
		if (irq >= IPIPE_NR_XIRQS && !ipipe_virtual_irq_p(irq)) {
			/*
			 * There might be a hole between the last external
			 * IRQ and the first virtual one; skip it.
			 */
			irq++;
			continue;
		}

		if (ipipe_virtual_irq_p(irq)
		    && !test_bit(irq - IPIPE_VIRQ_BASE,
				 &__ipipe_virtual_irq_map)) {
			/* Non-allocated virtual IRQ; skip it. */
			irq++;
			continue;
		}

		/*
		 * Attempt to group consecutive IRQ numbers having the
		 * same virtualization settings in a single line.
		 */

		_irq = irq;

		while (++_irq < IPIPE_NR_IRQS) {
			if (ipipe_virtual_irq_p(_irq) !=
			    ipipe_virtual_irq_p(irq)
			    || (ipipe_virtual_irq_p(_irq)
				&& !test_bit(_irq - IPIPE_VIRQ_BASE,
					     &__ipipe_virtual_irq_map))
			    || ctlbits != (ipd->irqs[_irq].
			     control & (IPIPE_HANDLE_MASK |
					IPIPE_PASS_MASK |
					IPIPE_STICKY_MASK)))
				break;
		}

		if (_irq == irq + 1)
			p += sprintf(p, "irq%u: ", irq);
		else
			p += sprintf(p, "irq%u-%u: ", irq, _irq - 1);

		/*
		 * Statuses are as follows:
		 * o "accepted" means handled _and_ passed down the pipeline.
		 * o "grabbed" means handled, but the interrupt might be
		 * terminated _or_ passed down the pipeline depending on
		 * what the domain handler asks for to the I-pipe.
		 * o "wired" is basically the same as "grabbed", except that
		 * the interrupt is unconditionally delivered to an invariant
		 * pipeline head domain.
		 * o "passed" means unhandled by the domain but passed
		 * down the pipeline.
		 * o "discarded" means unhandled and _not_ passed down the
		 * pipeline. The interrupt merely disappears from the
		 * current domain down to the end of the pipeline.
		 */
		if (ctlbits & IPIPE_HANDLE_MASK) {
			if (ctlbits & IPIPE_PASS_MASK)
				p += sprintf(p, "accepted");
			else if (ctlbits & IPIPE_WIRED_MASK)
				p += sprintf(p, "wired");
			else
				p += sprintf(p, "grabbed");
		} else if (ctlbits & IPIPE_PASS_MASK)
			p += sprintf(p, "passed");
		else
			p += sprintf(p, "discarded");

		if (ctlbits & IPIPE_STICKY_MASK)
			p += sprintf(p, ", sticky");

		if (ipipe_virtual_irq_p(irq))
			p += sprintf(p, ", virtual");

		p += sprintf(p, "\n");

		irq = _irq;
	}

	spin_unlock(&__ipipe_pipelock);

	len = p - page;

	if (len <= off + count)
		*eof = 1;

	*start = page + off;

	len -= off;

	if (len > count)
		len = count;

	if (len < 0)
		len = 0;

	return len;
}

void __ipipe_add_domain_proc(struct ipipe_domain *ipd)
{
	create_proc_read_entry(ipd->name,0444,ipipe_proc_root,&__ipipe_common_info_proc,ipd);
}

void __ipipe_remove_domain_proc(struct ipipe_domain *ipd)
{
	remove_proc_entry(ipd->name,ipipe_proc_root);
}

void ipipe_init_proc(void)
{
	ipipe_proc_root = create_proc_entry("ipipe",S_IFDIR, 0);
	create_proc_read_entry("version",0444,ipipe_proc_root,&__ipipe_version_info_proc,NULL);
	__ipipe_add_domain_proc(ipipe_root_domain);
}

#endif	/* CONFIG_PROC_FS */

EXPORT_SYMBOL(ipipe_virtualize_irq);
EXPORT_SYMBOL(ipipe_control_irq);
EXPORT_SYMBOL(ipipe_suspend_domain);
EXPORT_SYMBOL(ipipe_alloc_virq);
EXPORT_SYMBOL(ipipe_stall_pipeline_from);
EXPORT_SYMBOL(ipipe_test_and_stall_pipeline_from);
EXPORT_SYMBOL(ipipe_unstall_pipeline_from);
EXPORT_SYMBOL(ipipe_restore_pipeline_from);
EXPORT_SYMBOL(ipipe_test_and_unstall_pipeline_from);
EXPORT_SYMBOL(ipipe_unstall_pipeline_head);
EXPORT_SYMBOL(__ipipe_restore_pipeline_head);
EXPORT_SYMBOL(ipipe_percpu_domain);
EXPORT_SYMBOL(ipipe_root);
EXPORT_SYMBOL(ipipe_setscheduler_root);
EXPORT_SYMBOL(ipipe_reenter_root);
EXPORT_SYMBOL(__ipipe_unstall_root);
EXPORT_SYMBOL(__ipipe_stall_root);
EXPORT_SYMBOL(__ipipe_restore_root);
EXPORT_SYMBOL(__ipipe_test_and_stall_root);
EXPORT_SYMBOL(__ipipe_test_root);
EXPORT_SYMBOL(__ipipe_dispatch_event);
EXPORT_SYMBOL(__ipipe_dispatch_wired);
EXPORT_SYMBOL(__ipipe_sync_stage);
EXPORT_SYMBOL(__ipipe_pipeline);
EXPORT_SYMBOL(__ipipe_pipelock);
EXPORT_SYMBOL(__ipipe_virtual_irq_map);
