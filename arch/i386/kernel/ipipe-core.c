/*   -*- linux-c -*-
 *   linux/arch/i386/kernel/ipipe-core.c
 *
 *   Copyright (C) 2002-2005 Philippe Gerum.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *   Architecture-dependent I-PIPE core support for x86.
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <asm/system.h>
#include <asm/atomic.h>
#include <asm/hw_irq.h>
#include <asm/irq.h>
#include <asm/desc.h>
#include <asm/io.h>
#ifdef CONFIG_X86_LOCAL_APIC
#include <asm/fixmap.h>
#include <asm/bitops.h>
#include <asm/mpspec.h>
#ifdef CONFIG_X86_IO_APIC
#include <asm/io_apic.h>
#endif	/* CONFIG_X86_IO_APIC */
#include <asm/apic.h>
#endif	/* CONFIG_X86_LOCAL_APIC */

struct pt_regs __ipipe_tick_regs[IPIPE_NR_CPUS];

int __ipipe_tick_irq;

#ifdef CONFIG_SMP

static cpumask_t __ipipe_cpu_sync_map;

static cpumask_t __ipipe_cpu_lock_map;

static ipipe_spinlock_t __ipipe_cpu_barrier = IPIPE_SPIN_LOCK_UNLOCKED;

static atomic_t __ipipe_critical_count = ATOMIC_INIT(0);

static void (*__ipipe_cpu_sync) (void);

void __ipipe_send_IPI_allbutself(int vector);

#endif	/* CONFIG_SMP */

int __ipipe_ack_system_irq(unsigned irq)
{
#ifdef CONFIG_X86_LOCAL_APIC
	__ack_APIC_irq();
#endif	/* CONFIG_X86_LOCAL_APIC */
	return 1;
}

#ifdef CONFIG_SMP

/* Always called with hw interrupts off. */

void __ipipe_do_critical_sync(unsigned irq, void *cookie)
{
	ipipe_declare_cpuid;

	ipipe_load_cpuid();

	cpu_set(cpuid, __ipipe_cpu_sync_map);

	/* Now we are in sync with the lock requestor running on another
	   CPU. Enter a spinning wait until he releases the global
	   lock. */
	spin_lock_hw(&__ipipe_cpu_barrier);

	/* Got it. Now get out. */

	if (__ipipe_cpu_sync)
		/* Call the sync routine if any. */
		__ipipe_cpu_sync();

	spin_unlock_hw(&__ipipe_cpu_barrier);

	cpu_clear(cpuid, __ipipe_cpu_sync_map);
}

#endif	/* CONFIG_SMP */

/* ipipe_critical_enter() -- Grab the superlock excluding all CPUs
   but the current one from a critical section. This lock is used when
   we must enforce a global critical section for a single CPU in a
   possibly SMP system whichever context the CPUs are running. */

unsigned long ipipe_critical_enter(void (*syncfn) (void))
{
	unsigned long flags;

	local_irq_save_hw(flags);

#ifdef CONFIG_SMP
	if (num_online_cpus() > 1) {	/* We might be running a SMP-kernel on a UP box... */
		ipipe_declare_cpuid;
		cpumask_t lock_map;

		ipipe_load_cpuid();

		if (!cpu_test_and_set(cpuid, __ipipe_cpu_lock_map)) {
			while (cpu_test_and_set
			       (BITS_PER_LONG - 1, __ipipe_cpu_lock_map)) {
				int n = 0;
				do {
					cpu_relax();
				} while (++n < cpuid);
			}

			spin_lock_hw(&__ipipe_cpu_barrier);

			__ipipe_cpu_sync = syncfn;

			/* Send the sync IPI to all processors but the current one. */
			__ipipe_send_IPI_allbutself(IPIPE_CRITICAL_VECTOR);

			cpus_andnot(lock_map, cpu_online_map,
				    __ipipe_cpu_lock_map);

			while (!cpus_equal(__ipipe_cpu_sync_map, lock_map))
				cpu_relax();
		}

		atomic_inc(&__ipipe_critical_count);
	}
#endif	/* CONFIG_SMP */

	return flags;
}

/* ipipe_critical_exit() -- Release the superlock. */

void ipipe_critical_exit(unsigned long flags)
{
#ifdef CONFIG_SMP
	if (num_online_cpus() > 1) {	/* We might be running a SMP-kernel on a UP box... */
		ipipe_declare_cpuid;

		ipipe_load_cpuid();

		if (atomic_dec_and_test(&__ipipe_critical_count)) {
			spin_unlock_hw(&__ipipe_cpu_barrier);

			while (!cpus_empty(__ipipe_cpu_sync_map))
				cpu_relax();

			cpu_clear(cpuid, __ipipe_cpu_lock_map);
			cpu_clear(BITS_PER_LONG - 1, __ipipe_cpu_lock_map);
		}
	}
#endif	/* CONFIG_SMP */

	local_irq_restore_hw(flags);
}

/* ipipe_trigger_irq() -- Push the interrupt at front of the pipeline
   just like if it has been actually received from a hw source. Also
   works for virtual interrupts. */

int fastcall ipipe_trigger_irq(unsigned irq)
{
	struct pt_regs regs;
	unsigned long flags;

	if (irq >= IPIPE_NR_IRQS ||
	    (ipipe_virtual_irq_p(irq) &&
	     !test_bit(irq - IPIPE_VIRQ_BASE, &__ipipe_virtual_irq_map)))
		return -EINVAL;

	local_irq_save_hw(flags);

	regs.orig_eax = irq;	/* Won't be acked */
	regs.xcs = __KERNEL_CS;
	regs.eflags = flags;

	__ipipe_handle_irq(regs);

	local_irq_restore_hw(flags);

	return 1;
}

int ipipe_get_sysinfo(struct ipipe_sysinfo *info)
{
	info->ncpus = num_online_cpus();
	info->cpufreq = ipipe_cpu_freq();
	info->archdep.tmirq = __ipipe_tick_irq;
#ifdef CONFIG_X86_TSC
	info->archdep.tmfreq = ipipe_cpu_freq();
#else	/* !CONFIG_X86_TSC */
	info->archdep.tmfreq = CLOCK_TICK_RATE;
#endif	/* CONFIG_X86_TSC */

	return 0;
}

int ipipe_tune_timer (unsigned long ns, int flags)

{
	unsigned hz, latch;
	unsigned long x;

	if (flags & IPIPE_RESET_TIMER)
		latch = LATCH;
	else {
		hz = 1000000000 / ns;

		if (hz < HZ)
			return -EINVAL;

		latch = (CLOCK_TICK_RATE + hz/2) / hz;
	}

	x = ipipe_critical_enter(NULL); /* Sync with all CPUs */

	/* Shamelessly lifted from init_IRQ() in i8259.c */
	outb_p(0x34,0x43);		/* binary, mode 2, LSB/MSB, ch 0 */
	outb_p(latch & 0xff,0x40);	/* LSB */
	outb(latch >> 8,0x40);	/* MSB */

	ipipe_critical_exit(x);

	return 0;
}

EXPORT_SYMBOL(__ipipe_tick_irq);
EXPORT_SYMBOL(ipipe_critical_enter);
EXPORT_SYMBOL(ipipe_critical_exit);
EXPORT_SYMBOL(ipipe_trigger_irq);
EXPORT_SYMBOL(ipipe_get_sysinfo);
EXPORT_SYMBOL(ipipe_tune_timer);
