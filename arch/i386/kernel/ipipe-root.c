/*   -*- linux-c -*-
 *   linux/arch/i386/kernel/ipipe-root.c
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
 *   Architecture-dependent I-PIPE support for x86.
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/vt_kern.h>
#include <linux/sys.h>
#include <asm/unistd.h>
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

static int __ipipe_noack_irq(unsigned irq)
{
	return 1;
}
#endif	/* CONFIG_X86_LOCAL_APIC */

asmlinkage unsigned int do_IRQ(struct pt_regs *regs);
void smp_apic_timer_interrupt(struct pt_regs *regs);
asmlinkage void smp_spurious_interrupt(struct pt_regs *regs);
asmlinkage void smp_error_interrupt(struct pt_regs *regs);
asmlinkage void smp_reschedule_interrupt(struct pt_regs *regs);
asmlinkage void smp_invalidate_interrupt(struct pt_regs *regs);
asmlinkage void smp_call_function_interrupt(struct pt_regs *regs);

static int __ipipe_ack_common_irq(unsigned irq)
{
	irq_desc_t *desc = irq_desc + irq;
	unsigned long flags;
	ipipe_declare_cpuid;

	ipipe_load_cpuid();	/* hw interrupts are off. */
	flags = ipipe_test_and_stall_pipeline();
	desc->handler->ack(irq);
	ipipe_restore_pipeline_nosync(ipipe_percpu_domain[cpuid], flags, cpuid);

	return 1;
}

#ifdef CONFIG_X86_LOCAL_APIC

static void __ipipe_null_handler(unsigned irq, void *cookie)
{
	/* Nop. */
}

#ifdef CONFIG_SMP

static int __ipipe_boot_cpuid(void)
{
	return 0;
}

u8 __ipipe_apicid_2_cpu[IPIPE_NR_CPUS];

static int __ipipe_hard_cpuid(void)
{
	unsigned long flags;
	int cpu;

	local_irq_save_hw(flags);
	cpu = __ipipe_apicid_2_cpu[GET_APIC_ID(apic_read(APIC_ID))];
	local_irq_restore_hw(flags);
	return cpu;
}

int (*__ipipe_logical_cpuid)(void) = &__ipipe_boot_cpuid;

EXPORT_SYMBOL(__ipipe_logical_cpuid);

#endif /* CONFIG_SMP */

#endif	/* CONFIG_X86_LOCAL_APIC */

/* __ipipe_enable_pipeline() -- We are running on the boot CPU, hw
   interrupts are off, and secondary CPUs are still lost in space. */

void __init __ipipe_enable_pipeline(void)
{
	unsigned irq;

#ifdef CONFIG_X86_LOCAL_APIC

	/* Map the APIC system vectors. */

	ipipe_virtualize_irq(ipipe_root_domain,
			     LOCAL_TIMER_VECTOR - FIRST_EXTERNAL_VECTOR,
			     (ipipe_irq_handler_t)&smp_apic_timer_interrupt,
			     NULL,
			     &__ipipe_ack_system_irq,
			     IPIPE_STDROOT_MASK);

	ipipe_virtualize_irq(ipipe_root_domain,
			     SPURIOUS_APIC_VECTOR - FIRST_EXTERNAL_VECTOR,
			     (ipipe_irq_handler_t)&smp_spurious_interrupt,
			     NULL,
			     &__ipipe_noack_irq,
			     IPIPE_STDROOT_MASK);

	ipipe_virtualize_irq(ipipe_root_domain,
			     ERROR_APIC_VECTOR - FIRST_EXTERNAL_VECTOR,
			     (ipipe_irq_handler_t)&smp_error_interrupt,
			     NULL,
			     &__ipipe_ack_system_irq,
			     IPIPE_STDROOT_MASK);

	ipipe_virtualize_irq(ipipe_root_domain,
			     IPIPE_SERVICE_VECTOR0 - FIRST_EXTERNAL_VECTOR,
			     &__ipipe_null_handler,
			     NULL,
			     &__ipipe_ack_system_irq,
			     IPIPE_STDROOT_MASK);

	ipipe_virtualize_irq(ipipe_root_domain,
			     IPIPE_SERVICE_VECTOR1 - FIRST_EXTERNAL_VECTOR,
			     &__ipipe_null_handler,
			     NULL,
			     &__ipipe_ack_system_irq,
			     IPIPE_STDROOT_MASK);

	ipipe_virtualize_irq(ipipe_root_domain,
			     IPIPE_SERVICE_VECTOR2 - FIRST_EXTERNAL_VECTOR,
			     &__ipipe_null_handler,
			     NULL,
			     &__ipipe_ack_system_irq,
			     IPIPE_STDROOT_MASK);

	ipipe_virtualize_irq(ipipe_root_domain,
			     IPIPE_SERVICE_VECTOR3 - FIRST_EXTERNAL_VECTOR,
			     &__ipipe_null_handler,
			     NULL,
			     &__ipipe_ack_system_irq,
			     IPIPE_STDROOT_MASK);

	__ipipe_tick_irq =
	    using_apic_timer ? LOCAL_TIMER_VECTOR - FIRST_EXTERNAL_VECTOR : 0;

#else	/* !CONFIG_X86_LOCAL_APIC */

	__ipipe_tick_irq = 0;

#endif	/* CONFIG_X86_LOCAL_APIC */

#ifdef CONFIG_SMP

	ipipe_virtualize_irq(ipipe_root_domain,
			     RESCHEDULE_VECTOR - FIRST_EXTERNAL_VECTOR,
			     (ipipe_irq_handler_t)&smp_reschedule_interrupt,
			     NULL,
			     &__ipipe_ack_system_irq,
			     IPIPE_STDROOT_MASK);

	ipipe_virtualize_irq(ipipe_root_domain,
			     INVALIDATE_TLB_VECTOR - FIRST_EXTERNAL_VECTOR,
			     (ipipe_irq_handler_t)&smp_invalidate_interrupt,
			     NULL,
			     &__ipipe_ack_system_irq,
			     IPIPE_STDROOT_MASK);

	ipipe_virtualize_irq(ipipe_root_domain,
			     CALL_FUNCTION_VECTOR - FIRST_EXTERNAL_VECTOR,
			     (ipipe_irq_handler_t)&smp_call_function_interrupt,
			     NULL,
			     &__ipipe_ack_system_irq,
			     IPIPE_STDROOT_MASK);

	/* Some guest O/S may run tasks over non-Linux stacks, so we
	 * cannot rely on the regular definition of smp_processor_id()
	 * on x86 to fetch the logical cpu id. We fix this by using
	 * our own private physical apicid -> logicial cpuid mapping
	 * as soon as the pipeline is enabled, so that
	 * ipipe_processor_id() always do the right thing, regardless
	 * of the current stack setup. Also note that the pipeline is
	 * enabled after the APIC space has been mapped in
	 * trap_init(), so it's safe to use it. */

	__ipipe_logical_cpuid = &__ipipe_hard_cpuid;

#endif	/* CONFIG_SMP */

	/* Finally, virtualize the remaining ISA and IO-APIC
	 * interrupts. Interrupts which have already been virtualized
	 * will just beget a silent -EPERM error since
	 * IPIPE_SYSTEM_MASK has been passed for them, that's ok. */

	for (irq = 0; irq < NR_IRQS; irq++) {
		/* Fails for IPIPE_CRITICAL_IPI but that's ok. */
		ipipe_virtualize_irq(ipipe_root_domain,
				     irq,
				     (ipipe_irq_handler_t)&do_IRQ,
				     NULL,
				     &__ipipe_ack_common_irq,
				     IPIPE_STDROOT_MASK);
	}

#ifdef CONFIG_X86_LOCAL_APIC
	/* Eventually allow these vectors to be reprogrammed. */
	ipipe_root_domain->irqs[IPIPE_SERVICE_IPI0].control &= ~IPIPE_SYSTEM_MASK;
	ipipe_root_domain->irqs[IPIPE_SERVICE_IPI1].control &= ~IPIPE_SYSTEM_MASK;
	ipipe_root_domain->irqs[IPIPE_SERVICE_IPI2].control &= ~IPIPE_SYSTEM_MASK;
	ipipe_root_domain->irqs[IPIPE_SERVICE_IPI3].control &= ~IPIPE_SYSTEM_MASK;
#endif	/* CONFIG_X86_LOCAL_APIC */
}

static inline void __fixup_if(struct pt_regs *regs)
{
	ipipe_declare_cpuid;
	unsigned long flags;

	ipipe_get_cpu(flags);

	if (ipipe_percpu_domain[cpuid] == ipipe_root_domain) {
		/* Have the saved hw state look like the domain stall bit, so
		   that __ipipe_unstall_iret_root() restores the proper
		   pipeline state for the root stage upon exit. */

		if (test_bit
		    (IPIPE_STALL_FLAG,
		     &ipipe_root_domain->cpudata[cpuid].status))
			regs->eflags &= ~X86_EFLAGS_IF;
		else
			regs->eflags |= X86_EFLAGS_IF;
	}

	ipipe_put_cpu(flags);
}

asmlinkage void __ipipe_unstall_iret_root(struct pt_regs regs)
{
	ipipe_declare_cpuid;

	/* Emulate IRET's handling of the interrupt flag. */

	local_irq_disable_hw();

	ipipe_load_cpuid();

	/* Restore the software state as it used to be on kernel
	   entry. CAUTION: NMIs must *not* return through this
	   emulation. */

	if (!(regs.eflags & X86_EFLAGS_IF)) {
		__set_bit(IPIPE_STALL_FLAG,
			  &ipipe_root_domain->cpudata[cpuid].status);
		regs.eflags |= X86_EFLAGS_IF;
	} else {
		__clear_bit(IPIPE_STALL_FLAG,
			    &ipipe_root_domain->cpudata[cpuid].status);

		/* Only sync virtual IRQs here, so that we don't recurse
		   indefinitely in case of an external interrupt flood. */

		if ((ipipe_root_domain->cpudata[cpuid].
		     irq_pending_hi & IPIPE_IRQMASK_VIRT) != 0)
			__ipipe_sync_pipeline(IPIPE_IRQMASK_VIRT);
	}
}

asmlinkage int __ipipe_syscall_root(struct pt_regs regs)
{
	ipipe_declare_cpuid;
	unsigned long flags;

	__fixup_if(&regs);

	/* This routine either returns:
	    0 -- if the syscall is to be passed to Linux;
	   >0 -- if the syscall should not be passed to Linux, and no
	   tail work should be performed;
	   <0 -- if the syscall should not be passed to Linux but the
	   tail work has to be performed (for handling signals etc). */

	if (__ipipe_syscall_watched_p(current, regs.orig_eax) &&
	    __ipipe_event_monitored_p(IPIPE_EVENT_SYSCALL) &&
	    __ipipe_dispatch_event(IPIPE_EVENT_SYSCALL,&regs) > 0) {
		/* We might enter here over a non-root domain and exit
		 * over the root one as a result of the syscall
		 * (i.e. by recycling the register set of the current
		 * context across the migration), so we need to fixup
		 * the interrupt flag upon return too, so that
		 * __ipipe_unstall_iret_root() resets the correct
		 * stall bit on exit. */
		__fixup_if(&regs);

		if (ipipe_current_domain == ipipe_root_domain) {
			/* Sync pending VIRQs before _TIF_NEED_RESCHED
			 * is tested. */
			ipipe_lock_cpu(flags);
			if ((ipipe_root_domain->cpudata[cpuid].irq_pending_hi & IPIPE_IRQMASK_VIRT) != 0)
				__ipipe_sync_stage(IPIPE_IRQMASK_VIRT);
			ipipe_unlock_cpu(flags);
			return -1;
		}
		return 1;
	}

    return 0;
}

asmlinkage void do_divide_error(struct pt_regs *regs, long error_code);
asmlinkage void do_debug(struct pt_regs *regs, long error_code);
asmlinkage void do_int3(struct pt_regs *regs, long error_code);
asmlinkage void do_overflow(struct pt_regs *regs, long error_code);
asmlinkage void do_bounds(struct pt_regs *regs, long error_code);
asmlinkage void do_invalid_op(struct pt_regs *regs, long error_code);
asmlinkage void do_coprocessor_segment_overrun(struct pt_regs *regs, long error_code);
asmlinkage void do_double_fault(struct pt_regs *regs, long error_code);
asmlinkage void do_invalid_TSS(struct pt_regs *regs, long error_code);
asmlinkage void do_segment_not_present(struct pt_regs *regs, long error_code);
asmlinkage void do_stack_segment(struct pt_regs *regs, long error_code);
asmlinkage void do_general_protection(struct pt_regs *regs, long error_code);
asmlinkage void do_page_fault(struct pt_regs *regs, long error_code);
asmlinkage void do_spurious_interrupt_bug(struct pt_regs *regs, long error_code);
asmlinkage void do_coprocessor_error(struct pt_regs *regs, long error_code);
asmlinkage void do_alignment_check(struct pt_regs *regs, long error_code);
asmlinkage void do_machine_check(struct pt_regs *regs, long error_code);
asmlinkage void do_simd_coprocessor_error(struct pt_regs *regs, long error_code);

/* Work around genksyms's issue with over-qualification in decls. */

typedef asmlinkage void __ipipe_exhandler(struct pt_regs *, long);

typedef __ipipe_exhandler *__ipipe_exptr;

static __ipipe_exptr __ipipe_std_extable[] = {

	[ex_do_divide_error] = &do_divide_error,
	[ex_do_debug] = &do_debug,
	[ex_do_int3] = &do_int3,
	[ex_do_overflow] = &do_overflow,
	[ex_do_bounds] = &do_bounds,
	[ex_do_invalid_op] = &do_invalid_op,
	[ex_do_coprocessor_segment_overrun] = &do_coprocessor_segment_overrun,
	[ex_do_double_fault] = &do_double_fault,
	[ex_do_invalid_TSS] = &do_invalid_TSS,
	[ex_do_segment_not_present] = &do_segment_not_present,
	[ex_do_stack_segment] = &do_stack_segment,
	[ex_do_general_protection] = do_general_protection,
	[ex_do_page_fault] = &do_page_fault,
	[ex_do_spurious_interrupt_bug] = &do_spurious_interrupt_bug,
	[ex_do_coprocessor_error] = &do_coprocessor_error,
	[ex_do_alignment_check] = &do_alignment_check,
	[ex_do_machine_check] = &do_machine_check,
	[ex_do_simd_coprocessor_error] = &do_simd_coprocessor_error
};

asmlinkage int __ipipe_handle_exception(int vector, struct pt_regs *regs, long error_code)
{
	if (!__ipipe_event_monitored_p(vector) ||
	    __ipipe_dispatch_event(vector,regs) == 0) {
		__ipipe_exptr handler = __ipipe_std_extable[vector];
		handler(regs,error_code);
		__fixup_if(regs);
		return 0;
	}

	return 1;
}

int FASTCALL(__ipipe_divert_exception(struct pt_regs *regs, int vector));

int fastcall __ipipe_divert_exception(struct pt_regs *regs, int vector)
{
	if (__ipipe_event_monitored_p(vector) &&
	    __ipipe_dispatch_event(vector,regs) != 0)
		return 1;

	__fixup_if(regs);

	return 0;
}

/* __ipipe_handle_irq() -- IPIPE's generic IRQ handler. An optimistic
   interrupt protection log is maintained here for each domain.  Hw
   interrupts are off on entry. */

int __ipipe_handle_irq(struct pt_regs regs)
{
	struct ipipe_domain *this_domain, *next_domain;
	unsigned irq = regs.orig_eax;
	struct list_head *head, *pos;
	ipipe_declare_cpuid;
	int m_ack, s_ack;

	ipipe_load_cpuid();

	if (regs.orig_eax < 0) {
		irq &= 0xff;
		m_ack = 0;
	} else
		m_ack = 1;

	this_domain = ipipe_percpu_domain[cpuid];

	if (test_bit(IPIPE_STICKY_FLAG, &this_domain->irqs[irq].control))
		head = &this_domain->p_link;
	else {
		head = __ipipe_pipeline.next;
		next_domain = list_entry(head, struct ipipe_domain, p_link);
		if (likely(test_bit(IPIPE_WIRED_FLAG, &next_domain->irqs[irq].control))) {
			if (!m_ack && next_domain->irqs[irq].acknowledge != NULL)
				next_domain->irqs[irq].acknowledge(irq);
			if (likely(__ipipe_dispatch_wired(next_domain, irq)))
				goto finalize;
			else
				goto finalize_nosync;
		}
	}

	/* Ack the interrupt. */

	s_ack = m_ack;
	pos = head;

	while (pos != &__ipipe_pipeline) {
		next_domain = list_entry(pos, struct ipipe_domain, p_link);

		/* For each domain handling the incoming IRQ, mark it as
		   pending in its log. */

		if (test_bit
		    (IPIPE_HANDLE_FLAG, &next_domain->irqs[irq].control)) {
			/* Domains that handle this IRQ are polled for
			   acknowledging it by decreasing priority order. The
			   interrupt must be made pending _first_ in the domain's
			   status flags before the PIC is unlocked. */

			next_domain->cpudata[cpuid].irq_counters[irq].total_hits++;
			next_domain->cpudata[cpuid].irq_counters[irq].pending_hits++;
			__ipipe_set_irq_bit(next_domain, cpuid, irq);

			/* Always get the first master acknowledge available. Once
			   we've got it, allow slave acknowledge handlers to run
			   (until one of them stops us). */

			if (!m_ack)
				m_ack = next_domain->irqs[irq].acknowledge(irq);
			else if (test_bit
				 (IPIPE_SHARED_FLAG,
				  &next_domain->irqs[irq].control) && !s_ack)
				s_ack = next_domain->irqs[irq].acknowledge(irq);
		}

		/* If the domain does not want the IRQ to be passed down the
		   interrupt pipe, exit the loop now. */

		if (!test_bit(IPIPE_PASS_FLAG, &next_domain->irqs[irq].control))
			break;

		pos = next_domain->p_link.next;
	}

	if (irq == __ipipe_tick_irq &&
	    __ipipe_pipeline_head_p(ipipe_root_domain) &&
	    ipipe_root_domain->cpudata[cpuid].irq_counters[irq].pending_hits > 1)
		/*
		 * Emulate a loss of clock ticks if Linux is owning
		 * the time source. The drift will be compensated by
		 * the timer support code.
		 */
		ipipe_root_domain->cpudata[cpuid].irq_counters[irq].pending_hits = 1;

finalize:

	if (irq == __ipipe_tick_irq) {
		__ipipe_tick_regs[cpuid].eflags = regs.eflags;
		__ipipe_tick_regs[cpuid].eip = regs.eip;
		__ipipe_tick_regs[cpuid].xcs = regs.xcs;
#if defined(CONFIG_SMP) && defined(CONFIG_FRAME_POINTER)
		/* Linux profiling code needs this. */
		__ipipe_tick_regs[cpuid].ebp = regs.ebp;
#endif	/* CONFIG_SMP && CONFIG_FRAME_POINTER */
	}

	/* Now walk the pipeline, yielding control to the highest
	   priority domain that has pending interrupt(s) or
	   immediately to the current domain if the interrupt has been
	   marked as 'sticky'. This search does not go beyond the
	   current domain in the pipeline. */

	__ipipe_walk_pipeline(head, cpuid);

finalize_nosync:

	ipipe_load_cpuid();

	if (ipipe_percpu_domain[cpuid] != ipipe_root_domain ||
	    test_bit(IPIPE_STALL_FLAG,
		     &ipipe_root_domain->cpudata[cpuid].status))
		return 0;

#ifdef CONFIG_SMP
	/* Prevent a spurious rescheduling from being triggered on
	   preemptible kernels along the way out through
	   ret_from_intr. */
	if (regs.orig_eax < 0)
		__set_bit(IPIPE_STALL_FLAG, &ipipe_root_domain->cpudata[cpuid].status);
#endif	/* CONFIG_SMP */

	return 1;
}

extern unsigned long cpu_khz;
EXPORT_SYMBOL_GPL(cpu_khz);
#ifdef CONFIG_SMP
extern struct tlb_state cpu_tlbstate[];
EXPORT_SYMBOL_NOVERS(cpu_tlbstate);
extern spinlock_t nmi_print_lock;
EXPORT_SYMBOL_GPL(nmi_print_lock);
#endif /* CONFIG_SMP */
extern irq_desc_t irq_desc[];
EXPORT_SYMBOL_NOVERS(irq_desc);
EXPORT_SYMBOL_NOVERS(default_ldt);
EXPORT_SYMBOL_NOVERS(__switch_to);
extern void show_stack(unsigned long *);
EXPORT_SYMBOL_NOVERS(show_stack);
EXPORT_SYMBOL_GPL(init_tss);
EXPORT_SYMBOL_GPL(set_ldt_desc);
EXPORT_SYMBOL_GPL(do_exit);
void (*nmi_watchdog_tick) (struct pt_regs * regs);
EXPORT_SYMBOL_GPL(nmi_watchdog_tick);

