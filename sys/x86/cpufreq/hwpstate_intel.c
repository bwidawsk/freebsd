/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2018 Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/sbuf.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/cpu.h>
#include <sys/smp.h>
#include <sys/proc.h>
#include <sys/sched.h>

#include <machine/cpu.h>
#include <machine/md_var.h>
#include <machine/cputypes.h>
#include <machine/specialreg.h>

#include <contrib/dev/acpica/include/acpi.h>

#include <dev/acpica/acpivar.h>

#include "acpi_if.h"
#include "cpufreq_if.h"

extern uint64_t	tsc_freq;

bool intel_speed_shift=true;
SYSCTL_BOOL(_machdep, OID_AUTO, intel_speed_shift, CTLFLAG_RDTUN, &intel_speed_shift,
    0, "Enable Intel Speed Shift (HWP)");

static void	intel_hwpstate_identify(driver_t *driver, device_t parent);
static int	intel_hwpstate_probe(device_t dev);
static int	intel_hwpstate_attach(device_t dev);
static int	intel_hwpstate_detach(device_t dev);

static int      intel_hwpstate_get(device_t dev, struct cf_setting *cf);
static int      intel_hwpstate_type(device_t dev, int *type);

static device_method_t intel_hwpstate_methods[] = {
	/* Device interface */
	DEVMETHOD(device_identify,	intel_hwpstate_identify),
	DEVMETHOD(device_probe,		intel_hwpstate_probe),
	DEVMETHOD(device_attach,	intel_hwpstate_attach),
	DEVMETHOD(device_detach,	intel_hwpstate_detach),

	/* cpufreq interface */
	DEVMETHOD(cpufreq_drv_get,      intel_hwpstate_get),
	DEVMETHOD(cpufreq_drv_type,     intel_hwpstate_type),

	{0, 0}
};

struct hwp_softc {
	device_t		dev;
	bool 			hwp_notifications;
	bool			hwp_activity_window;
	bool			hwp_pref_ctrl;
	bool			hwp_pkg_ctrl;

	uint64_t		req; /* Cached copy of last request */

	uint8_t			high;
	uint8_t			guaranteed;
	uint8_t			efficient;
	uint8_t			low;
};

static devclass_t hwpstate_intel_devclass;
static driver_t hwpstate_intel_driver = {
	"hwpstate_intel",
	intel_hwpstate_methods,
	sizeof(struct hwp_softc),
};

/*
 * NB: This must run before the est and acpi_perf module!!!!
 *
 * If a user opts in to hwp, but the CPU doesn't support it, we need to find that
 * out before est loads or else we won't be able to use est as a backup.
 */
DRIVER_MODULE_ORDERED(hwpstate_intel, cpu, hwpstate_intel_driver,
    hwpstate_intel_devclass, 0, 0, SI_ORDER_FIRST);

static int
intel_hwp_dump_sysctl_handler(SYSCTL_HANDLER_ARGS)
{
	device_t dev;
	struct pcpu *pc;
	struct sbuf *sb;
	struct hwp_softc *sc;
	uint64_t data, data2;
	int ret;

	sc = (struct hwp_softc *)arg1;
	dev = sc->dev;

	pc = cpu_get_pcpu(dev);
	if (pc == NULL)
		return (ENXIO);

	sb = sbuf_new_for_sysctl(NULL, NULL, 1024, req);
	sbuf_putc(sb, '\n');
	thread_lock(curthread);
	sched_bind(curthread, pc->pc_cpuid);
	thread_unlock(curthread);

	rdmsr_safe(MSR_IA32_PM_ENABLE, &data);
	sbuf_printf(sb, "CPU%d: HWP %sabled\n", pc->pc_cpuid,
	    ((data & 1) ? "En" : "Dis"));

	if (data == 0) {
		ret = 0;
		goto out;
	}

	rdmsr_safe(MSR_IA32_HWP_CAPABILITIES, &data);
	sbuf_printf(sb, "\tHighest Performance: %03lu\n", data & 0xff);
	sbuf_printf(sb, "\tGuaranteed Performance: %03lu\n", (data >> 8) & 0xff);
	sbuf_printf(sb, "\tEfficient Performance: %03lu\n", (data >> 16) & 0xff);
	sbuf_printf(sb, "\tLowest Performance: %03lu\n", (data >> 24) & 0xff);

	rdmsr_safe(MSR_IA32_HWP_REQUEST, &data);
	if (sc->hwp_pkg_ctrl && (data & IA32_HWP_REQUEST_PACKAGE_CONTROL)) {
		rdmsr_safe(MSR_IA32_HWP_REQUEST_PKG, &data2);
	}

	sbuf_putc(sb, '\n');

#define pkg_print(x, name, offset) do {						\
	if (!sc->hwp_pkg_ctrl || (data & x) != 0) 				\
	sbuf_printf(sb, "\t%s: %03lu\n", name, (data >> offset) & 0xff);\
	else									\
	sbuf_printf(sb, "\t%s: %03lu\n", name, (data2 >> offset) & 0xff);\
} while (0)

	pkg_print(IA32_HWP_REQUEST_EPP_VALID,
	    "Requested Efficiency Performance Preference", 24);
	pkg_print(IA32_HWP_REQUEST_DESIRED_VALID,
	    "Requested Desired Performance", 16);
	pkg_print(IA32_HWP_REQUEST_MAXIMUM_VALID,
	    "Requested Maximum Performance", 8);
	pkg_print(IA32_HWP_REQUEST_MINIMUM_VALID,
	    "Requested Minimum Performance", 0);
#undef pkg_print

	sbuf_putc(sb, '\n');

out:
	thread_lock(curthread);
	sched_unbind(curthread);
	thread_unlock(curthread);

	ret = sbuf_finish(sb);
	sbuf_delete(sb);

	return (ret);
}

static inline int
__percent_to_raw(int x)
{

	MPASS(x <= 100 && x >= 0);
	return (0xff * x / 100);
}

static inline int
__raw_to_percent(int x)
{

	MPASS(x <= 0xff && x >= 0);
	return (x * 100 / 0xff);
}

static int
sysctl_epp_select(SYSCTL_HANDLER_ARGS)
{
	device_t dev;
	struct pcpu *pc;
	uint64_t requested;
	uint32_t val;
	int ret;

	dev = oidp->oid_arg1;
	pc = cpu_get_pcpu(dev);
	if (pc == NULL)
		return (ENXIO);

	thread_lock(curthread);
	sched_bind(curthread, pc->pc_cpuid);
	thread_unlock(curthread);

	rdmsr_safe(MSR_IA32_HWP_REQUEST, &requested);
	val = (requested & IA32_HWP_REQUEST_ENERGY_PERFORMANCE_PREFERENCE) >> 24;
	val = __raw_to_percent(val);

	MPASS(val >= 0 && val <= 100);

	ret = sysctl_handle_int(oidp, &val, 0, req);
	if (ret || req->newptr == NULL)
		goto out;

	if (val < 0)
		val = 0;
	if (val > 100)
		val = 100;

	val = __percent_to_raw(val);

	requested &= ~IA32_HWP_REQUEST_ENERGY_PERFORMANCE_PREFERENCE;
	requested |= val << 24;

	wrmsr_safe(MSR_IA32_HWP_REQUEST, requested);

out:
	thread_lock(curthread);
	sched_unbind(curthread);
	thread_unlock(curthread);

	return (ret);
}

static void
intel_hwpstate_identify(driver_t *driver, device_t parent)
{
	uint32_t regs[4];

	if (!intel_speed_shift)
		return;

	if (device_find_child(parent, "hwpstate_intel", -1) != NULL) {
		intel_speed_shift = false;
		return;
	}

	if (cpu_vendor_id != CPU_VENDOR_INTEL) {
		intel_speed_shift = false;
		return;
	}

	if (resource_disabled("hwpstate_intel", 0)) {
		intel_speed_shift = false;
		return;
	}

	/*
	 * Intel SDM 14.4.1 (HWP Programming Interfaces):
	 *   The CPUID instruction allows software to discover the presence of
	 *   HWP support in an Intel processor. Specifically, execute CPUID
	 *   instruction with EAX=06H as input will return 5 bit flags covering
	 *   the following aspects in bits 7 through 11 of CPUID.06H:EAX.
	 */

	if (cpu_high < 6)
		goto out;

	/*
	 * Intel SDM 14.4.1 (HWP Programming Interfaces):
	 *   Availability of HWP baseline resource and capability,
	 *   CPUID.06H:EAX[bit 7]: If this bit is set, HWP provides several new
	 *   architectural MSRs: IA32_PM_ENABLE, IA32_HWP_CAPABILITIES,
	 *   IA32_HWP_REQUEST, IA32_HWP_STATUS.
	 */

	do_cpuid(6, regs);
	if ((regs[0] & CPUTPM1_HWP) == 0)
		goto out;

	if (BUS_ADD_CHILD(parent, 10, "hwpstate_intel", -1) == NULL)
		goto out;

	device_printf(parent, "hwpstate registered (0x%x)\n", (regs[0] >> 7) & 0x1f);
	return;

out:
	device_printf(parent, "Speed Shift unavailable. Falling back to est\n");
	intel_speed_shift = false;
}

static int
intel_hwpstate_probe(device_t dev)
{
	device_t perf_dev;
	int ret, type;

	/*
	 * It is currently impossible for conflicting cpufreq driver to be loaded at
	 * this point since it's protected by the boolean intel_speed_shift.
	 * However, if at some point the knobs are made a bit more robust to
	 * control cpufreq, or, at some point INFO_ONLY drivers are permitted,
	 * this should make sure things work properly.
	 *
	 * IOW: This is a no-op for now.
	 */
	perf_dev = device_find_child(device_get_parent(dev), "acpi_perf", -1);
	if (perf_dev && device_is_attached(perf_dev)) {
		ret= CPUFREQ_DRV_TYPE(perf_dev, &type);
		if (ret== 0) {
			if ((type & CPUFREQ_FLAG_INFO_ONLY) != 0) {
				device_printf(dev, "Avoiding acpi_perf\n");
				return (ENXIO);
			}
		}
	}

	perf_dev = device_find_child(device_get_parent(dev), "est", -1);
	if (perf_dev && device_is_attached(perf_dev)) {
		ret= CPUFREQ_DRV_TYPE(perf_dev, &type);
		if (ret== 0) {
			if ((type & CPUFREQ_FLAG_INFO_ONLY) != 0) {
				device_printf(dev, "Avoiding EST\n");
				return (ENXIO);
			}
		}
	}

	device_set_desc(dev, "Intel Speed Shift");
	return (BUS_PROBE_DEFAULT);
}

/* FIXME: Need to support PKG variant */
static int
set_autonomous_hwp(struct hwp_softc *sc)
{
	struct pcpu *pc;
	device_t dev;
	uint64_t caps;
	int ret;

	dev = sc->dev;

	pc = cpu_get_pcpu(dev);
	if (pc == NULL)
		return (ENXIO);

	thread_lock(curthread);
	sched_bind(curthread, pc->pc_cpuid);
	thread_unlock(curthread);

	/* XXX: Many MSRs aren't readable until feature is enabled */
	ret = wrmsr_safe(MSR_IA32_PM_ENABLE, 1);
	if (ret) {
		device_printf(dev, "Failed to enable HWP for cpu%d (%d)\n",
		    pc->pc_cpuid, ret);
		goto out;
	}

	ret = rdmsr_safe(MSR_IA32_HWP_REQUEST, &sc->req);
	if (ret)
		return (ret);

	ret = rdmsr_safe(MSR_IA32_HWP_CAPABILITIES, &caps);
	if (ret)
		return (ret);

	sc->high = IA32_HWP_CAPABILITIES_HIGHEST_PERFORMANCE(caps);
	sc->guaranteed = IA32_HWP_CAPABILITIES_GUARANTEED_PERFORMANCE(caps);
	sc->efficient = IA32_HWP_CAPABILITIES_EFFICIENT_PERFORMANCE(caps);
	sc->low = IA32_HWP_CAPABILITIES_LOWEST_PERFORMANCE(caps);

	/* hardware autonomous selection determines the performance target */
	sc->req &= ~IA32_HWP_DESIRED_PERFORMANCE;

	/* enable HW dynamic selection of window size */
	sc->req &= ~IA32_HWP_ACTIVITY_WINDOW;

	/* IA32_HWP_REQUEST.Minimum_Performance = IA32_HWP_CAPABILITIES.Lowest_Performance */
	sc->req &= ~IA32_HWP_MINIMUM_PERFORMANCE;
	sc->req |= sc->low;

	/* IA32_HWP_REQUEST.Maximum_Performance = IA32_HWP_CAPABILITIES.Highest_Performance. */
	sc->req &= ~IA32_HWP_REQUEST_MAXIMUM_PERFORMANCE;
	sc->req |= sc->high << 8;

	ret = wrmsr_safe(MSR_IA32_HWP_REQUEST, sc->req);
	if (ret) {
		device_printf(dev,
		    "Failed to setup autonomous HWP for cpu%d (file a bug)\n",
		    pc->pc_cpuid);
	}

out:
	thread_lock(curthread);
	sched_unbind(curthread);
	thread_unlock(curthread);

	return (ret);
}

static int
intel_hwpstate_attach(device_t dev)
{
	struct hwp_softc *sc;
	uint32_t regs[4];
	char buf[128];
	int ret;

	KASSERT(device_find_child(device_get_parent(dev), "est", -1) == NULL,
	    ("EST driver already loaded"));

	KASSERT(device_find_child(device_get_parent(dev), "acpi_perf", -1) == NULL,
	    ("ACPI driver already loaded"));

	sc = device_get_softc(dev);
	sc->dev = dev;

	do_cpuid(6, regs);
	if (regs[0] & CPUTPM1_HWP_NOTIFICATION)
		sc->hwp_notifications = true;
	if (regs[0] & CPUTPM1_HWP_ACTIVITY_WINDOW)
		sc->hwp_activity_window = true;
	if (regs[0] & CPUTPM1_HWP_PERF_PREF)
		sc->hwp_pref_ctrl = true;
	if (regs[0] & CPUTPM1_HWP_PKG)
		sc->hwp_pkg_ctrl = true;

	ret = set_autonomous_hwp(sc);
	if (ret)
		return (ret);

	snprintf(buf, 18, "intel_hwp_debug%d", device_get_unit(dev));
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_STATIC_CHILDREN(_debug), OID_AUTO, buf,
	    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_SKIP,
	    sc, 0, intel_hwp_dump_sysctl_handler, "A", "");

	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)), OID_AUTO,
	    "epp", CTLTYPE_INT | CTLFLAG_RWTUN, dev, sizeof(dev),
	    sysctl_epp_select, "I",
	    "Efficiency/Performance Preference (0-100)");

	return (cpufreq_register(dev));
}

static int
intel_hwpstate_detach(device_t dev)
{

	return (cpufreq_unregister(dev));
}

static int
intel_hwpstate_get(device_t dev, struct cf_setting *set)
{
	struct pcpu *pc;
	uint64_t rate;
	int ret;

	if (set == NULL)
		return (EINVAL);

	pc = cpu_get_pcpu(dev);
	if (pc == NULL)
		return (ENXIO);

	memset(set, CPUFREQ_VAL_UNKNOWN, sizeof(*set));
	set->dev = dev;

	ret = cpu_est_clockrate(pc->pc_cpuid, &rate);
	if (ret == 0)
		set->freq = rate / 1000000;

	set->volts = CPUFREQ_VAL_UNKNOWN;
	set->power = CPUFREQ_VAL_UNKNOWN;
	set->lat = CPUFREQ_VAL_UNKNOWN;

	return (0);
}

static int
intel_hwpstate_type(device_t dev, int *type)
{
	if (type == NULL)
		return (EINVAL);
	*type = CPUFREQ_TYPE_ABSOLUTE | CPUFREQ_FLAG_INFO_ONLY | CPUFREQ_FLAG_UNCACHED;

	return (0);
}
