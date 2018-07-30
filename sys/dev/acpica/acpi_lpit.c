/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2018 Ben Widawsky
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * The Low Power Idle Table (LPIT) is used to help diagnose and advise in low
 * power idle states which are automatically transitioned into, and out of, by
 * Intel hardware. Details may be found here:
 * http://www.uefi.org/sites/default/files/resources/Intel_ACPI_Low_Power_S0_Idle.pdf
 *
 * Unlike a standard device driver, LPIT should be considered part of the core
 * ACPI support because it's just a table and has nothing to actually probe or
 * attach.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/resource.h>
#include <sys/rman.h>

#include <machine/clock.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/accommon.h>

#include <dev/acpica/acpivar.h>

static struct sysctl_ctx_list acpi_lpit_sysctl_ctx;
static struct sysctl_oid *lpit_sysctl_tree;

struct lpi_state {
	ACPI_GENERIC_ADDRESS residency_counter;
	struct {
		struct resource *res;
		int	type;
		int	rid;
	}	res;
	uint64_t frequency;
	bool	enabled;
}      *lpi_states;

static int acpi_lpit_residency_sysctl(SYSCTL_HANDLER_ARGS);

static void
init_sysctl(struct acpi_softc *sc)
{
	sysctl_ctx_init(&acpi_lpit_sysctl_ctx);

	lpit_sysctl_tree = SYSCTL_ADD_NODE(&acpi_lpit_sysctl_ctx,
	    SYSCTL_CHILDREN(sc->acpi_sysctl_tree), OID_AUTO, "lp_idle_residency",
	    CTLFLAG_RD, NULL, "Residency for Low Power Idle states");
}

static int
acpi_lpit_init(void *data)
{
	struct acpi_softc *sc;
	ACPI_TABLE_LPIT *hdr;
	ACPI_LPIT_NATIVE *alloc, *end;
	ACPI_STATUS status;
	int i, entries = 0;

	/*
	 * If The system doesn't have low power idle states, we don't want to bother
	 * exposing any of the residency information since BIOS vendors tend to copy
	 * and paste code and we might get non-functional residency registers in the
	 * LPIT. Perhaps in the future a quirk table would be best.
	 */
	sc = devclass_get_softc(devclass_find("acpi"), 0);
	if (sc == NULL)
		return (ENXIO);

	if ((sc->acpi_supports_s0ix & PREFER_S0IX_FADT21) == 0)
		return (ENODEV);

	status = AcpiGetTable(ACPI_SIG_LPIT, 0, (ACPI_TABLE_HEADER * *) & hdr);
	if (ACPI_FAILURE(status))
		return (ENXIO);

	init_sysctl(sc);

	end = (ACPI_LPIT_NATIVE *) ((char *)hdr + hdr->Header.Length);
	alloc = (ACPI_LPIT_NATIVE *) ((char *)hdr + sizeof(ACPI_TABLE_HEADER));

	if (end != alloc) {
		entries = (end - alloc);
		lpi_states = mallocarray(entries, sizeof(struct lpi_state), M_DEVBUF,
		    M_ZERO | M_WAITOK);
	}

	for (i = 0; alloc < end; alloc++, i++) {
		struct lpi_state *state;
		char name[16];
		int id = alloc->Header.UniqueId;

		KASSERT(i < entries, ("Invalid entries i=%d, entries=%d (%p %p)",
		    i, entries, alloc, end));

		state = &lpi_states[i];

		state->enabled = false;

		/*
		 * This checks for there being a residency counter maintained by a
		 * microcontroller which is MMIO mapped (not an MSR). It's not a
		 * surefire indication that the system supports s0ix, but it's a good
		 * hack that is used by Linux.
		 */
		if (alloc->Header.Type != ACPI_LPIT_TYPE_NATIVE_CSTATE)
			continue;

		if (alloc->Header.Flags & ACPI_LPIT_STATE_DISABLED)
			continue;

		if (alloc->ResidencyCounter.SpaceId == ACPI_ADR_SPACE_SYSTEM_MEMORY)
			sc->acpi_supports_s0ix |= PREFER_S0IX_LPIT;

		state->enabled = true;
		state->residency_counter = alloc->ResidencyCounter;
		state->frequency = alloc->CounterFrequency ?:
		    atomic_load_acq_64(&tsc_freq);
		if (alloc->ResidencyCounter.SpaceId != ACPI_ADR_SPACE_FIXED_HARDWARE) {
			acpi_bus_alloc_gas(sc->acpi_dev, &state->res.type, &state->res.rid,
			    &alloc->ResidencyCounter, &state->res.res, 0);
		}

		snprintf(name, sizeof(name), "LPI%d", id);
		SYSCTL_ADD_PROC(&acpi_lpit_sysctl_ctx,
		    SYSCTL_CHILDREN(lpit_sysctl_tree), id, name, CTLTYPE_U64 | CTLFLAG_RD,
		    sc->acpi_dev, i, acpi_lpit_residency_sysctl, "QU",
		    "Low Power Idle Residency");
	}

	return (0);
}

SYSINIT(acpi_lpit, SI_SUB_INTRINSIC_POST, SI_ORDER_ANY, acpi_lpit_init, NULL);

static uint64_t
calculate_residency(struct lpi_state *state)
{
	uint64_t residency = 0;
	int ret = 0;

	if (state->residency_counter.SpaceId == ACPI_ADR_SPACE_FIXED_HARDWARE) {
		ret = rdmsr_safe(state->residency_counter.Address, &residency);
		if (ret)
			printf("Error occured while reading MSR: 0x%lx\n",
			    state->residency_counter.Address);
	} else
		residency = bus_read_8(state->res.res, 0);

	return residency / state->frequency;
}

static int
acpi_lpit_residency_sysctl(SYSCTL_HANDLER_ARGS)
{
	device_t dev;
	struct lpi_state *state;
	uint64_t residency;

	dev = (device_t)arg1;
	state = (struct lpi_state *)&(lpi_states[arg2]);

	residency = calculate_residency(state);

	return (sysctl_handle_64(oidp, &residency, 0, req));
}
