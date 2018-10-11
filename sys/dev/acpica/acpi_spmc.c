/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2018 Intel Corporation
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/types.h>
#include <sys/sbuf.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/accommon.h>

#include <dev/acpica/acpivar.h>

ACPI_MODULE_NAME("SPMC")

/* Published specs only have rev 0, but Linux uses rev 1 */
#define SPMC_REVISION 1
enum {
	LPS0_DEVICE_CONSTRAINTS	= 1,
	LPS0_CRASH_DUMP_DEV 	= 2,
	LPS0_SCREEN_OFF		= 3,
	LPS0_SCREEN_ON		= 4,
	LPS0_ENTRY 		= 5,
	LPS0_EXIT 		= 6
};

static uint8_t lps0_uuid[16] = {
	0xa0, 0x40, 0xeb, 0xc4, 0xd2, 0x6c, 0xe2, 0x11,
	0xbc, 0xfd, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66};

static struct sysctl_ctx_list acpi_spmc_sysctl_ctx;
static struct sysctl_oid *spmc_sysctl_tree;

static int acpi_spmc_probe(device_t dev);
static int acpi_spmc_attach(device_t dev);
static int acpi_spmc_post_suspend(device_t dev);
static int acpi_spmc_post_resume(device_t dev);
static int walk_constraints(ACPI_HANDLE handle);

/*
 * Driver softc.
 */
struct acpi_spmc_softc {
	device_t 		dev;	/* This device */
	ACPI_HANDLE 		handle; /* This device's handle */
	ACPI_OBJECT		*obj;   /* The constraint object */
};

struct device_constraint {
	SLIST_ENTRY(device_constraint)  dc_link;
	ACPI_HANDLE			handle;
	device_t			dev;
	bool				configured;

	ACPI_OBJECT			*obj;

	/* Parsed ACPI object info */
	ACPI_STRING 			name;
	ACPI_INTEGER		 	enabled;
	ACPI_INTEGER			revision;
	ACPI_INTEGER			lpi_uid;
	ACPI_INTEGER			min_dstate;
	ACPI_INTEGER			optional;
};

static SLIST_HEAD(, device_constraint) devices_list =
    SLIST_HEAD_INITIALIZER(devices_list);

static device_method_t acpi_spmc_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		acpi_spmc_probe),
	DEVMETHOD(device_attach,	acpi_spmc_attach),
	DEVMETHOD(device_post_suspend,	acpi_spmc_post_suspend),
	DEVMETHOD(device_post_resume,	acpi_spmc_post_resume),

	DEVMETHOD_END
};

static driver_t acpi_spmc_driver = {
	"acpi_spmc",
	acpi_spmc_methods,
	sizeof(struct acpi_spmc_softc),
};

static devclass_t acpi_spmc_devclass;

/* XXX: Try to install near the end so we get most devices during our attach. */
DRIVER_MODULE_ORDERED(acpi_spmc, acpi, acpi_spmc_driver, acpi_spmc_devclass, 0,
    0, SI_ORDER_ANY);
MODULE_DEPEND(acpi_spmc, acpi, 1, 1, 1);


static int
acpi_spmc_probe(device_t dev)
{
	char desc[64];
	static char *spmc_ids[] = {"PNP0D80", NULL};
	uint8_t dsm_bits = 0;
	int err;

	/* Check that this is an enabled device */
	if (acpi_get_type(dev) != ACPI_TYPE_DEVICE || acpi_disabled("spmc"))
		return (ENXIO);

	err = ACPI_ID_PROBE(device_get_parent(dev), dev, spmc_ids, NULL);
	if (err > 0)
		return (err);

	dsm_bits = acpi_DSMQuery(acpi_get_handle(dev), lps0_uuid, SPMC_REVISION);
	if ((dsm_bits & 1) == 0) {
		device_printf(dev, "Useless device without _DSM\n");
		return (ENODEV);
	}

	acpi_set_private(dev, (void *)(uintptr_t)dsm_bits);
	snprintf(desc, sizeof(desc),
	    "System Power Management Controller: funcs (0x%02x)\n", dsm_bits);

	device_set_desc_copy(dev, desc);

	return (BUS_PROBE_DEFAULT);
}

/*
 * Parses a power constraint into the provided structure.
 *
 * Returns ENXIO if the entire object is invalid, and EINVAL if any individual
 * field is invalid.
 *
 * Table 7 Device Constraint Entry Format
 * _____________________________________________________________________
 * | Field   Name            | Format |       Description              |
 * |-------------------------|--------|--------------------------------|
 * | Device Name             | String | Fully qualified Namestring     |
 * |-------------------------|--------|--------------------------------|
 * | Device Enabled          | Integer| 0=Disabled, no constraints     |
 * |                         |        | Non-zero=Device is enabled and |
 * |                         |        | constraints apply	       |
 * |-------------------------|--------|--------------------------------|
 * | Device Constraint Detail| Package| see Table 8                    |
 * ---------------------------------------------------------------------
 *
 * Table 8 Revision Package Format
 * _____________________________________________________________________
 * | Field   Name            | Format   |       Description            |
 * |-------------------------|----------|------------------------------|
 * | Revision                | Integer  |  Integer (zero)              |
 * |-------------------------|----------|------------------------------|
 * | Constraint Package      |Constraint| Package (see Table 9)        |
 * |                         | Package  |                              |
 * ---------------------------------------------------------------------
 *
 * Table 9 Constraint Package
 * ______________________________________________________________________
 * | Field   Name            | Format   |       Description             |
 * |-------------------------|----------|-------------------------------|
 * | LPI UID                 |Integer   | LPIT entry (see Section 2.2)  |
 * |                         |          | 0xFF:Constraint applies to all|
 * |                         |          | entries in LPIT               |
 * |-------------------------|----------|-------------------------------|
 * | Minimum D-state         |  Integer | Minimum D-state constraint.   |
 * |                         |          | 0 = D0                        |
 * |                         |          | 1 = D1                        |
 * |                         |          | 2 = D2                        |
 * |                         |          | 3 = D3                        |
 * |-------------------------|----------|-------------------------------|
 * | Minimum device-specific | Integer  | device-specific information   |
 * | state Precondition      |          |                               |
 * --------------------------|----------|--------------------------------
 */
static int
parse_constraint(ACPI_OBJECT *obj, struct device_constraint *constraint)
{
	ACPI_OBJECT *iter;
	ACPI_INTEGER enable;
	int ret;

	if (!ACPI_PKG_VALID(obj, 3))
		return ENXIO;

	iter = obj;
	/* Table 7 - Device Constraint */
	if (iter->Package.Elements[0].Type != ACPI_TYPE_STRING) {
		ret = EINVAL;
		goto err;
	}
	constraint->name = iter->Package.Elements[0].String.Pointer;

	ret = acpi_PkgInt(iter, 1, &enable);
	if (ret)
		goto err;

	if (!ACPI_PKG_VALID(&iter->Package.Elements[2], 2)) {
		ret = EINVAL;
		goto err;
	}

	/* Table 8 - Revision Package */
	iter = &iter->Package.Elements[2];
	ret = acpi_PkgInt(iter, 0, &constraint->revision);
	if (ret)
		goto err;

	if (constraint->revision > 0)
		printf("Unknown revision for device constraint->\n");

	/* The spec allows the third element to not exist */
	if (!ACPI_PKG_VALID(&iter->Package.Elements[1], 2)) {
		ret = ENXIO;
		goto err;
	}

	/* Table 9 - Constraint Package */
	iter = &iter->Package.Elements[1];
	ret = acpi_PkgInt(iter, 0, &constraint->lpi_uid);
	if (ret)
		goto err;
	ret = acpi_PkgInt(iter, 1, &constraint->min_dstate);
	if (ret)
		goto err;

	MPASS(constraint->name != NULL);

	return (0);

err:
	device_printf(constraint->dev,
	    "Unexpected error in parsing device constraints\n");
	return (ret);
}

static int
walk_constraints(ACPI_HANDLE handle)
{
	ACPI_STATUS status;
	ACPI_BUFFER buf;
	ACPI_OBJECT *obj;
	int i;

	status = acpi_EvaluateDSM(handle, lps0_uuid, SPMC_REVISION,
	    LPS0_DEVICE_CONSTRAINTS, NULL, &buf);

	if (ACPI_FAILURE(status))
		return (ENXIO);

	obj = (ACPI_OBJECT *) buf.Pointer;
	if (obj == NULL || obj->Type != ACPI_TYPE_PACKAGE)
		return (ENXIO);

	for (i = 0; i < obj->Package.Count; i++) {
		struct device_constraint *c;
		int ret;

		c = malloc(sizeof(*c), M_DEVBUF, M_ZERO | M_WAITOK);
		ret = parse_constraint(&obj->Package.Elements[i], c);
		if (ret) {
			free(c, M_DEVBUF);
			continue;
		}

		/* Add it to the list */
		c->obj = &obj->Package.Elements[i];
		c->handle = acpi_GetReference(NULL, &c->obj->Package.Elements[0]);
		c->dev = acpi_get_device(c->handle);
		SLIST_INSERT_HEAD(&devices_list, c, dc_link);

		/* If we can find the device now, just handle it */
		if (c->dev && c->min_dstate == 3)
			device_set_idle_suspend(c->dev);

		if (c->dev) {
			c->configured = true;
		} else if (c->handle) {
			/*
			 * There is no device_t for this and it may or
			 * may not exist later
			 */
		}
	}

	return (0);
}

static int
sysctl_dump_constraints(SYSCTL_HANDLER_ARGS)
{
	struct device_constraint *device;
	struct sbuf *sb;
	int error;

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);

	sb = sbuf_new_for_sysctl(NULL, NULL, 0, req);
	if (sb == NULL)
		return (ENOMEM);

	SLIST_FOREACH(device, &devices_list, dc_link)
		sbuf_printf(sb, "%s: D%ld\n", device->name, device->min_dstate);

	error = sbuf_finish(sb);
	sbuf_delete(sb);

	return (error);
}

static int
acpi_spmc_attach(device_t dev)
{
	struct acpi_spmc_softc *sc;
	struct acpi_softc *acpi_sc;
	device_t nexus;
	uint8_t dsm_bits;

	sc = device_get_softc(dev);
	sc->dev = dev;
	sc->handle = acpi_get_handle(dev);

	acpi_sc = acpi_device_get_parent_softc(sc->dev);

	dsm_bits = (uint8_t)acpi_get_private(dev);
	if (dsm_bits & LPS0_DEVICE_CONSTRAINTS) {
		int ret = walk_constraints(sc->handle);
		if (ret)
			return ret;

		/*
		 * This will be the final piece of enabling s0ix for suspend
		 * to idle.
		 */
		if ((dsm_bits & (LPS0_ENTRY | LPS0_EXIT)) == (LPS0_ENTRY | LPS0_EXIT)) {
			acpi_sc->acpi_supports_s0ix |= PREFER_S0IX_DSM;
			nexus = device_find_child(root_bus, "nexus", 0);
			device_set_idle_suspend(nexus);
		}
	}

	acpi_sc->acpi_pm_device = dev;

	spmc_sysctl_tree = SYSCTL_ADD_NODE(&acpi_spmc_sysctl_ctx,
	    SYSCTL_CHILDREN(acpi_sc->acpi_sysctl_tree), OID_AUTO, "SPMC",
	    CTLFLAG_RD, NULL, "System Power Management Controller");

	SYSCTL_ADD_PROC(&acpi_spmc_sysctl_ctx,
	    SYSCTL_CHILDREN(spmc_sysctl_tree), OID_AUTO, "min_dstate",
	    CTLTYPE_STRING | CTLFLAG_RD, NULL, 0, sysctl_dump_constraints, "A",
	    "Minimum dstates");

	return (0);
}

static int
spmc_do_dsm(device_t dev, uint32_t cmd)
{
	ACPI_BUFFER b;
	ACPI_STATUS err;

	err = acpi_EvaluateDSM(acpi_get_handle(dev), lps0_uuid, SPMC_REVISION,
			       cmd, NULL, &b);
	if (ACPI_SUCCESS(err))
	    AcpiOsFree(b.Pointer);

	return err;
}

static int
acpi_spmc_post_suspend(device_t dev)
{
	if (spmc_do_dsm(dev, LPS0_SCREEN_OFF))
		return (ENODEV);

	if (spmc_do_dsm(dev, LPS0_ENTRY)) {
		spmc_do_dsm(dev, LPS0_SCREEN_ON);
		return (ENODEV);
	}

	return (0);
}

static int
acpi_spmc_post_resume(device_t dev)
{
	spmc_do_dsm(dev, LPS0_EXIT);
	spmc_do_dsm(dev, LPS0_SCREEN_ON);
	return (0);
}
