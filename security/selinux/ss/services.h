/*
 * Implementation of the security services.
 *
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil>
 */
#ifndef _SS_SERVICES_H_
#define _SS_SERVICES_H_

#include "policydb.h"
#include "sidtab.h"

extern struct policydb policydb;

<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> 03ef60a... selinux: extended permissions for ioctls
void services_compute_xperms_drivers(struct extended_perms *xperms,
				struct avtab_node *node);

void services_compute_xperms_decision(struct extended_perms_decision *xpermd,
<<<<<<< HEAD
=======
void services_compute_operation_type(struct operation *ops,
				struct avtab_node *node);

void services_compute_operation_num(struct operation_decision *od,
>>>>>>> 57ce68f... SELinux: per-command whitelisting of ioctls
=======
>>>>>>> 03ef60a... selinux: extended permissions for ioctls
					struct avtab_node *node);

#endif	/* _SS_SERVICES_H_ */

