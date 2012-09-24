/* libtinynotify
 * (c) 2011 Michał Górny
 * 2-clause BSD-licensed
 */

#include "config.h"
#include "tinynotify-systemwide.h"
#include <tinynotify.h>

#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>

#include <proc/readproc.h>

#include <assert.h>

const struct notify_error _error_syscall_failed = { "Required system call %s failed: %s" };
const NotifyError NOTIFY_ERROR_SYSCALL_FAILED = &_error_syscall_failed;
const struct notify_error _error_uids_compromised = { "Required system call setresuid() failed to restore UIDs: %s" };
const struct notify_error _error_no_bus_found = { "No D-Bus session bus process found" };
const NotifyError NOTIFY_ERROR_NO_BUS_FOUND = &_error_no_bus_found;

static int _proc_matches_dbus_session(proc_t* const p) {
	const char *procname;
	char* const *ap;

	if (!p->cmdline)
		return 0;

	/* Check whether the binary name matches. */
	procname = basename(p->cmdline[0]);
	if (strcmp(procname, "dbus-daemon"))
		return 0;

	/* Lookup supplied command-line argument list for '--session'.
	 * We don't have to worry about additional '--system' arguments as
	 * dbus refuses to run with multiple configuration files supplied.
	 */
	for (ap = &(p->cmdline[1]); *ap; ap++)
		if (!strcmp(*ap, "--session"))
			return 1;

	return 0;
}

static char *_proc_getenv(const proc_t* const p, const char* const keystr) {
	char* const *ap;
	const int matchlen = strlen(keystr);

	assert(keystr[matchlen-1] == '=');

	if (!p->environ)
		return NULL;

	for (ap = p->environ; *ap; ap++) {
		if (!strncmp(*ap, keystr, matchlen))
			return *ap;
	}

	return NULL;
}

static int _notification_send_for_bus(Notification n, NotifySession s,
		uid_t uid) {
	int ret = -1;

	/* D-Bus no longer likes to talk to setuid processes, so we need to
	 * fork and switch UIDs completely. */
	pid_t pid = fork();
	switch (pid)
	{
		case -1:
			break;

		case 0:
			/* We need to use setreuid() because D-Bus checks uid & euid */
			setreuid(uid, uid);

			/* Ensure getting a new connection. */
			notify_session_disconnect(s);
			exit(!!notification_send(n, s));

		default:
			waitpid(pid, &ret, 0);
	}

	return ret;
}

int notification_send_systemwide(Notification n, NotifySession s) {
	PROCTAB *proc;
	proc_t *p = NULL;
	int ret = 0;

	proc = openproc(PROC_FILLCOM | PROC_FILLENV);
	if (!proc) {
		notify_session_set_error(s, NOTIFY_ERROR_SYSCALL_FAILED,
				"openproc()", strerror(errno) /* XXX */);
		return 0;
	}

	notify_session_set_error(s, NOTIFY_ERROR_NO_BUS_FOUND);

	while (((p = readproc(proc, p)))) {
		if (_proc_matches_dbus_session(p)) {
			char* const display = _proc_getenv(p, "DISPLAY=");
			char* const xauth = _proc_getenv(p, "XAUTHORITY=");
			char* home = _proc_getenv(p, "HOME=");
			const struct passwd* const pw = getpwuid(p->euid); /* XXX */

			/* All of the following are necessary to proceed. */
			if (!display || !pw || (!xauth && !home && !pw->pw_dir))
				continue;

			/* Set environment early;
			 * we won't have to worry about UIDs if it fails. */
			if (putenv(display)) {
				notify_session_set_error(s, NOTIFY_ERROR_SYSCALL_FAILED,
						"putenv(DISPLAY)", strerror(errno));
				break;
			}
			if (xauth) {
				if (putenv(xauth)) {
					notify_session_set_error(s, NOTIFY_ERROR_SYSCALL_FAILED,
							"putenv(XAUTHORITY)", strerror(errno));
					break;
				}
			} else {
				if (unsetenv("XAUTHORITY")) {
					notify_session_set_error(s, NOTIFY_ERROR_SYSCALL_FAILED,
							"unsetenv(XAUTHORITY)", strerror(errno));
					break;
				}
				if (home) {
					if (putenv(home)) {
						notify_session_set_error(s, NOTIFY_ERROR_SYSCALL_FAILED,
								"putenv(HOME)", strerror(errno));
						break;
					}
				} else {
					if (setenv("HOME", pw->pw_dir, 1)) {
						notify_session_set_error(s, NOTIFY_ERROR_SYSCALL_FAILED,
								"setenv(HOME)", strerror(errno));
						break;
					}
				}
			}

			if (!_notification_send_for_bus(n, s, p->euid))
				ret += 1;
		}
	}
	closeproc(proc);

	return ret;
}
