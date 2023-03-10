/* $Id: openbsd-compat.h,v 1.1.1.1 2005-02-27 17:08:49 cmn Exp $ */

/*
 * Copyright (c) 1999-2003 Damien Miller.  All rights reserved.
 * Copyright (c) 2003 Ben Lindstrom. All rights reserved.
 * Copyright (c) 2002 Tim Rice.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _OPENBSD_COMPAT_H
#define _OPENBSD_COMPAT_H

#include "includes.h"

/* OpenBSD function replacements */
#include "base64.h"
#include "sigact.h"
#include "glob.h"
#include "readpassphrase.h"
#include "vis.h"
#include "getrrsetbyname.h"


#ifndef HAVE_BASENAME
char *basename(const char *path);
#endif

#ifndef HAVE_BINDRESVPORT_SA
int bindresvport_sa(int sd, struct sockaddr *sa);
#endif

#ifndef HAVE_CLOSEFROM
void closefrom(int);
#endif

#ifndef HAVE_GETCWD
char *getcwd(char *pt, size_t size);
#endif 

#if !defined(HAVE_REALPATH) || defined(BROKEN_REALPATH)
char *realpath(const char *path, char *resolved);
#endif 

#ifndef HAVE_RRESVPORT_AF
int rresvport_af(int *alport, sa_family_t af);
#endif

#ifndef HAVE_STRLCPY
/* #include <sys/types.h> XXX Still needed? */
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
/* #include <sys/types.h> XXX Still needed? */
size_t strlcat(char *dst, const char *src, size_t siz);
#endif 

#ifndef HAVE_SETENV
int setenv(register const char *name, register const char *value, int rewrite);
#endif

#ifndef HAVE_STRMODE
void strmode(int mode, char *p);
#endif

#if !defined(HAVE_MKDTEMP) || defined(HAVE_STRICT_MKSTEMP)
int mkstemps(char *path, int slen);
int mkstemp(char *path);
char *mkdtemp(char *path);
#endif 

#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose);
#endif 

#ifndef HAVE_DIRNAME
char *dirname(const char *path);
#endif

#if defined(BROKEN_INET_NTOA) || !defined(HAVE_INET_NTOA)
char *inet_ntoa(struct in_addr in);
#endif

#ifndef HAVE_INET_NTOP
const char *inet_ntop(int af, const void *src, char *dst, size_t size);
#endif

#ifndef HAVE_INET_ATON
int inet_aton(const char *cp, struct in_addr *addr);
#endif 

#ifndef HAVE_STRSEP
char *strsep(char **stringp, const char *delim);
#endif

#ifndef HAVE_SETPROCTITLE
void setproctitle(const char *fmt, ...);
void compat_init_setproctitle(int argc, char *argv[]);
#endif

#ifndef HAVE_GETGROUPLIST
/* #include <grp.h> XXXX Still needed ? */
int getgrouplist(const char *, gid_t, gid_t *, int *);
#endif

#if !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
int BSDgetopt(int argc, char * const *argv, const char *opts);
#endif


/* Home grown routines */
#include "bsd-misc.h"
#include "bsd-waitpid.h"

/*#include <sys/types.h> XXX Still needed? * For uid_t, gid_t * */

#ifndef HAVE_GETPEEREID
int getpeereid(int , uid_t *, gid_t *);
#endif 

#ifndef HAVE_ARC4RANDOM
unsigned int arc4random(void);
void arc4random_stir(void);
#endif /* !HAVE_ARC4RANDOM */

#ifndef HAVE_OPENPTY
int openpty(int *, int *, char *, struct termios *, struct winsize *);
#endif /* HAVE_OPENPTY */

/* #include <sys/types.h> XXX needed? For size_t */

#ifndef HAVE_SNPRINTF
int snprintf(char *, size_t, const char *, ...);
#endif 

#ifndef HAVE_VSNPRINTF
int vsnprintf(char *, size_t, const char *, va_list);
#endif

void *xmmap(size_t size);
char *xcrypt(const char *password, const char *salt);
char *shadow_pw(struct passwd *pw);


/* rfc2553 socket API replacements */
#include "fake-rfc2553.h"

/* Routines for a single OS platform */
#include "bsd-cray.h"
#include "bsd-cygwin_util.h"
#include "port-irix.h"
#include "port-aix.h"

#endif /* _OPENBSD_COMPAT_H */
