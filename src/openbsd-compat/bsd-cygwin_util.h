/* $Id: bsd-cygwin_util.h,v 1.1.1.1 2005-02-27 17:08:49 cmn Exp $ */

/*
 * Copyright (c) 2000, 2001, Corinna Vinschen <vinschen@cygnus.com>
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
 *
 * Created: Sat Sep 02 12:17:00 2000 cv
 *
 * This file contains functions for forcing opened file descriptors to
 * binary mode on Windows systems.
 */

#ifndef _BSD_CYGWIN_UTIL_H
#define _BSD_CYGWIN_UTIL_H

#ifdef HAVE_CYGWIN

#undef ERROR
#define is_winnt       (GetVersion() < 0x80000000)

#include <windows.h>
#include <sys/cygwin.h>
#include <io.h>

int binary_open(const char *, int , ...);
int binary_pipe(int fd[2]);
int check_nt_auth(int, struct passwd *);
int check_ntsec(const char *);
void register_9x_service(void);

#define open binary_open
#define pipe binary_pipe

#endif /* HAVE_CYGWIN */

#endif /* _BSD_CYGWIN_UTIL_H */
