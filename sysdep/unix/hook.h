/*
 * hook.h
 *
 *  Created on: Apr 2, 2016
 *      Author: reboot
 */

#ifndef SYSDEP_UNIX_HOOK_H_
#define SYSDEP_UNIX_HOOK_H_

#define HOOK_LOAD			0x1
#define HOOK_CONN_INBOUND_UNEXPECTED	0x2
#define HOOK_PRE_CONFIGURE		0x3
#define HOOK_POST_CONFIGURE		0x4
#define HOOK_SHUTDOWN			0x5

#define MAX_HOOKS		32

struct glob_hook
{
  unsigned int ac;
  char *exec;
};

struct glob_hook_config
{
  struct glob_hook hooks[MAX_HOOKS];
};

#include "nest/bird.h"

typedef void
(*execv_callback) (u32 index, void *d);

struct hook_execv_data
{
  execv_callback pre, add;
  void *data, *add_data;
  const char *hook_string;
  const char *protocol;
  char **argv;
  u32 flags;
};

void
hook_setenv_conf_generic (void *C);

#define HOOK_F_ASYNC		(u32)1 << 1
#define HOOK_F_NORECONF		(u32)1 << 2

#define HOOK_STATUS_NONE	(int)0
#define HOOK_STATUS_BAD		(int)1 << 1
#define HOOK_STATUS_RECONFIGURE	(int)1 << 2

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#define GET_HS(a) hook_strings[a]
#define ERRNO_STRING char __b[1024];strerror_r(errno,__b,1024);
#define ERRNO_PRINT(m,e){ERRNO_STRING;log(L_ERR m,e,__b,errno);}
#define SETENV_INT(a,b,c,d){snprintf(b,sizeof(b),a,d);setenv(c,b,1);}

#ifdef IPV6
#define SETENV_IPTOSTR(a,c){u16*ip=(u16*)c;snprintf(b, sizeof(b),"%x:%x:%x:%x:%x:%x:%x:%x",ip[1],ip[0],ip[3],ip[2],ip[5],ip[4],ip[7],ip[6]);setenv(a,b,1);}
#else
#define SETENV_IPTOSTR(a,c){u8*ip=(u8*)c;snprintf(b, sizeof(b),"%hhu.%hhu.%hhu.%hhu",ip[3],ip[2],ip[1],ip[0]);setenv(a,b,1);}
#endif

#define HOOK_PARSEOPT(a,b,c,d){if(c){d->hc.hooks[a].ac|=c;}d->hc.hooks[a].exec=b;}
#define HOOK_PARSEOPT2(a,b,c,d){if(c){d->hooks[a].ac|=c;}d->hooks[a].exec=b;}

#define F_EXECV_FORK	(u32)1 << 1

int
do_execv (const char *exec, u32 index, struct hook_execv_data *data);
struct hook_execv_data
hook_execv_mkdata (u32 ac, void *pre, void *data, const char *hs,
		   const char *proto, void *add, void *add_data, void *argv);

int
hook_run (u32 index, void *C, execv_callback add, void* add_data);

#include <stdlib.h>

#ifndef WEXITSTATUS
#define WEXITSTATUS(status)     (((status) & 0xff00) >> 8)
#endif

#include <limits.h>

#define MAX_ENV_SIZE	PATH_MAX
#define PTRSIZE 	sizeof(void*)

#define _BA_AS_PATH BA_AS_PATH


#define BGP_HOOK_IMPORT			0x18
#define BGP_HOOK_EXPORT			0x19

typedef int
generic_hook_filter (u32 index, void *P, void *RT);

generic_hook_filter filter_hook_dispatcher, bgp_hook_filter;


#define IS_PROTO_BGP(p)	(p->proto->name[0] == 0x42 && p->proto->name[1] == 0x47)

#endif /* SYSDEP_UNIX_HOOK_H_ */
