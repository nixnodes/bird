/*
 *     BIRD -- BGP event hooks
 *
 */

#include "hook.h"
#include "bgp.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#define ERRNO_STRING char __b[1024];strerror_r(errno,__b,1024);

#define ERRNO_PRINT(m,e){ERRNO_STRING;log(L_ERR m,e,__b,errno);}
#define SETENV_INT(a,b,c,d){snprintf(b,sizeof(b),a,d);setenv(c,b,1);}

char *bgp_hook_strings[BGP_MAX_HOOKS] =
  { [BGP_HOOK_ENTER_ESTABLISHED] = "BGP_HOOK_ENTER_ESTABLISHED",
      [BGP_HOOK_LEAVE_ESTABLISHED ] = "BGP_HOOK_LEAVE_ESTABLISHED",
      [BGP_HOOK_ENTER_CLOSE ] = "BGP_HOOK_ENTER_CLOSE", [BGP_HOOK_ENTER_IDLE
	  ] = "BGP_HOOK_ENTER_IDLE", [BGP_HOOK_ENTER_OPENCONFIRM
	  ] = "BGP_HOOK_ENTER_OPENCONFIRM", [BGP_HOOK_CHANGE_STATE
	  ] = "BGP_HOOK_CHANGE_STATE", [BGP_HOOK_REFRESH_BEGIN
	  ] = "BGP_HOOK_REFRESH_BEGIN", [BGP_HOOK_REFRESH_END
	  ] = "BGP_HOOK_REFRESH_END", [BGP_HOOK_INIT] = "BGP_HOOK_INIT",
      [BGP_HOOK_START] = "BGP_HOOK_START", [BGP_HOOK_DOWN] = "BGP_HOOK_DOWN",
      [BGP_HOOK_CONN_OUTBOUND ] = "BGP_HOOK_CONN_OUTBOUND", [BGP_HOOK_SHUTDOWN
	  ] = "BGP_HOOK_SHUTDOWN", [BGP_HOOK_NEIGH_GRESTART
	  ] = "BGP_HOOK_NEIGH_GRESTART", [BGP_HOOK_NEIGH_START
	  ] = "BGP_HOOK_NEIGH_START", [BGP_HOOK_CONN_INBOUND
	  ] = "BGP_HOOK_CONN_INBOUND", [BGP_HOOK_FEED_BEGIN
	  ] = "BGP_HOOK_FEED_BEGIN", [BGP_HOOK_FEED_END ] = "BGP_HOOK_FEED_END",
      [BGP_HOOK_KEEPALIVE] = "BGP_HOOK_KEEPALIVE" };

#ifdef IPV6
#define SETENV_IPTOSTR(a,c){u16*ip=(u16*)c;snprintf(b, sizeof(b),"%x:%x:%x:%x:%x:%x:%x:%x",ip[1],ip[0],ip[3],ip[2],ip[5],ip[4],ip[7],ip[6]);setenv(a,b,1);}
#else
#define SETENV_IPTOSTR(a,c){u8*ip=(u8*)c;snprintf(b, sizeof(b),"%hhu.%hhu.%hhu.%hhu",ip[3],ip[2],ip[1],ip[0]);setenv(a,b,1);}
#endif

static int
bgp_create_hook (u32 index, struct bgp_proto *p)
{
  p->hooks[index] = p->cf->hc.hooks[index];

  /*log (L_DEBUG "%s: %shook %s created", p->cf->c.name,
   p->hooks[index].ac & BGP_HOOK_F_ASYNC ? "asynchronous " : "",
   GET_HS(index));*/

  return 0;
}

int
bgp_parse_hooks (void *P)
{
  struct bgp_proto *p = (struct bgp_proto *) P;

  memset (p->hooks, 0x0, sizeof(p->hooks));

  int index;
  for (index = 1; index < BGP_MAX_HOOKS; index++)
    {
      struct bgp_hook *h = &p->cf->hc.hooks[index];
      if (h->exec != NULL)
	{
	  bgp_create_hook (index, p);
	}
    }

  char b[16];

  SETENV_INT("%d", b, "BGP_HOOK_STATUS_BAD", BGP_HOOK_STATUS_BAD);
  SETENV_INT("%d", b, "BGP_HOOK_STATUS_RECONFIGURE",
	     BGP_HOOK_STATUS_RECONFIGURE);

  return 0;
}

int
bgp_check_hooks (void *C)
{
  struct bgp_config *c = (struct bgp_config *) C;

  int index;
  int r = 0;

  for (index = 1; index < BGP_MAX_HOOKS; index++)
    {
      struct bgp_hook *h = &c->hc.hooks[index];
      if (h->exec == NULL)
	{
	  continue;
	}

      int t;
      r += (t = access (h->exec, R_OK | X_OK));

      if (t)
	{
	  ERRNO_STRING
	  log (L_ERR "%s: %s: '%s' can not be executed: %s", c->c.name,
	       GET_HS(index), h->exec, __b);
	}
    }

  return r;
}

static void
bgp_build_hook_envvars (u32 index, struct bgp_proto *p)
{
  char b[MAX_ENV_SIZE];

  setenv ("BGP_EVENT", GET_HS(index), 1);
  SETENV_INT("%u", b, "EVENT_INDEX", index);

  if (p->cf->c.dsc != NULL)
    {
      setenv ("PROTO_DESC", p->cf->c.dsc, 1);
    }

  setenv ("PROTO_NAME", p->cf->c.name, 1);

  SETENV_IPTOSTR("REMOTE_IP", &p->cf->remote_ip);
  SETENV_IPTOSTR("CFG_SOURCE_IP", &p->cf->source_addr);
  SETENV_IPTOSTR("SOURCE_IP", &p->source_addr);

  SETENV_INT("%hu", b, "REMOTE_PORT", p->cf->remote_port);
  SETENV_INT("%u", b, "REMOTE_AS", p->cf->remote_as);
  SETENV_INT("%hhu", b, "LAST_ERROR_CLASS", p->last_error_class);
  SETENV_INT("%u", b, "LAST_ERROR_CODE", p->last_error_code);
  SETENV_INT("%u", b, "LOCAL_ID", p->local_id);
  SETENV_INT("%u", b, "REMOTE_ID", p->remote_id);
  SETENV_INT("%hhu", b, "IS_INTERNAL", p->is_internal);
  SETENV_INT("%hhu", b, "LOAD_STATE", p->load_state);
  SETENV_INT("%hhu", b, "DOWN_CODE", p->p.down_code);
  SETENV_INT("%hhu", b, "DOWN_SCHED", p->p.down_sched);
  SETENV_INT("%d", b, "START_STATE", p->start_state);
  SETENV_INT("%hhu", b, "PROTO_STATE", p->p.proto_state);
  SETENV_INT("%hhu", b, "CORE_STATE", p->p.core_state);
  SETENV_INT("%hhu", b, "IS_RECONFIGURING", p->p.reconfiguring);
  SETENV_INT("%hhu", b, "IS_DISABLED", p->p.disabled);
  SETENV_INT("%hhu", b, "FEED_STATE", p->feed_state);
  SETENV_INT("%d", b, "TABLE_USE_COUNT", p->p.table->use_count);
  SETENV_INT("%hhu", b, "AS4_SESSION", p->as4_session);
  SETENV_INT("%hhu", b, "GR_READY", p->gr_ready);
  SETENV_INT("%hhu", b, "GR_ACTIVE", p->gr_active);
  SETENV_INT("%d", b, "RR_CLIENT", p->rr_client);
  SETENV_INT("%d", b, "RS_CLIENT", p->rs_client);
  SETENV_INT("%u", b, "LAST_PROTO_ERROR", (unsigned int )p->last_proto_error);
  SETENV_INT("%u", b, "STARTUP_DELAY", p->startup_delay);
  setenv ("TABLE_NAME", p->p.table->name, 1);

  if (p->conn != NULL)
    {
      SETENV_INT("%u", b, "CONN_STATE", p->conn->state);
    }
  else
    {
      setenv ("CONN_STATE", "0", 1);
    }

  SETENV_INT("%u", b, "BIRD_PID", getpid ());
}

static int
prep_for_exec (u32 index, struct bgp_proto *p)
{
  const char inputfile[] = "/dev/null";

  if (close (STDIN_FILENO) < 0)
    {
      return 1;
    }
  else
    {
      if (open (inputfile, O_RDONLY
#if defined O_LARGEFILE
		| O_LARGEFILE
#endif
		) < 0)
	{
	  log (L_ERR "ERROR: could not open %s", inputfile);
	}
    }

  return 0;
}

static int
do_execv (const char *exec, u32 index, struct bgp_proto *p)
{
  pid_t c_pid;

  bgp_build_hook_envvars (index, p);

  if ((c_pid = fork ()) == (pid_t) -1)
    {
      ERRNO_PRINT("%s: fork failed [%s]", GET_HS(index))
      return 1;
    }

  if (0 == c_pid)
    {
      if (prep_for_exec (index, p))
	{
	  _exit (1);
	}
      else
	{
	  const char *argv[] =
	    { [0] = exec, [1] = NULL };
	  execv (exec, (char**) argv);
	  ERRNO_PRINT("%s: execv failed [%s]", GET_HS(index))
	  _exit (1);
	}
    }

  if (p->hooks[index].ac & BGP_HOOK_F_ASYNC)
    {
      log (L_DEBUG "%s: forked %s to background | %s", GET_HS(index), exec,
	   p->cf->c.name);
      return 0;
    }
  else
    {
      log (L_DEBUG "%s: %u executed '%s' on %s", GET_HS(index), c_pid, exec,
	   p->cf->c.name);

      int status;

      while (waitpid (c_pid, &status, 0) == (pid_t) -1)
	{
	  if (errno != EINTR)
	    {
	      ERRNO_PRINT(
		  "hook: %s: failed waiting for child process to finish [%s]",
		  GET_HS(index))
	      return -1;
	    }
	}

      int r = WEXITSTATUS(status);

      log (L_DEBUG "%s: %u exited with status: %d | %s", GET_HS(index), c_pid,
	   r, p->cf->c.name);

      return r;
    }
}

#include "sysdep/unix/unix.h"

int
bgp_hook_run (u32 index, void *P)
{
  struct bgp_proto *p = (struct bgp_proto *) P;
  struct bgp_hook *h = &p->hooks[index];

  if (h->exec != NULL)
    {
      int r = do_execv (h->exec, index, p);
      if (r & BGP_HOOK_STATUS_RECONFIGURE)
	async_config ();

      return r;
    }
  else
    {
      return 0;
    }
}
