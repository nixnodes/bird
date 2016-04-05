/*
 * hook.c
 *
 *  Created on: Apr 2, 2016
 *      Author: reboot
 */

#include "nest/bird.h"
#include "nest/protocol.h"

#include "sysdep/unix/unix.h"
#include "sysdep/unix/hook.h"
#include "conf/conf.h"


#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

static const char *hook_strings[MAX_HOOKS] =
  { [HOOK_CONN_INBOUND_UNEXPECTED ] = "HOOK_CONN_INBOUND_UNEXPECTED", [HOOK_LOAD
      ] = "HOOK_LOAD", [HOOK_POST_CONFIGURE] = "HOOK_POST_CONFIGURE",
      [HOOK_PRE_CONFIGURE] = "HOOK_PRE_CONFIGURE", [HOOK_SHUTDOWN
	  ] = "HOOK_SHUTDOWN" };

static int
prep_for_exec (void)
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

int
do_execv (const char *exec, u32 index, struct hook_execv_data *data)
{
  pid_t c_pid;

  if (data->pre != NULL)
    {
      data->pre (index, data->data);
    }

  if (data->add != NULL)
    {
      data->add (index, data->add_data);
    }

  if ((c_pid = fork ()) == (pid_t) -1)
    {
      ERRNO_PRINT("%s: fork failed [%s]", data->hook_string)
      return 1;
    }

  if (0 == c_pid)
    {
      if (prep_for_exec ())
	{
	  _exit (1);
	}
      else
	{
	  if (data->argv == NULL)
	    {
	      const char *argv[] =
		{ [0] = exec, [1] = NULL };
	      execv (exec, (char**) argv);
	    }
	  else
	    {
	      execv (exec, data->argv);
	    }
	  ERRNO_PRINT("%s: execv failed [%s]", data->hook_string)
	  _exit (1);
	}
    }

  if (data->flags & F_EXECV_FORK)
    {
      log (L_DEBUG "%s: %s: forked %s to background", data->protocol,
	   data->hook_string, exec);
      return 0;
    }
  else
    {
      log (L_DEBUG "%s: %s: %u executing '%s'", data->protocol,
	   data->hook_string, c_pid, exec);

      int status;

      while (waitpid (c_pid, &status, 0) == (pid_t) -1)
	{
	  if (errno != EINTR)
	    {
	      ERRNO_PRINT(
		  "hook: %s: failed waiting for child process to finish [%s]",
		  data->hook_string)
	      return 1;
	    }
	}

      int r = WEXITSTATUS(status);

      log (L_DEBUG "%s: %s: %u exited with status: %d", data->protocol,
	   data->hook_string, c_pid, r);

      if ((r & HOOK_STATUS_RECONFIGURE) && !(data->flags & HOOK_F_NORECONF))
	{
	  log (L_DEBUG "%s: %s: external process requesting reconfigure..",
	       data->protocol, data->hook_string);
	  async_config ();
	}

      return r;
    }
}

struct hook_execv_data
hook_execv_mkdata (u32 ac, void *pre, void *data, const char *hs,
		   const char *proto, void *add, void *add_data, void *argv)
{
  struct hook_execv_data t =
    { .flags = ac, .pre = pre, .data = data, .hook_string = hs, .protocol =
	proto, .argv = (char**) argv, .add = add, .add_data = add_data };
  return t;
}

static void
build_hook_envvars (u32 index, void *C)
{
  struct config *c = (struct config *) C;
  char b[MAX_ENV_SIZE];
  setenv ("EVENT", GET_HS(index), 1);
  SETENV_INT("%u", b, "EVENT_INDEX", index);
  setenv ("ERR_MSG", c->err_msg ? c->err_msg : "", 1);
  setenv ("ERR_FILE_NAME", c->err_file_name ? c->err_file_name : "", 1);
}

int
hook_run (u32 index, void *C, execv_callback add, void *add_data)
{
  struct config *c = (struct config *) C;

  if (c == NULL)
    {
      return HOOK_STATUS_NONE ;
    }

  struct glob_hook *h = &c->hooks[index];

  if (h->exec != NULL)
    {
      struct hook_execv_data data = hook_execv_mkdata (h->ac,
						       build_hook_envvars,
						       (void*) c, GET_HS(index),
						       "global", add, add_data,
						       NULL);

      data.add = add;
      data.add_data = add_data;

      return do_execv (h->exec, index, &data);
    }
  else
    {
      return HOOK_STATUS_NONE ;
    }
}

void
hook_setenv_conf_generic (void *c)
{
  struct config *cfg = (struct config *) c;

  char b[MAX_ENV_SIZE];

  SETENV_INT("%d", b, "HOOK_STATUS_NONE", HOOK_STATUS_NONE);
  SETENV_INT("%d", b, "HOOK_STATUS_BAD", HOOK_STATUS_BAD);
  SETENV_INT("%d", b, "HOOK_STATUS_RECONFIGURE", HOOK_STATUS_RECONFIGURE);
  SETENV_INT("%u", b, "BIRD_PID", getpid ());

  if (cfg != NULL)
    {

      SETENV_IPTOSTR("ROUTER_ID", &cfg->router_id);
      SETENV_IPTOSTR("LISTEN_BGP_ADDR", &cfg->listen_bgp_addr);
      SETENV_INT("%hu", b, "LISTEN_BGP_PORT",
		 (unsigned short )cfg->listen_bgp_port);

      SETENV_INT("%u", b, "LOAD_TIME", (unsigned int )cfg->load_time);
      SETENV_INT("%u", b, "GR_WAIT", (unsigned int )cfg->gr_wait);

      /*
       setenv ("ERR_MSG", cfg->err_msg ? cfg->err_msg : "", 1);
       setenv ("ERR_FILE_NAME", cfg->err_file_name ? cfg->err_file_name : "", 1);
      */

      setenv ("SYSLOG_NAME", cfg->syslog_name ? cfg->syslog_name : "", 1);
      setenv ("PATH_CONFIG_NAME", cfg->file_name ? cfg->file_name : "", 1);
    }
}

int
filter_hook_dispatcher (u32 index, void *P, void *RT)
{
  struct proto *p = (struct proto*) P;

  if (p->proto->name[0] == 0x42 && p->proto->name[1] == 0x47) // BGP
    {
      return bgp_hook_filter (index, P, RT);
    }
  else
    {
      return HOOK_STATUS_NONE ;
    }

}
