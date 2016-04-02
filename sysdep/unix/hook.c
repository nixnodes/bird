/*
 * hook.c
 *
 *  Created on: Apr 2, 2016
 *      Author: reboot
 */

#include "nest/bird.h"

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
      ] = "HOOK_LOAD" };

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
	  const char *argv[] =
	    { [0] = exec, [1] = NULL };
	  execv (exec, (char**) argv);
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
      log (L_DEBUG "%s: %s: %u executed '%s'", data->protocol,
	   data->hook_string, c_pid, exec);

      int status;

      while (waitpid (c_pid, &status, 0) == (pid_t) -1)
	{
	  if (errno != EINTR)
	    {
	      ERRNO_PRINT(
		  "hook: %s: failed waiting for child process to finish [%s]",
		  data->hook_string)
	      return -1;
	    }
	}

      int r = WEXITSTATUS(status);

      log (L_DEBUG "%s: %s: %u exited with status: %d", data->protocol,
	   data->hook_string, c_pid, r);

      if (r & HOOK_STATUS_RECONFIGURE)
	{
	  log (L_DEBUG "%s: %s: external process requesting reconfigure..",
	       data->protocol, data->hook_string);
	  async_config ();
	}

      return r;
    }
}

struct hook_execv_data
hook_execv_mkdata (unsigned int ac, void *pre, void *data, const char *hs,
		   const char *proto)
{
  struct hook_execv_data t =
    { .flags = ac & HOOK_F_ASYNC ? F_EXECV_FORK : 0, .pre = pre, .data = data,
	.hook_string = hs, .protocol = proto };
  return t;
}

static void
build_hook_envvars (u32 index, void *C)
{
  //struct config *c = (struct config *) C;
  char b[32];
  setenv ("EVENT", GET_HS(index), 1);
  SETENV_INT("%u", b, "EVENT_INDEX", index);
}

int
hook_run (u32 index, execv_callback add, void *add_data)
{
  struct config *c = config;
  struct glob_hook *h = &c->hooks[index];

  if (h->exec != NULL)
    {

      struct hook_execv_data data = hook_execv_mkdata (h->ac,
						       build_hook_envvars,
						       (void*) c, GET_HS(index),
						       "global");

      data.add = add;
      data.add_data = add_data;

      return do_execv (h->exec, index, &data);

    }
  else
    {
      return 0;
    }
}

void
hook_init (void)
{
  char b[MAX_ENV_SIZE];

  SETENV_INT("%d", b, "HOOK_STATUS_BAD", HOOK_STATUS_BAD);
  SETENV_INT("%d", b, "HOOK_STATUS_RECONFIGURE", HOOK_STATUS_RECONFIGURE);
  SETENV_INT("%u", b, "BIRD_PID", getpid ());

  SETENV_IPTOSTR("ROUTER_ID", &config->router_id);
  SETENV_IPTOSTR("LISTEN_BGP_ADDR", &config->listen_bgp_addr);
  SETENV_INT("%hu", b, "LISTEN_BGP_PORT",
	     (unsigned short )config->listen_bgp_port);

  SETENV_INT("%u", b, "LOAD_TIME", (unsigned int )config->load_time);
  SETENV_INT("%u", b, "GR_WAIT", (unsigned int )config->gr_wait);

  setenv ("ERR_MSG", config->err_msg ? config->err_msg : "", 1);
  setenv ("ERR_FILE_NAME", config->err_file_name ? config->err_file_name : "", 1);
  setenv ("SYSLOG_NAME", config->syslog_name ? config->syslog_name : "", 1);
  setenv ("PATH_CONFIG_NAME", config->file_name ? config->file_name : "", 1);

  //log (L_DEBUG "hook_init: complete: %u", config->load_time);
}
