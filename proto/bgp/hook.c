/*
 *     BIRD -- BGP event hooks
 *
 */

#include "bgp.h"
#include "filter/filter.h"
#include "lib/socket.h"
#include "nest/attrs.h"


#include "hook.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

static const char *hook_strings[MAX_HOOKS] =
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
      [BGP_HOOK_KEEPALIVE] = "BGP_HOOK_KEEPALIVE", [BGP_HOOK_RECONFIGURE
	  ] = "BGP_HOOK_RECONFIGURE", [BGP_HOOK_CONN_TIMEOUT
	  ] = "BGP_HOOK_CONN_TIMEOUT", [BGP_HOOK_UPDATE] = "BGP_HOOK_UPDATE",
      [BGP_HOOK_WITHDRAW] = "BGP_HOOK_WITHDRAW", [BGP_HOOK_IMPORT
	  ] = "BGP_HOOK_IMPORT", [BGP_HOOK_EXPORT] = "BGP_HOOK_EXPORT" };

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
  for (index = 1; index < MAX_HOOKS; index++)
    {
      bgp_hook *h = &p->cf->hc.hooks[index];
      if (h->exec != NULL)
	{
	  bgp_create_hook (index, p);
	}
    }

  return 0;
}

int
bgp_check_hooks (void *C)
{
  struct bgp_config *c = (struct bgp_config *) C;

  int index;
  int t;

  for (index = 1; index < MAX_HOOKS; index++)
    {
      bgp_hook *h = &c->hc.hooks[index];
      if (h->exec == NULL)
	{
	  continue;
	}

      t = access (h->exec, R_OK | X_OK);

      if (t == -1)
	{
	  ERRNO_STRING
	  log (L_WARN "%s: %s: '%s' is not executable: %s", c->c.name,
	       GET_HS(index), h->exec, __b);
	}
    }

  return 0;
}

static void
bgp_build_hook_envvars (u32 index, void *P)
{
  struct bgp_proto *p = (struct bgp_proto *) P;

  char b[MAX_ENV_SIZE];

  setenv ("EVENT", GET_HS(index), 1);
  SETENV_INT("%u", b, "EVENT_INDEX", index);

  SETENV_INT("%hhu", b, "LAST_ERROR_CLASS", p->last_error_class);
  SETENV_INT("%u", b, "LAST_ERROR_CODE", p->last_error_code);
  SETENV_INT("%u", b, "REMOTE_ID", p->remote_id);
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
  SETENV_INT("%hhu", b, "IS_INTERNAL", p->is_internal);
  SETENV_INT("%u", b, "LOCAL_ID", p->local_id);

  SETENV_INT("%hu", b, "REMOTE_PORT", p->cf->remote_port);
  SETENV_INT("%u", b, "REMOTE_AS", p->cf->remote_as);
  SETENV_IPTOSTR("REMOTE_IP", &p->cf->remote_ip);
  SETENV_IPTOSTR("CFG_SOURCE_IP", &p->cf->source_addr);
  SETENV_INT("%d", b, "IGP_METRIC", p->cf->igp_metric);
  SETENV_INT("%d", b, "MED_METRIC", p->cf->med_metric);
  SETENV_INT("%d", b, "GW_MODE", p->cf->gw_mode);
  SETENV_INT("%d", b, "PREFER_OLDER", p->cf->prefer_older);
  SETENV_INT("%d", b, "DETERMINISTIC_MED", p->cf->deterministic_med);
  SETENV_INT("%d", b, "DEFAULT_LOCAL_PREF", p->cf->default_local_pref);
  SETENV_INT("%d", b, "CAPABILITIES", p->cf->capabilities);
  SETENV_INT("%d", b, "ENABLE_REFRESH", p->cf->enable_refresh);
  SETENV_INT("%d", b, "ENABLE_AS4", p->cf->enable_as4);
  SETENV_INT("%u", b, "RR_CLUSTER_ID", p->cf->rr_cluster_id);
  SETENV_INT("%d", b, "ADVERTISE_IPV4", p->cf->advertise_ipv4);
  SETENV_INT("%d", b, "PASSIVE", p->cf->passive);
  SETENV_INT("%d", b, "SECONDARY", p->cf->secondary);
  SETENV_INT("%d", b, "ADD_PATH", p->cf->add_path);

  if (p->cf->c.dsc != NULL)
    {
      setenv ("PROTO_DESC", p->cf->c.dsc, 1);
    }

  setenv ("PROTO_NAME", p->cf->c.name, 1);
  setenv ("TABLE_NAME", p->p.table->name, 1);

  SETENV_IPTOSTR("SOURCE_IP", &p->source_addr);

  if (p->conn != NULL)
    {
      SETENV_INT("%u", b, "CONN_STATE", p->conn->state);
    }
  else
    {
      setenv ("CONN_STATE", "0", 1);
    }
}

int
bgp_hook_run (u32 index, void *P, execv_callback add, void *add_data)
{
  struct bgp_proto *p = (struct bgp_proto *) P;

  if (p == NULL)
    {
      return HOOK_STATUS_NONE ;
    }

  bgp_hook *h = &p->hooks[index];

  if (h->exec != NULL)
    {

      struct hook_execv_data data = hook_execv_mkdata (h->ac,
						       bgp_build_hook_envvars,
						       P, GET_HS(index),
						       p->cf->c.name, add,
						       add_data, NULL);

      return do_execv (h->exec, index, &data);

    }
  else
    {
      return HOOK_STATUS_NONE ;
    }
}

void
bgp_handle_invalid_in_conn (u32 index, void *data)
{
  char b[64];
  sock *sk = data;

  SETENV_IPTOSTR("REMOTE_IP", &sk->daddr);
  SETENV_IPTOSTR("SOURCE_IP", &sk->saddr);
  SETENV_INT("%hu", b, "REMOTE_PORT", (unsigned short )sk->dport);
  SETENV_INT("%hu", b, "SOURCE_PORT", (unsigned short )sk->sport);
}

struct bgp_filter_build_params
{
  struct rte *e;
  struct bgp_proto *p;
};

static void
bgp_build_route_envvars (u32 index, void *RT)
{
  struct bgp_filter_build_params *par = (struct bgp_filter_build_params *) RT;
  struct rte *e = par->e;

  char b[MAX_ENV_SIZE];

  if (e->net)
    {
      SETENV_IPTOSTR("PREFIX", &e->net->n.prefix);
      SETENV_INT("%hhu", b, "PREFIX_LEN", (unsigned char )e->net->n.pxlen);
      SETENV_INT("%hhu", b, "NET_FLAGS", (unsigned char )e->net->n.flags);
    }

  if (e->attrs)
    {
      SETENV_IPTOSTR("BGP_NEXT_HOP", &e->attrs->gw);
      SETENV_IPTOSTR("BGP_FROM", &e->attrs->from);

      byte buf[1000];

      eattr *ad = ea_find (e->attrs->eattrs, EA_CODE(EAP_BGP, BA_AS_PATH));
      if (ad)
	{
	  as_path_format (ad->u.ptr, buf, sizeof(buf));
	  setenv ("BGP_PATH", buf, 1);
	}
    }
}

int
bgp_hook_filter (u32 index, void *P, void *RT)
{
  struct bgp_filter_build_params p =
    { .p = (struct bgp_proto *) P, .e = (struct rte*) RT };

  return bgp_hook_run (index, P, bgp_build_route_envvars, &p);
}

void
bgp_hook_proc_sa (int w, struct f_val *res, struct rta *rta)
{
  struct proto *P = rta->src->proto;
  if (IS_PROTO_BGP (P))
    {
      struct bgp_proto *p = (struct bgp_proto *) P;

      if (w == 1)
	{
	  res->val.i = (uint) p->cf->remote_as;
	}
      else if (w == 2)
	{
	  res->val.i = (uint) p->cf->local_as;
	}
    }
  else
    {
      res->val.i = 0;
    }
}
