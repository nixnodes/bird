/*
 *     BIRD -- BGP event hooks
 */

#ifndef PROTO_BGP_HOOK_H_
#define PROTO_BGP_HOOK_H_

int
bgp_parse_hooks (void *p);

#include "sysdep/unix/hook.h"

int
bgp_hook_run (unsigned int flags, void *pp, execv_callback add, void *add_data);
int
bgp_check_hooks (void *pp);

#include "sysdep/unix/hook.h"

typedef struct glob_hook bgp_hook;
typedef struct glob_hook_config bgp_hook_config;

#define BGP_HOOK_ENTER_ESTABLISHED 	0x01
#define BGP_HOOK_LEAVE_ESTABLISHED 	0x02
#define BGP_HOOK_ENTER_CLOSE		0x03
#define BGP_HOOK_ENTER_IDLE		0x04
#define BGP_HOOK_ENTER_OPENCONFIRM	0x05
#define BGP_HOOK_CHANGE_STATE		0x06
#define BGP_HOOK_REFRESH_BEGIN		0x07
#define BGP_HOOK_REFRESH_END		0x08
#define BGP_HOOK_INIT			0x09
#define BGP_HOOK_START			0x0A
#define BGP_HOOK_DOWN			0x0B
#define BGP_HOOK_CONN_OUTBOUND		0x0C
#define BGP_HOOK_SHUTDOWN		0x0D
#define BGP_HOOK_NEIGH_GRESTART 	0x0E
#define BGP_HOOK_CONN_INBOUND		0x0F
#define BGP_HOOK_FEED_BEGIN		0x10
#define BGP_HOOK_FEED_END		0x11
#define BGP_HOOK_NEIGH_START		0x12
#define BGP_HOOK_CONN_TIMEOUT		0x13
#define BGP_HOOK_KEEPALIVE		0x14
#define BGP_HOOK_RECONFIGURE		0x15
#define BGP_HOOK_WITHDRAW		0x16
#define BGP_HOOK_UPDATE			0x17
//#define BGP_HOOK_IMPORT			0x18
//#define BGP_HOOK_EXPORT			0x19


void
bgp_handle_invalid_in_conn (u32 index, void *data);


#endif /* PROTO_BGP_HOOK_H_ */
