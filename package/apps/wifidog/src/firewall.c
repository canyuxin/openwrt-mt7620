/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

/*
 * $Id: firewall.c 1389 2009-02-27 17:39:30Z benoitg $
 */
/** @internal
  @file firewall.c
  @brief Firewall update functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  2006 Benoit Grégoire, Technologies Coeus inc. <bock@step.polymtl.ca>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/unistd.h>

#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/time.h>

#ifdef __linux__
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#endif

#if defined(__NetBSD__)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#endif

#include "httpd.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "firewall.h"
#include "fw_iptables.h"
#include "auth.h"
#include "centralserver.h"
#include "client_list.h"

extern pthread_mutex_t client_list_mutex;

/* from commandline.c */
extern pid_t restart_orig_pid;



/**
 * Allow a client access through the firewall by adding a rule in the firewall to MARK the user's packets with the proper
 * rule by providing his IP and MAC address
 * @param ip IP address to allow
 * @param mac MAC address to allow
 * @param fw_connection_state fw_connection_state Tag
 * @return Return code of the command
 */
int
fw_allow(char *ip, char *mac, int fw_connection_state)
{
    debug(LOG_DEBUG, "Allowing %s %s with fw_connection_state %d", ip, mac, fw_connection_state);

    return iptables_fw_access(FW_ACCESS_ALLOW, ip, mac, fw_connection_state);
}

/**
 * @brief Deny a client access through the firewall by removing the rule in the firewall that was fw_connection_stateging the user's traffic
 * @param ip IP address to deny
 * @param mac MAC address to deny
 * @param fw_connection_state fw_connection_state Tag
 * @return Return code of the command
 */
int
fw_deny(char *ip, char *mac, int fw_connection_state)
{
    debug(LOG_DEBUG, "Denying %s %s with fw_connection_state %d", ip, mac, fw_connection_state);
	remove_ip_bandwith(ip);
    return iptables_fw_access(FW_ACCESS_DENY, ip, mac, fw_connection_state);
}

/* XXX DCY */
/**
 * Get an IP's MAC address from the ARP cache.
 * Go through all the entries in /proc/net/arp until we find the requested
 * IP address and return the MAC address bound to it.
 * @todo Make this function portable (using shell scripts?)
 */
char           *
arp_get(char *req_ip)
{
    FILE           *proc;
	 char ip[16];
	 char mac[18];
	 char * reply = NULL;

    if (!(proc = fopen("/proc/net/arp", "r"))) {
        return NULL;
    }
    //debug(LOG_DEBUG, "call arp_get() begin");

    /* Skip first line */
	 while (!feof(proc) && fgetc(proc) != '\n');

	 /* Find ip, copy mac in reply */
	 reply = NULL;
    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %*s", ip, mac) == 2)) {
		  if (strcmp(ip, req_ip) == 0) {
				reply = safe_strdup(mac);
				break;
		  }
    }

    fclose(proc);
    //debug(LOG_DEBUG, "call arp_get() end %s %p", req_ip, reply);

    return reply;
}
char           *
arp_get_formatB(char *req_ip)
{
    FILE           *proc;
	 char ip[16];
	 char mac[18];
	 char * reply = NULL;

    if (!(proc = fopen("/proc/net/arp", "r"))) {
        return NULL;
    }
    //debug(LOG_DEBUG, "call arp_get() begin");

    /* Skip first line */
	 while (!feof(proc) && fgetc(proc) != '\n');

	 /* Find ip, copy mac in reply */
	 reply = NULL;
    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %*s", ip, mac) == 2)) {
		  if (strcmp(ip, req_ip) == 0) {
				reply = safe_strdup(mac);
				break;
		  }
    }

    fclose(proc);
    //debug(LOG_DEBUG, "call arp_get() end %s %p", req_ip, reply);

    return reply;
}

/** Initialize the firewall rules
 */// 1. called by main(), 初始化防火墙
int
fw_init(void)
{
    int flags, oneopt = 1, zeroopt = 0;
	 int result = 0;
	 t_client * client = NULL;

    debug(LOG_INFO, "Creating ICMP socket");  // 创建一个收发ICMP包的socket
    if ((icmp_fd = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1 ||
            (flags = fcntl(icmp_fd, F_GETFL, 0)) == -1 ||
             fcntl(icmp_fd, F_SETFL, flags | O_NONBLOCK) == -1 ||
             setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &oneopt, sizeof(oneopt)) ||
             setsockopt(icmp_fd, SOL_SOCKET, SO_DONTROUTE, &zeroopt, sizeof(zeroopt)) == -1) {
        debug(LOG_ERR, "Cannot create ICMP raw socket.");
        return 0;
    }

    debug(LOG_INFO, "Initializing Firewall");
    result = iptables_fw_init();

	if (restart_orig_pid) {  // shell exec "wdctl restart" , for restart wifidog
		 debug(LOG_INFO, "Restoring firewall rules for clients inherited from parent");
		 LOCK_CLIENT_LIST();
		 client = client_get_first_client();
		 while (client) {
			 fw_allow(client->ip, client->mac, client->fw_connection_state);
			 client = client->next;
		 }
		 UNLOCK_CLIENT_LIST();
	} else {  // add by lijg, 2013-08-13, Load fw rules from ...
		debug(LOG_INFO, "Load fw rules from /etc/wifidog_client.conf");
		LOCK_CLIENT_LIST();
		load_fwrule_conf();
		UNLOCK_CLIENT_LIST();
	}

	 return result;
}

/** Remove all auth server firewall whitelist rules
 */
void
fw_clear_authservers(void)
{
	debug(LOG_INFO, "Clearing the authservers list");
	iptables_fw_clear_authservers();
}

/** Add the necessary firewall rules to whitelist the authservers
 */
void
fw_set_authservers(void)
{
	debug(LOG_INFO, "Setting the authservers list");
	iptables_fw_set_authservers();
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog.
 * @return Return code of the fw.destroy script
 */
int
fw_destroy(void)
{
    if (icmp_fd != 0) {
        debug(LOG_INFO, "Closing ICMP socket");
        close(icmp_fd);
    }

    debug(LOG_INFO, "Removing Firewall rules");
    return iptables_fw_destroy();
}

// add by lijg, 2013-06-04 , 遍历链表的临时结构体
typedef struct {
	char *ip;
	char *mac;
	char *token;
	unsigned long long incoming;
	unsigned long long outgoing;
	time_t	last_updated;
	//unsigned int fw_connection_state;
} t_clitmp;

/**Probably a misnomer, this function actually refreshes the entire client list's traffic counter, re-authenticates every client with the central server and update's the central servers traffic counters and notifies it if a client has logged-out.
 * @todo Make this function smaller and use sub-fonctions
 */
// called by thread_client_timeout_check(), 定时检查认证通过的客户端 是否存在异常
// modified by lijg, 2013-06-04, 解决链表锁问题
void
fw_sync_with_authserver(void)
{
    t_authresponse  authresponse;
    //char            *token, *ip, *mac;
    t_client        *p1;
    //unsigned long long	    incoming, outgoing;
    s_config *config = config_get_config();


    if (-1 == iptables_fw_counters_update()) { //从防火墙规则中更新客户端上下行流量以及最近更新时间@last_updated
        debug(LOG_ERR, "Could not get counters from firewall!");
        return;
    }

    debug(LOG_DEBUG, "begin fw_sync_with_authserver");

	// add by lijg, 2013-06-04, 判断链表节点数
	if (0 == client_num) {
		debug(LOG_DEBUG, "end fw_sync_with_authserver\n\n");
		return ;
	}

	// add by lijg, 2013-06-04, 解决客户端链表锁BUG问题
	LOCK_CLIENT_LIST();
	unsigned int tmp_cnum = client_num;
	t_clitmp *clitmp = (t_clitmp *)malloc((tmp_cnum+1)*sizeof(t_clitmp));
	int i = 0;
	t_clitmp *_tmp = clitmp;

	for (p1 = client_get_first_client(); p1 != NULL && i < tmp_cnum; p1 = p1->next, i++, _tmp++) {
		_tmp->ip = safe_strdup(p1->ip);
        _tmp->token = safe_strdup(p1->token);
        _tmp->mac = safe_strdup(p1->mac);
	    _tmp->outgoing = p1->counters.outgoing; // 下行总流量
	    _tmp->incoming = p1->counters.incoming; // 上行总流量
	    _tmp->last_updated = p1->counters.last_updated;
	}
    UNLOCK_CLIENT_LIST();
    /////////////////////////////////////////////////////////////////

	// 遍历临时链表数组结构, 切记不要直接使用@client_num, 因为它的值随时可能会被修改
    for (i = 0, _tmp = clitmp; i < tmp_cnum; i ++, _tmp ++) {

        /* Ping the client, if he responds it'll keep activity on the link.
         * However, if the firewall blocks it, it will not help.  The suggested
         * way to deal witht his is to keep the DHCP lease time extremely
         * short:  Shorter than config->checkinterval * config->clienttimeout */
        icmp_ping(_tmp->ip); //目的为了更新防火墙规则的下行流量值

        /* Update the counters on the remote server only if we have an auth server */
        if (config->auth_servers != NULL) { // 向认证服务器上报客户端的上下行流量信息 "GET wifidog/auth/?stage=counters"
            auth_server_request(&authresponse, REQUEST_TYPE_COUNTERS, _tmp->ip, _tmp->mac, _tmp->token, _tmp->incoming,
				_tmp->outgoing);
        }

        //if (!(p1 = client_list_find(ip, mac))) {
        //    debug(LOG_ERR, "Node %s was freed while being re-validated!", ip);
        //} else {
		time_t	current_time = time(NULL);
		debug(LOG_INFO, "Checking client %s for timeout:  Last updated %ld (%ld seconds ago), timeout delay %ld seconds, current time %ld, ",
			_tmp->ip, _tmp->last_updated, current_time-_tmp->last_updated,
			config->checkinterval * config->clienttimeout, current_time);
		if (_tmp->last_updated +
			(config->checkinterval * config->clienttimeout)
			<= current_time) { // 如果该客户端超过300s了仍没有互联网访问 (@last_updated 值在300s内没有更新) 那么视为超时
			/* Timing out user */
			debug(LOG_INFO, "%s - Inactive for more than %ld seconds, removing client and denying in firewall",
				_tmp->ip, config->checkinterval * config->clienttimeout);

			LOCK_CLIENT_LIST();
			p1 = client_list_find(_tmp->ip, _tmp->mac);
			fw_deny(_tmp->ip, _tmp->mac, 0); //删除客户端的防火墙规则
			client_fwrule_clear(_tmp->ip);  // add by lijg, 2013-08-13
			if (p1 != NULL) {
				client_list_delete(p1); //从链表中删除超时的客户端
				p1 = NULL;
			} else {
				debug(LOG_ERR, "client %s had been deleted 1", _tmp->ip);
			}
			UNLOCK_CLIENT_LIST();

			/* Advertise the logout if we have an auth server */
			if (config->auth_servers != NULL) { //向认证服务器发送 退出该客户端http请求消息
				auth_server_request(&authresponse, REQUEST_TYPE_LOGOUT, _tmp->ip, _tmp->mac, _tmp->token, 0, 0);
			}
		} else { // 如果客户端没有超时
			/*
			 * This handles any change in
			 * the status this allows us
			 * to change the status of a
			 * user while he's connected
			 *
			 * Only run if we have an auth server
			 * configured!
			*/// 根据认证服务器返回的应答码 来判断是否该客户端存在异常
			if (config->auth_servers != NULL) {
				switch (authresponse.authcode) {
					case AUTH_DENIED:
						debug(LOG_NOTICE, "%s - Denied. Removing client and firewall rules", _tmp->ip);
						LOCK_CLIENT_LIST();
						fw_deny(_tmp->ip, _tmp->mac, 0);
						client_fwrule_clear(_tmp->ip);  // add by lijg, 2013-08-13
						p1 = client_list_find(_tmp->ip, _tmp->mac);
						if (p1 != NULL) {
							client_list_delete(p1);
							p1 = NULL;
						} else {
							debug(LOG_ERR, "client %s had been deleted 2", _tmp->ip);
						}
						UNLOCK_CLIENT_LIST();
						break;

					case AUTH_VALIDATION_FAILED:
						debug(LOG_NOTICE, "%s - Validation timeout, now denied. Removing client and firewall rules", _tmp->ip);
						LOCK_CLIENT_LIST();
						fw_deny(_tmp->ip, _tmp->mac, 0);
						client_fwrule_clear(_tmp->ip);  // add by lijg, 2013-08-13
						p1 = client_list_find(_tmp->ip, _tmp->mac);
						if (p1 != NULL) {
							client_list_delete(p1);
							p1 = NULL;
						} else {
							debug(LOG_ERR, "client %s had been deleted 3", _tmp->ip);
						}
						UNLOCK_CLIENT_LIST();
						break;

					case AUTH_ALLOWED:
						LOCK_CLIENT_LIST();
						p1 = client_list_find(_tmp->ip, _tmp->mac);

						if (p1 && p1->fw_connection_state != FW_MARK_KNOWN) {
							debug(LOG_INFO, "%s - Access has changed to allowed, refreshing firewall and clearing counters", p1->ip);


							if (p1->fw_connection_state != FW_MARK_PROBATION) {
								p1->counters.incoming = p1->counters.outgoing = 0;
							}
							else {
								//We don't want to clear counters if the user was in validation, it probably already transmitted data..
								debug(LOG_INFO, "%s - Skipped clearing counters after all, the user was previously in validation", p1->ip);
							}
							p1->fw_connection_state = FW_MARK_KNOWN;
							fw_allow(p1->ip, p1->mac, p1->fw_connection_state);
							client_fwrule_save(p1->ip, p1->mac, p1->token);  // add by lijg, 2013-08-13
						}
						UNLOCK_CLIENT_LIST();
						break;

					case AUTH_VALIDATION:
						/*
						 * Do nothing, user
						 * is in validation
						 * period
						*/
						debug(LOG_INFO, "%s - User in validation period", _tmp->ip);
						break;

					case AUTH_ERROR:
						debug(LOG_WARNING, "Error communicating with auth server - leaving %s as-is for now", _tmp->ip);
						break;

					default:
						debug(LOG_ERR, "I do not know about authentication code %d", authresponse.authcode);
						break;
				}
			}
		}

		// 释放每个节点的空间
		free(_tmp->ip);
		free(_tmp->token);
		free(_tmp->mac);
    }

	free(clitmp);
    debug(LOG_DEBUG, "end fw_sync_with_authserver\n\n");
}

void
icmp_ping(char *host)
{
	struct sockaddr_in saddr;
#if defined(__linux__) || defined(__NetBSD__)
	struct {
		struct ip ip;
		struct icmp icmp;
	} packet;
#endif
	unsigned int i, j;
	int opt = 2000;
	unsigned short id = rand16();

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	inet_aton(host, &saddr.sin_addr);
#if defined(HAVE_SOCKADDR_SA_LEN) || defined(__NetBSD__)
	saddr.sin_len = sizeof(struct sockaddr_in);
#endif

#if defined(__linux__) || defined(__NetBSD__)
	memset(&packet.icmp, 0, sizeof(packet.icmp));
	packet.icmp.icmp_type = ICMP_ECHO;
	packet.icmp.icmp_id = id;

	for (j = 0, i = 0; i < sizeof(struct icmp) / 2; i++)
		j += ((unsigned short *)&packet.icmp)[i];

	while (j >> 16)
		j = (j & 0xffff) + (j >> 16);

	packet.icmp.icmp_cksum = (j == 0xffff) ? j : ~j;

	if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
		debug(LOG_ERR, "setsockopt(): %s", strerror(errno));

	if (sendto(icmp_fd, (char *)&packet.icmp, sizeof(struct icmp), 0,
	           (const struct sockaddr *)&saddr, sizeof(saddr)) == -1)
		debug(LOG_ERR, "sendto(): %s", strerror(errno));

	opt = 1;
	if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
		debug(LOG_ERR, "setsockopt(): %s", strerror(errno));
#endif

	return;
}

unsigned short rand16(void) {
  static int been_seeded = 0;

  if (!been_seeded) {
    unsigned int seed = 0;
    struct timeval now;

    /* not a very good seed but what the heck, it needs to be quickly acquired */
    gettimeofday(&now, NULL);
    seed = now.tv_sec ^ now.tv_usec ^ (getpid() << 16);

    srand(seed);
    been_seeded = 1;
    }

    /* Some rand() implementations have less randomness in low bits
     * than in high bits, so we only pay attention to the high ones.
     * But most implementations don't touch the high bit, so we
     * ignore that one.
     **/
      return( (unsigned short) (rand() >> 15) );
}
