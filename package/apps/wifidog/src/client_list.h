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

/* $Id: client_list.h 1373 2008-09-30 09:27:40Z wichert $ */
/** @file client_list.h
    @brief Client List functions
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#ifndef _CLIENT_LIST_H_
#define _CLIENT_LIST_H_

/** Counters struct for a client's bandwidth usage (in bytes)
 */// init by client_list_append(), 所有成员都初始化为0 , 客户端上下行流量统计(从防火墙规则中获取)
// 定时60s更新一次 by iptables_fw_counters_update()
typedef struct _t_counters {
    unsigned long long	incoming;	/**< @brief Incoming data total*/
    unsigned long long	outgoing;	/**< @brief Outgoing data total*/ // 客户端的下行流量,定时60s更新一次 by iptables_fw_counters_update()
    unsigned long long	incoming_history;	/**< @brief Incoming data before wifidog restarted*/
    unsigned long long	outgoing_history;	/**< @brief Outgoing data before wifidog restarted*///从原有wifidog进程中继承过来的下行流量 by get_clients_from_parent()
    time_t	last_updated;	/**< @brief Last update of the counters *///如果客户端有网络访问的话,那么更新到当前时间
} t_counters;

/** Client node for the connected client linked list.
 */
typedef struct	_t_client {
  struct	_t_client *next;        /**< @brief Pointer to the next client */
	char	*ip;			/**< @brief Client Ip address */
	char	*mac;			/**< @brief Client Mac address */
	char	*token;			/**< @brief Client token */
	unsigned int fw_connection_state; /**< @brief Connection state in the
						     firewall */ // --set-mark 0x02, fw_connection_state 即 该客户端数据包被防火墙打的标记
	int	fd;			/**< @brief Client HTTP socket (valid only
					     during login before one of the
					     _http_* function is called */
	t_counters	counters;	/**< @brief Counters for input/output of
					     the client. */// init by client_list_append() , 初始化为0
	time_t sessiontimeout; // add by weeds, 2014-05-13
	time_t start_time;
} t_client;

// add by lijg, 2013-06-04
extern unsigned int client_num;

/** @brief Get the first element of the list of connected clients
 */
t_client *client_get_first_client(void);

/** @brief Initializes the client list */
void client_list_init(void);

/** @brief Adds a new client to the connections list */
t_client *client_list_append(const char *ip, const char *mac, const char *token);

t_client *
client_list_append_in(const char *ip, const char *mac, const char *token, unsigned long sessiontimeout);

/** @brief Finds a client by its IP and MAC */
t_client *client_list_find(const char *ip, const char *mac);

/** @brief Finds a client only by its IP */
t_client *client_list_find_by_ip(const char *ip); /* needed by fw_iptables.c, auth.c
					     * and wdctl_thread.c */

/** @brief Finds a client only by its Mac */
t_client *client_list_find_by_mac(const char *mac); /* needed by wdctl_thread.c */

/** @brief Finds a client by its token */
t_client *client_list_find_by_token(const char *token);

/** @brief Deletes a client from the connections list */
void client_list_delete(t_client *client);

#define LOCK_CLIENT_LIST() do { \
	debug(LOG_DEBUG, "Locking client list"); \
	pthread_mutex_lock(&client_list_mutex); \
	debug(LOG_DEBUG, "Client list locked"); \
} while (0)

#define UNLOCK_CLIENT_LIST() do { \
	debug(LOG_DEBUG, "Unlocking client list"); \
	pthread_mutex_unlock(&client_list_mutex); \
	debug(LOG_DEBUG, "Client list unlocked"); \
} while (0)

#endif /* _CLIENT_LIST_H_ */
