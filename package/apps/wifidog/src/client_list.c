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
 * $Id: client_list.c 1373 2008-09-30 09:27:40Z wichert $
 */
/** @file client_list.c
  @brief Client List Functions
  @author Copyright (C) 2004 Alexandre Carmel-Veillex <acv@acv.ca>
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

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "client_list.h"

/** Global mutex to protect access to the client list */
pthread_mutex_t client_list_mutex = PTHREAD_MUTEX_INITIALIZER;

/** @internal
 * Holds a pointer to the first element of the list
 */ //连接的客户端链表头指针
t_client         *firstclient = NULL;

// add by lijg, 2013-06-04, 记录客户端链表的数量
unsigned int client_num = 0;

/** Get the first element of the list of connected clients
 */
t_client *
client_get_first_client(void)
{
    return firstclient;
}

/**
 * Initializes the list of connected clients (client)
 */
void
client_list_init(void)
{
    firstclient = NULL;

    // add by lijg, 2013-06-04, clear it
    client_num = 0;
}

/** Based on the parameters it receives, this function creates a new entry
 * in the connections list. All the memory allocation is done here.
 * @param ip IP address
 * @param mac MAC address
 * @param token Token
 * @return Pointer to the client we just created
 */

t_client * client_list_append(const char *ip, const char *mac, const char *token)
{
	client_list_append_in(ip, mac, token, -1);
}
t_client         *
client_list_append_in(const char *ip, const char *mac, const char *token, unsigned long sessiontimeout)
{
    t_client         *curclient, *prevclient;

    prevclient = NULL;
    curclient = firstclient;

    while (curclient != NULL) { // 将 @prevclient指向链表尾节点
        prevclient = curclient;
        curclient = curclient->next;
    }

    curclient = safe_malloc(sizeof(t_client)); //新增链表结构
    memset(curclient, 0, sizeof(t_client));

    curclient->ip = safe_strdup(ip);
    curclient->mac = safe_strdup(mac);
    curclient->token = safe_strdup(token);
    curclient->counters.incoming = curclient->counters.incoming_history = curclient->counters.outgoing = curclient->counters.outgoing_history = 0;
    curclient->counters.last_updated = time(NULL);
    // add by weeds, 2014-05-13
    if (sessiontimeout >= 0)
    {
		curclient->sessiontimeout = sessiontimeout;
		curclient->start_time = time(NULL);
	}
	else
	{
		curclient->sessiontimeout = 0;
		curclient->start_time = 0;
	}

    if (prevclient == NULL) { // 第一个节点(之前链表为空)
        firstclient = curclient;
    } else {
        prevclient->next = curclient; // 将新节点增加到链表尾
    }

    debug(LOG_INFO, "Added a new client to linked list: IP: %s Token: %s",
          ip, token);

	// add by lijg, 2013-06-04, 增加链表节点数
	client_num ++;

    return curclient;
}

/** Finds a  client by its IP and MAC, returns NULL if the client could not
 * be found
 * @param ip IP we are looking for in the linked list
 * @param mac MAC we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client         *
client_list_find(const char *ip, const char *mac)
{
    t_client         *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->ip, ip) && 0 == strcmp(ptr->mac, mac))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/**
 * Finds a  client by its IP, returns NULL if the client could not
 * be found
 * @param ip IP we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client         *
client_list_find_by_ip(const char *ip)
{
    t_client         *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->ip, ip))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/**
 * Finds a  client by its Mac, returns NULL if the client could not
 * be found
 * @param mac Mac we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client         *
client_list_find_by_mac(const char *mac)
{
    t_client         *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
		printf("%s(%d): mac=%s\n", __FUNCTION__, __LINE__, ptr->mac);
        if (0 == strcasecmp(ptr->mac, mac)) // mac format: aa:bb:cc:dd:ee [smaller case]
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/** Finds a client by its token
 * @param token Token we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client *
client_list_find_by_token(const char *token)
{
    t_client         *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->token, token))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/** @internal
 * @brief Frees the memory used by a t_client structure
 * This function frees the memory used by the t_client structure in the
 * proper order.
 * @param client Points to the client to be freed
 */
void
_client_list_free_node(t_client * client)
{

    if (client->mac != NULL)
        free(client->mac);

    if (client->ip != NULL)
        free(client->ip);

    if (client->token != NULL)
        free(client->token);

    free(client);

    // add by lijg, 2013-06-04, 增加链表节点数
    if (client_num > 0)
		client_num --;
	else
		fprintf(stderr, "[error]client num is invalid %d\n", client_num);
}

/**
 * @brief Deletes a client from the connections list
 *
 * Removes the specified client from the connections list and then calls
 * the function to free the memory used by the client.
 * @param client Points to the client to be deleted
 */
void
client_list_delete(t_client * client)
{
    t_client         *ptr;

    ptr = firstclient;

    if (ptr == NULL) {
        debug(LOG_ERR, "Node list empty!");
    } else if (ptr == client) { // 删除链表头
        firstclient = ptr->next;
        _client_list_free_node(client);
    } else {
        /* Loop forward until we reach our point in the list. */
        while (ptr->next != NULL && ptr->next != client) {
            ptr = ptr->next;
        }
        /* If we reach the end before finding out element, complain. */
        if (ptr->next == NULL) {
            debug(LOG_ERR, "Node to delete could not be found.");
        /* Free element. */
        } else {
            ptr->next = client->next;
            _client_list_free_node(client);
        }
    }
}
