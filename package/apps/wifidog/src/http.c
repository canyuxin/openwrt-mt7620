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

/* $Id: http.c 1464 2012-08-28 19:59:39Z benoitg $ */
/** @file http.c
  @brief HTTP IO functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire
  @author Copyright (C) 2007 David Bird <david@coova.com>

 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "httpd.h"

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "auth.h"
#include "firewall.h"
#include "http.h"
#include "httpd.h"
#include "client_list.h"
#include "common.h"
#include "centralserver.h"

#include "util.h"

#include "../config.h"

extern pthread_mutex_t	client_list_mutex;

/** The 404 handler is also responsible for redirecting to the auth server */
//  called by httpdProcessRequest() 当有http客户端请求被防火墙重定向到本地wifidog的http服务2060端口后,会回调该函数
// @webserver->handle404->function = http_callback_404
void
http_callback_404(httpd *webserver, request *r)
{
	char tmp_url[MAX_BUF],
			*url,
			*mac;
	s_config	*config = config_get_config();
	t_auth_serv	*auth_server = get_auth_server();
	
	//debug(LOG_DEBUG, "call http_callback_404() test");

	memset(tmp_url, 0, sizeof(tmp_url));
	/*
	 * XXX Note the code below assumes that the client's request is a plain
	 * http request to a standard port. At any rate, this handler is called only
	 * if the internet/auth server is down so it's not a huge loss, but still.
	 */
        snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
                        r->request.host,
                        r->request.path,
                        r->request.query[0] ? "?" : "",
                        r->request.query);
	url = httpdUrlEncode(tmp_url);  // 浏览器实际访问的web站点如 http://www.baidu.com

	if (!is_online()) { // 网关不能访问互联网了
		/* The internet connection is down at the moment  - apologize and do not redirect anywhere */
		char * buf;
		safe_asprintf(&buf,
			"<p>We apologize, but it seems that the internet connection that powers this hotspot is temporarily unavailable.</p>"
			"<p>If at all possible, please notify the owners of this hotspot that the internet connection is out of service.</p>"
			"<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>"
			"<p>In a while please <a href='%s'>click here</a> to try your request again.</p>", tmp_url);

                send_http_page(r, "Uh oh! Internet access unavailable!", buf);
		free(buf);
		debug(LOG_INFO, "Sent %s an apology since I am not online - no point sending them to auth server", r->clientAddr);
	}
	else if (!is_auth_online()) { // 网关不能访问认证服务器了
		/* The auth server is down at the moment - apologize and do not redirect anywhere */
		char * buf;
		safe_asprintf(&buf,
			"<p>We apologize, but it seems that we are currently unable to re-direct you to the login screen.</p>"
			"<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>"
			"<p>In a couple of minutes please <a href='%s'>click here</a> to try your request again.</p>", tmp_url);

                send_http_page(r, "Uh oh! Login screen unavailable!", buf);
		free(buf);
		debug(LOG_INFO, "Sent %s an apology since auth server not online - no point sending them to auth server", r->clientAddr);
	}
	else {  // 网关的网络处于正常情况
		/* Re-direct them to auth server */
		char *urlFragment;

		if (!(mac = arp_get(r->clientAddr))) {
			/* We could not get their MAC address */
			debug(LOG_INFO, "Failed to retrieve MAC address for ip %s, so not putting in the login request", r->clientAddr);
			safe_asprintf(&urlFragment, "%sgw_address=%s&gw_port=%d&gw_id=%s&url=%s",
				auth_server->authserv_login_script_path_fragment,
				config->gw_address,
				config->gw_port,
				config->gw_id,
				url);
		} else {
			debug(LOG_INFO, "Got client MAC address for ip %s: %s", r->clientAddr, mac);
			safe_asprintf(&urlFragment, "%sgw_address=%s&gw_port=%d&gw_id=%s&mac=%s&url=%s",
				auth_server->authserv_login_script_path_fragment,
				config->gw_address,
				config->gw_port,
				config->gw_id,
				mac,
				url);

			free(mac);  // add by lijg, 2013-08-19, this is bug for memory leak
		}

		//debug(LOG_INFO, "Captured %s requesting [%s] and re-directing them to login page", r->clientAddr, url);
		http_send_redirect_to_auth(r, urlFragment, "Redirect to login page");  // 回复客户端浏览器http应答
		free(urlFragment);
	}
	free(url);
}

void
http_callback_wifidog(httpd *webserver, request *r)
{
	send_http_page(r, "WiFiDog", "Please use the menu to navigate the features of this WiFiDog installation.");
}

void
http_callback_about(httpd *webserver, request *r)
{
	send_http_page(r, "About WiFiDog", "This is WiFiDog version <strong>" VERSION "</strong>");
}

// called by http://ipaddr:2060/wifidog/status, 浏览器访问wifidog的http服务器的 status页面会回调该函数
void
http_callback_status(httpd *webserver, request *r)
{
	const s_config *config = config_get_config();
	char * status = NULL;
	char *buf;

	if (config->httpdusername &&
			(strcmp(config->httpdusername, r->request.authUser) ||
			 strcmp(config->httpdpassword, r->request.authPassword))) {
		debug(LOG_INFO, "Status page requested, forcing authentication");
		httpdForceAuthenticate(r, config->httpdrealm);
		return;
	}

	status = get_status_text();  // 返回认证通过的用户信息
	safe_asprintf(&buf, "<pre>%s</pre>", status);
	send_http_page(r, "WiFiDog Status", buf);
	free(buf);
	free(status);
}
/** @brief Convenience function to redirect the web browser to the auth server
 * @param r The request
 * @param urlFragment The end of the auth server URL to redirect to (the part after path)
 * @param text The text to include in the redirect header ant the mnual redirect title */
void http_send_redirect_to_auth(request *r, char *urlFragment, char *text)
{
	char *protocol = NULL;
	int port = 80;
	t_auth_serv	*auth_server = get_auth_server();

	if (auth_server->authserv_use_ssl) {
		protocol = "https";
		port = auth_server->authserv_ssl_port;
	} else {
		protocol = "http";
		port = auth_server->authserv_http_port;
	}

	char *url = NULL;
	safe_asprintf(&url, "%s://%s:%d%s%s",
		protocol,
		auth_server->authserv_hostname,
		port,
		auth_server->authserv_path,
		urlFragment
	);
	http_send_redirect(r, url, text);
	free(url);
}

/** @brief Sends a redirect to the web browser
 * @param r The request
 * @param url The url to redirect to
 * @param text The text to include in the redirect header and the manual redirect link title.  NULL is acceptable */
void http_send_redirect(request *r, char *url, char *text)
{
		char *message = NULL;
		char *header = NULL;
		char *response = NULL;
							/* Re-direct them to auth server */
		//debug(LOG_DEBUG, "Redirecting client browser to %s", url);
		safe_asprintf(&header, "Location: %s",
			url
		);
		if(text) {
			// modified by lijg, 2013-05-18, 重定向码修改为 307改为302
			safe_asprintf(&response, "302 %s\r\n",
				text
			);
		}
		else {
			safe_asprintf(&response, "302 %s\r\n",
				"Redirecting"
			);
		}
		httpdSetResponse(r, response);
		httpdAddHeader(r, header);
		free(response);
		free(header);
		safe_asprintf(&message, "Please <a href='%s'>click here</a>.", url);
		send_http_page(r, text ? text : "Redirection to message", message);
		free(message);
}

void client_fwrule_clear(const char *ip);  //add by lijg, 2013-08-13 
// 当客户端浏览器被要求重定向访问  http://wifidog ipaddr:2060/wifidog/auth?token=...
// modified by lijg, 2013-06-04, 解决链表锁问题
void
http_callback_auth(httpd *webserver, request *r)
{
	t_client	*client;
	httpVar * token;
	char	*mac;
	httpVar *logout = httpdGetVariableByName(r, "logout"); //是否携带logout参数
	debug(LOG_DEBUG, "begin recv client's token authen request");

	// add by lijg, 2013-06-04, 模拟多个用户登录的测试代码
	/**
	httpVar *hmac, *hip;
	hmac = httpdGetVariableByName(r, "mac");
	hip = httpdGetVariableByName(r, "ip");
	token = httpdGetVariableByName(r, "token");
	if (hmac && hip && token && 0 != strcmp(hip->value, "")) {
		if (client_num >= 256) {
			debug(LOG_ERR, "Failed to reach max num of client %u for test", client_num);
			send_http_page(r, "WiFiDog Error", "Failed to reach max num of client, for test");
			return;
		}
		LOCK_CLIENT_LIST();
		if ((client = client_list_find(hip->value, hmac->value)) == NULL) {
			debug(LOG_DEBUG, "testing add client for %s %s (%s)", hip->value, hmac->value, token->value);
			client_list_append(hip->value, hmac->value, token->value);
		} else {
			if (client->token)
				free(client->token);
			client->token = safe_strdup(token->value);
		}
		UNLOCK_CLIENT_LIST();

		authenticate_client_rtest(r, hip->value); //向认证服务器发起token认证请求

		return ;
	}
	*/
	///////////////////////////////////////////////////////////////////////////////////////////

	if (client_num >= 256) {
		debug(LOG_ERR, "Failed to reach max num of client %u", client_num);
		send_http_page(r, "WiFiDog Error", "Failed to reach max num of client");
		return;
	}

	if ((token = httpdGetVariableByName(r, "token"))) {  // 携带认证服务器返回的token值
		/* They supplied variable "token" */
		if (!(mac = arp_get(r->clientAddr))) { //如果没有找到客户端的MAC地址
			/* We could not get their MAC address */
			debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
			send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
		} else { // 找到客户端的MAC地址  run this ...
			/* We have their MAC address */

			LOCK_CLIENT_LIST();

			//if ((client = client_list_find(r->clientAddr, mac)) == NULL) { // 客户端不存在,说明是客户端第一次登录认证请求
			if ((client = client_list_find_by_ip(r->clientAddr)) == NULL) {  // modified by lijg, 2013-06-20
				debug(LOG_DEBUG, "New client for %s", r->clientAddr);
				client_list_append(r->clientAddr, mac, token->value);  // 将客户端添加到 客户端链表@firstclient中
			} else if (logout) { // 如果客户端已经存在,是客户端发来的logout 退出 http请求
			    t_authresponse  authresponse;
			    s_config *config = config_get_config();
			    unsigned long long incoming = client->counters.incoming;
			    unsigned long long outgoing = client->counters.outgoing;
			    char *ip = safe_strdup(client->ip);
			    char *urlFragment = NULL;
			    t_auth_serv	*auth_server = get_auth_server();

			    fw_deny(client->ip, client->mac, client->fw_connection_state); //删除防火墙规则
			    client_fwrule_clear(client->ip);  // add by lijg, 2013-08-13
			    client_list_delete(client); // 从客户端列表中删除
			    debug(LOG_DEBUG, "Got logout from %s", client->ip);

			    /* Advertise the logout if we have an auth server */
			    if (config->auth_servers != NULL) {
					UNLOCK_CLIENT_LIST();
					auth_server_request(&authresponse, REQUEST_TYPE_LOGOUT, ip, mac, token->value,
									    incoming, outgoing); // 向认证服务器上报该客户端的最后一点流量
					LOCK_CLIENT_LIST();

					/* Re-direct them to auth server */
					debug(LOG_INFO, "Got manual logout from client ip %s, mac %s, token %s"
					"- redirecting them to logout message", ip, mac, token->value);
					safe_asprintf(&urlFragment, "%smessage=%s",
						auth_server->authserv_msg_script_path_fragment,
						GATEWAY_MESSAGE_ACCOUNT_LOGGED_OUT
					);
					// 向客户端浏览器回复http应答,让其重定向访问证服务器的 "gw_message.php?message=logged-out"
					http_send_redirect_to_auth(r, urlFragment, "Redirect to logout message");
					free(urlFragment);
			    }
			    free(ip);
 			}
 			else {
				debug(LOG_DEBUG, "Client for %s is already in the client list", client->ip);

				// add by lijg, 2013-05-07 0001, 更新token值
				if (client->token)
					free(client->token);
				client->token = safe_strdup(token->value);

				// add by lijg, 2013-06-20, must update mac
				if (client->mac)
					free(client->mac);
				client->mac = safe_strdup(mac);

				// add by lijg, 2013-07-10
				client->counters.incoming = 0;
				client->counters.outgoing = 0;
				client->counters.incoming_history = 0;
				client->counters.outgoing_history = 0;
			}

			UNLOCK_CLIENT_LIST();

			if (!logout) {
				authenticate_client(r); //向认证服务器发起token认证请求
			}
			free(mac);
		}
	} else {
		/* They did not supply variable "token" */
		send_http_page(r, "WiFiDog error", "Invalid token");
	}

	debug(LOG_DEBUG, "end recv client's token authen request\n\n");
}
void 
http_callback_splash(httpd *webserver, request *r)
{
	t_client	*client;
	httpVar * token;
	char	*mac;
	s_config *config;
	t_auth_serv	*auth_server;
	httpVar *hmac = httpdGetVariableByName(r, "mac"); //是否携带logout参数
	debug(LOG_DEBUG, "begin recv client's login request");

	///////////////////////////////////////////////////////////////////////////////////////////

	if (!(mac = arp_get(r->clientAddr))) { //如果没有找到客户端的MAC地址
		/* We could not get their MAC address */
		debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
		send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
	} else { // 找到客户端的MAC地址  run this ...
		/* We have their MAC address */

		LOCK_CLIENT_LIST();

		//if ((client = client_list_find(r->clientAddr, mac)) == NULL) { // 客户端不存在,说明是客户端第一次登录认证请求
		if ((client = client_list_find_by_ip(r->clientAddr)) == NULL) {  // modified by lijg, 2013-06-20
			debug(LOG_DEBUG, "New client for %s", r->clientAddr);
			client_list_append(r->clientAddr, mac, YSWiFi_TOKEN);  // 将客户端添加到 客户端链表@firstclient中
		}
		else {
			debug(LOG_DEBUG, "Client for %s is already in the client list", client->ip);

			// add by lijg, 2013-05-07 0001, 更新token值
			if (client->token)
				free(client->token);
			client->token = safe_strdup(YSWiFi_TOKEN);

			// add by lijg, 2013-06-20, must update mac
			if (client->mac)
				free(client->mac);
			client->mac = safe_strdup(mac);

			// add by lijg, 2013-07-10
			client->counters.incoming = 0;
			client->counters.outgoing = 0;
			client->counters.incoming_history = 0;
			client->counters.outgoing_history = 0;
		}
		config = config_get_config();
		auth_server = get_auth_server();

		if (NULL == client)
		{
			printf("NULL client\n");
		}
		printf ("mac=%s, ip=%s, token=%s\n", client->ip, client->mac, YSWiFi_TOKEN);
		fw_allow(client->ip, client->mac, FW_MARK_KNOWN);
		client_fwrule_save(client->ip, client->mac, YSWiFi_TOKEN);
		
		UNLOCK_CLIENT_LIST();
		if (NULL != mac)
		{
			free(mac);
		}
	}

	debug(LOG_DEBUG, "end recv client's token authen request\n\n");
}
void send_http_page(request *r, const char *title, const char* message)
{
    s_config	*config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;

    fd=open(config->htmlmsgfile, O_RDONLY);
    if (fd==-1) {
        debug(LOG_CRIT, "Failed to open HTML message file %s: %s", config->htmlmsgfile, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info)==-1) {
        debug(LOG_CRIT, "Failed to stat HTML message file: %s", strerror(errno));
        close(fd);
        return;
    }

    buffer=(char*)safe_malloc(stat_info.st_size+1);
    written=read(fd, buffer, stat_info.st_size);
    if (written==-1) {
        debug(LOG_CRIT, "Failed to read HTML message file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);

    buffer[written]=0;
    httpdAddVariable(r, "title", title);
    httpdAddVariable(r, "message", message);
    httpdAddVariable(r, "nodeID", config->gw_id);
    httpdOutput(r, buffer);
    free(buffer);
}

