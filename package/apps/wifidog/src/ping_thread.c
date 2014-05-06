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

/* $Id: ping_thread.c 1373 2008-09-30 09:27:40Z wichert $ */
/** @file ping_thread.c
    @brief Periodically checks in with the central auth server so the auth
    server knows the gateway is still up.  Note that this is NOT how the gateway
    detects that the central server is still up.
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "../config.h"
#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "ping_thread.h"
#include "util.h"
#include "centralserver.h"

// add by lijg , 2013-08-20 
#include "conf.h"
#include "fw_iptables.h"
extern pthread_mutex_t	config_mutex;

static void ping(void);

extern time_t started_time;

// add by lijg, 2013-12-02, Report IP and gwid for bar to mood server

static int connect_tcp(const char *ip, unsigned short port)
{
	struct sockaddr_in peer_addr;
	int fd = -1;
	memset(&peer_addr, 0, sizeof(struct sockaddr_in));
	peer_addr.sin_family      = AF_INET;
	peer_addr.sin_addr.s_addr = inet_addr(ip);
	peer_addr.sin_port        = htons(port);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (-1 == fd) {
		debug(LOG_ERR, "mapp proxy create socket error,%s.\n", strerror(errno));
		return -1;
	}


	int ret = connect(fd, (struct sockaddr *) &peer_addr, sizeof(struct sockaddr_in));
	if (ret != 0) {
		debug(LOG_ERR, "mapp proxy connect error %s", strerror(errno));
		close(fd);
		return -1;
	}
	debug(LOG_DEBUG, "connect %s %u succ", ip, port);
	return fd;
}	

static int  _mapp_read(int sock, char *buf, int len, int secs)
{
	int		nfds;
	fd_set		readfds;
	struct timeval	timeout;

	FD_ZERO(&readfds);
	FD_SET(sock, &readfds);
	timeout.tv_sec = secs;  
	timeout.tv_usec = 0;
	nfds = sock + 1;

	nfds = select(nfds, &readfds, NULL, NULL, &timeout);

	if (nfds > 0) {
		return(read(sock, buf, len));
	}
	debug(LOG_ERR, "_mapp_read error %s %d", strerror(errno), nfds);
	return(-1);  // SIGINT for sys
}

static void mood_update(void)
{
	int ofd = connect_tcp("58.67.160.246", 9000);
	if (ofd < 0) {
		debug(LOG_ERR, "connect report svr %s %u failed", "58.67.160.246", 9000);
		return;
	} 

	s_config	*config = config_get_config();
	char *buff = NULL;
	safe_asprintf(&buff, "GET /my-gwid?gwid=%s HTTP/1.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 
		config->gw_id);
	write(ofd, buff, strlen(buff));
	debug(LOG_DEBUG, "send mood svr [%s]", buff);
	free(buff);
	
	// read data
	char rbuff[128];
	int rlen = _mapp_read(ofd, rbuff, sizeof(rbuff)-1, 3);
	if (rlen > 0) {
		rbuff[rlen] = 0;
		debug(LOG_DEBUG, "recv mood app 2 [%s]", rbuff);
	}
	close(ofd);
}
//////////////////////////////////////////////////////////////////////////////////////

// add by lijg, 2013-12-31, ����URL�����, ÿ��������һ��
void clean_acl_list_timeout(void);

/** Launches a thread that periodically checks in with the wifidog auth server to perform heartbeat function.
@param arg NULL
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
// called by main_loop(), wifidog定时向认证服务器上报心跳的线程入口函数
void
thread_ping(void *arg)
{
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;

	while (1) {
		/* Make sure we check the servers at the very begining */
		// 间隔60s向认证服务器上报一次心跳
		debug(LOG_DEBUG, "Running ping()");
		ping(); // 向认证服务器上报http请求心跳

		//mood_update();  // add by lijg, 2013-12-02 ... 

		clean_acl_list_timeout();  // add by lijg, 2013-12-31
		/* Sleep for config.checkinterval seconds... */
		// modified by lijg, 2013-07-17 , 
		timeout.tv_sec = time(NULL) + 60;
		timeout.tv_nsec = 0;

		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);

		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout); //等待60s

		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
	}
}

// add by lijg, 2013-10-12, statistics wan tx, rx bytes
static void stat_wanbytes(unsigned long long *rxbytes, unsigned long long *txbytes)
{
	static unsigned long long last_rxbytes = 0;
	static unsigned long long last_txbytes = 0;
	*rxbytes = 0;
	*txbytes = 0;
	unsigned long long tmp_rxbytes = 0;
	unsigned long long tmp_txbytes = 0;
	FILE *fp;
	fp = fopen("/proc/net/dev", "r");
	if (NULL == fp) return ;
	char dev[16];
	while (!feof(fp)) {
		fscanf(fp, "%s %llu %*s %*s %*s %*s %*s %*s %*s %llu %*s %*s %*s %*s %*s %*s %*s\n", 
			dev, &tmp_rxbytes, &tmp_txbytes);
		if (strncmp(dev, "eth0.2", 6) != 0) continue;
		
		if (0 == last_rxbytes) last_rxbytes = tmp_rxbytes;
		if (0 == last_txbytes) last_txbytes = tmp_txbytes;
		*rxbytes =  (tmp_rxbytes >= last_rxbytes) ? (tmp_rxbytes - last_rxbytes) : tmp_rxbytes;
		*txbytes =  (tmp_txbytes >= last_txbytes) ? (tmp_txbytes - last_txbytes) : tmp_txbytes;
		last_rxbytes = tmp_rxbytes;
		last_txbytes = tmp_txbytes;
		break;
	}
	
	fclose(fp);
}

extern unsigned int client_num;

/** @internal
 * This function does the actual request.
 */
// called by thread_ping(), 间隔60s就向认证服务器上报一次http请求心跳
static void
ping(void)
{
        ssize_t			numbytes;
        size_t	        	totalbytes;
	int			sockfd, nfds, done;
	char			request[MAX_BUF];
	fd_set			readfds;
	struct timeval		timeout;
	FILE * fh;
	unsigned long int sys_uptime  = 0;
	unsigned int      sys_memfree = 0;
	float             sys_load    = 0;
	t_auth_serv	*auth_server = NULL;
	auth_server = get_auth_server(); //获取认证服务器配置信息

	debug(LOG_DEBUG, "Entering ping()");
		
	/*
	 * The ping thread does not really try to see if the auth server is actually
	 * working. Merely that there is a web server listening at the port. And that
	 * is done by connect_auth_server() internally.
	 */
	sockfd = connect_auth_server(); // 连接认证服务器
	if (sockfd == -1) {
		/*
		 * No auth servers for me to talk to
		 */
		return;
	}

	/*
	 * Populate uptime, memfree and load
	 */
	if ((fh = fopen("/proc/uptime", "r"))) {
		fscanf(fh, "%lu", &sys_uptime); // 返回系统启动运行总时间(秒数)
		fclose(fh);
	}
	if ((fh = fopen("/proc/meminfo", "r"))) {
		while (!feof(fh)) {
			if (fscanf(fh, "MemFree: %u", &sys_memfree) == 0) { //返回可用内存大小
				/* Not on this line */
				while (!feof(fh) && fgetc(fh) != '\n');
			}
			else {
				/* Found it */
				break;
			}
		}
		fclose(fh);
	}
	if ((fh = fopen("/proc/loadavg", "r"))) {
		fscanf(fh, "%f", &sys_load); //返回系统负载值
		fclose(fh);
	}

	/*
	 * Prep & send request
	 */
	// @request = "GET wifidog/ping/?gw_id=default ... "
	// modified by lijg, 2013-10-12, add rx tx bytes 
	unsigned long long rxbytes, txbytes;
	stat_wanbytes(&rxbytes, &txbytes);
	snprintf(request, sizeof(request) - 1,
			"GET %s%sgw_id=%s&sys_uptime=%lu&sys_memfree=%u&sys_load=%.2f&rxbytes=%llu&txbytes=%llu&num=%u HTTP/1.0\r\n"
			"User-Agent: WiFiDog %s\r\n"
			"Host: %s\r\n"
			"\r\n",
			auth_server->authserv_path,
			auth_server->authserv_ping_script_path_fragment,
			config_get_config()->gw_id,
			sys_uptime,
			sys_memfree,
			sys_load,
			rxbytes, txbytes, client_num, 
			VERSION,
			auth_server->authserv_hostname);

	debug(LOG_DEBUG, "HTTP Request to Server: [%s]", request);

	send(sockfd, request, strlen(request), 0); // 向认证服务器发送http请求 @request字符串

	debug(LOG_DEBUG, "Reading response");

	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 30; /* XXX magic... 30 second */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout); // 最多等待30s, 等待接收认证服务其的http应答

		if (nfds > 0) {
			/** We don't have to use FD_ISSET() because there
			 *  was only one fd. */
			// 接收认证服务器的http应答消息存储到 @request[]中
			numbytes = read(sockfd, request + totalbytes, MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				debug(LOG_ERR, "An error occurred while reading from auth server: %s", strerror(errno));
				/* FIXME */
				close(sockfd);
				return;
			}
			else if (numbytes == 0) {
				done = 1;
			}
			else {
				totalbytes += numbytes;
				debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
			}
		}
		else if (nfds == 0) {
			debug(LOG_ERR, "Timed out reading data via select() from auth server");
			/* FIXME */
			close(sockfd);
			return;
		}
		else if (nfds < 0) {
			debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
			/* FIXME */
			close(sockfd);
			return;
		}
	} while (!done);
	close(sockfd);

	debug(LOG_DEBUG, "Done reading reply, total %d bytes", totalbytes);

	request[totalbytes] = '\0';

	debug(LOG_DEBUG, "HTTP Response from Server: [%s]", request);

    // 解析认证服务器的应答消息
	if (strstr(request, "Pong") == 0) {
		debug(LOG_WARNING, "Auth server did NOT say pong!");
		/* FIXME */
	}
	else {
		debug(LOG_DEBUG, "Auth Server Says: Pong");
	}

	// add by lijg, 2013-08-20, update auth server's dns cache
	struct in_addr *h_addr;
	char otmp[24];
	h_addr = wd_gethostbyname(auth_server->authserv_hostname);
	LOCK_CONFIG();
	if (h_addr) {
		net_to_str(h_addr->s_addr, otmp, sizeof(otmp));
		if (!auth_server->last_ip) {
			auth_server->last_ip = safe_strdup(otmp);
			if (!iptables_fw_find_mention("filter", TABLE_WIFIDOG_AUTHSERVERS, otmp)) {
				fw_set_authservers(); 
			}			
		} else if (strcmp(auth_server->last_ip, otmp) != 0) {
			free(auth_server->last_ip);
			auth_server->last_ip = safe_strdup(otmp);
			if (!iptables_fw_find_mention("filter", TABLE_WIFIDOG_AUTHSERVERS, otmp)) {
				fw_set_authservers(); 
			}
		}
		free (h_addr);
	}
	UNLOCK_CONFIG();
	
	return;
}
// POST /ysapi/rep_userstatus.php HTTP/1.1
// Content-Length: xxx
//\r\n\r\n
// status={"record": "- aa-bb-cc-dd-ee--ff 10.1.1.3 dnat 729347892375"}&auth_key=xxxx&wan_mac=00:11:22:33:44:55
static int rep_userstatus()
{
	ssize_t 		numbytes;
	size_t				totalbytes;
	int 		sockfd, nfds, done;
	char			request[MAX_BUF];
	char	content[MAX_BUF];
	fd_set			readfds;
	struct timeval		timeout;
	
	t_auth_serv *auth_server = NULL;
	auth_server = get_auth_server(); //获取认证服务器配置信息

	memset(request, 0, sizeof(request));
	memset(content, 0, sizeof(content));

	debug(LOG_DEBUG, "Entering rep_userstatus()");
	
	/*
	 * The ping thread does not really try to see if the auth server is actually
	 * working. Merely that there is a web server listening at the port. And that
	 * is done by connect_auth_server() internally.
	 */
	sockfd = connect_auth_server(); // 连接认证服务器
	if (sockfd == -1) {
		/*
		 * No auth servers for me to talk to
		 */
		 debug(LOG_DEBUG, "-1, cannot connect to auth server\n");
		 goto ERR_EXIT;
	}
	// get all the authenticated MAC address
	// 
	// status={ "record": "- 44-37-E6-D6-D1-45 192.168.1.2 dnat 533e963600000001" }&auth_key=81D55158E7D7B56182F6BFFCBD6A6C34&wan_mac=00:17:A5:70:0C:83
	//                              username mac ip_address dnat/pass xxxx timeout bitrate ????
	//
	snprintf(content, sizeof(content) - 1, "status={ \"record\": \"- AA-BB-CC-DD-EE-FF 10.1.1.4 dnat \
				5366088700000003 0\/0 0\/0 0\/0\nhalo 11-22-33-44-55-66 192.168.1.192 pass 5366085900000002 \
				105\/86400 381707\/0 115903\/0\n- aa-bb-bb-bb-cc-dd 192.168.1.106 dnat 5366066000000001 0\/0 0\/0 0\/0\" }
				&auth_key=81D55158E7D7B56182F6BFFCBD6A6C34&wan_mac=00:17:A5:70:0C:83");
	snprintf(request, sizeof(request) - 1,
			"POST /ysapi/rep_userstatus.php HTTP/1.1\r\n"
			"User-Agent: WiFiDog %s\r\n"
			"Host: www.yswifi.com\r\n"
			"Accept: */*\r\n"
			"Content-Length: %d\r\n"
			"\r\n"
			"%s",
			VERSION,
			mac,
			strlen(content),
			content
			);
	
	debug(LOG_DEBUG, "HTTP Request to Server: [%s]", request);

	send(sockfd, request, strlen(request), 0); // 向认证服务器发送http请求 @request字符串

	debug(LOG_DEBUG, "Reading response");

	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 30; /* XXX magic... 30 second */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout); // 最多等待30s, 等待接收认证服务其的http应答

		if (nfds > 0) {
			/** We don't have to use FD_ISSET() because there
			 *	was only one fd. */
			// 接收认证服务器的http应答消息存储到 @request[]中
			numbytes = read(sockfd, request + totalbytes, MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				debug(LOG_ERR, "An error occurred while reading from auth server: %s", strerror(errno));
				/* FIXME */
				close(sockfd);
				return;
			}
			else if (numbytes == 0) {
				done = 1;
			}
			else {
				totalbytes += numbytes;
				debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
			}
		}
		else if (nfds == 0) {
			debug(LOG_ERR, "Timed out reading data via select() from auth server");
			/* FIXME */
			close(sockfd);
			return;
		}
		else if (nfds < 0) {
			debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
			/* FIXME */
			close(sockfd);
			return;
		}
	} while (!done);
	close(sockfd);

	debug(LOG_DEBUG, "Done reading reply, total %d bytes", totalbytes);

	request[totalbytes] = '\0';

	debug(LOG_DEBUG, "HTTP Response from Server: [%s]", request);

	//upgradestatus=0
	if (strstr(request, "upgradestatus=0") != NULL) {
		debug(LOG_WARNING, "Do not need do upgrade progress!\n");
	}
	else if (strstr(request,"firmwaredlurl=")!=NULL && strstr(request,"firmwaremd5=")!=NULL){
		//firmwaredlurl=http://xxxx/xxx.bin
		//firmwaremd5=678687asdfasdfasdf		#32 letter must be lower case.
		debug(LOG_DEBUG, "Need do upgrade process\n");
		
	}
#if 0
	// add by lijg, 2013-08-20, update auth server's dns cache
	struct in_addr *h_addr;
	char otmp[24];
	h_addr = wd_gethostbyname(auth_server->authserv_hostname);
	LOCK_CONFIG();
	if (h_addr) {
		net_to_str(h_addr->s_addr, otmp, sizeof(otmp));
		if (!auth_server->last_ip) {
			auth_server->last_ip = safe_strdup(otmp);
			if (!iptables_fw_find_mention("filter", TABLE_WIFIDOG_AUTHSERVERS, otmp)) {
				fw_set_authservers(); 
			}			
		} else if (strcmp(auth_server->last_ip, otmp) != 0) {
			free(auth_server->last_ip);
			auth_server->last_ip = safe_strdup(otmp);
			if (!iptables_fw_find_mention("filter", TABLE_WIFIDOG_AUTHSERVERS, otmp)) {
				fw_set_authservers(); 
			}
		}
		free (h_addr);
	}
	UNLOCK_CONFIG();
#endif

EXIT:
	return 0;
ERR_EXIT:
	return -1;

}

// GET /ysapi/disconn_user.php?authkey=xxxx HTTP/1.1
static int dev_status()
{
	ssize_t 		numbytes;
	size_t				totalbytes;
	int 		sockfd, nfds, done;
	char			request[MAX_BUF];
	fd_set			readfds;
	struct timeval		timeout;
	char mac[32];
	
	t_auth_serv *auth_server = NULL;
	auth_server = get_auth_server(); //获取认证服务器配置信息

	debug(LOG_DEBUG, "Entering dev_status()");
	memset(mac, 0, sizeof mac);
	snprintf(mac, sizeof mac, "dd:dd:dd:dd:dd:dd");
	/*
	 * The ping thread does not really try to see if the auth server is actually
	 * working. Merely that there is a web server listening at the port. And that
	 * is done by connect_auth_server() internally.
	 */
	sockfd = connect_auth_server(); // 连接认证服务器
	if (sockfd == -1) {
		/*
		 * No auth servers for me to talk to
		 */
		return;
	}

	snprintf(request, sizeof(request) - 1,
			"GET /ysapi/dev_status.php?authkey=81D55158E7D7B56182F6BFFCBD6A6C34&hostname=MT7620N&devicename=&firmware=MT7620N"
			"&firmware_revision=0.0.0&online_user_num=0&uptime=0&cpu=25%%&memfree=0&wan_iface=eth2.2&wan_mac=11:11:11:11:11:11"
			"&wan_ip=192.168.1.143&wan_bup=0&wan_bdown=0&wifi_bup=0&wifi_iface=ra1&wifi_iface_hs=ra0&wifi_mac=&wifi_ip=&wifi_ssid_hs=YS"
			"&wifi_ssid=MyWiFi&wifi_encryption=psk2&wifi_key=12345678&wifi_channel_mode=manual&wifi_signal=&wifi_maxassoc=&wan_mac=%s HTTP/1.1\r\n"
			"User-Agent: WiFiDog %s\r\n"
			"Host: www.yswifi.com\r\n"
			"\r\n",
			VERSION,
			mac
			);

	debug(LOG_DEBUG, "HTTP Request to Server: [%s]", request);

	send(sockfd, request, strlen(request), 0); // 向认证服务器发送http请求 @request字符串

	debug(LOG_DEBUG, "Reading response");

	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 30; /* XXX magic... 30 second */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout); // 最多等待30s, 等待接收认证服务其的http应答

		if (nfds > 0) {
			/** We don't have to use FD_ISSET() because there
			 *	was only one fd. */
			// 接收认证服务器的http应答消息存储到 @request[]中
			numbytes = read(sockfd, request + totalbytes, MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				debug(LOG_ERR, "An error occurred while reading from auth server: %s", strerror(errno));
				/* FIXME */
				close(sockfd);
				return;
			}
			else if (numbytes == 0) {
				done = 1;
			}
			else {
				totalbytes += numbytes;
				debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
			}
		}
		else if (nfds == 0) {
			debug(LOG_ERR, "Timed out reading data via select() from auth server");
			/* FIXME */
			close(sockfd);
			return;
		}
		else if (nfds < 0) {
			debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
			/* FIXME */
			close(sockfd);
			return;
		}
	} while (!done);
	close(sockfd);

	debug(LOG_DEBUG, "Done reading reply, total %d bytes", totalbytes);

	request[totalbytes] = '\0';

	debug(LOG_DEBUG, "HTTP Response from Server: [%s]", request);

	//upgradestatus=0
	if (strstr(request, "ssid") != NULL) {
		debug(LOG_WARNING, "found modification content\n");
	}
	else {
		//firmwaredlurl=http://xxxx/xxx.bin
		//firmwaremd5=678687asdfasdfasdf		#32 letter must be lower case.
		debug(LOG_DEBUG, "Do not need do any modifications\n");
	}
#if 0
	// add by lijg, 2013-08-20, update auth server's dns cache
	struct in_addr *h_addr;
	char otmp[24];
	h_addr = wd_gethostbyname(auth_server->authserv_hostname);
	LOCK_CONFIG();
	if (h_addr) {
		net_to_str(h_addr->s_addr, otmp, sizeof(otmp));
		if (!auth_server->last_ip) {
			auth_server->last_ip = safe_strdup(otmp);
			if (!iptables_fw_find_mention("filter", TABLE_WIFIDOG_AUTHSERVERS, otmp)) {
				fw_set_authservers(); 
			}			
		} else if (strcmp(auth_server->last_ip, otmp) != 0) {
			free(auth_server->last_ip);
			auth_server->last_ip = safe_strdup(otmp);
			if (!iptables_fw_find_mention("filter", TABLE_WIFIDOG_AUTHSERVERS, otmp)) {
				fw_set_authservers(); 
			}
		}
		free (h_addr);
	}
	UNLOCK_CONFIG();
#endif

EXIT:
	return 0;
ERR_EXIT:
	return -1;

}
// GET /ysapi/disconn_user.php?authkey=xxxx HTTP/1.1
static int disconnect_user()
{
	ssize_t 		numbytes;
	size_t				totalbytes;
	int 		sockfd, nfds, done;
	char			request[MAX_BUF];
	fd_set			readfds;
	struct timeval		timeout;
	char mac[32];
	
	t_auth_serv *auth_server = NULL;
	auth_server = get_auth_server(); //获取认证服务器配置信息

	debug(LOG_DEBUG, "Entering disconnect_user()");
	memset(mac, 0, sizeof(mac));
	snprintf(mac, sizeof(mac), "ee:ee:ee:ee:ee:ee");
		
	/*
	 * The ping thread does not really try to see if the auth server is actually
	 * working. Merely that there is a web server listening at the port. And that
	 * is done by connect_auth_server() internally.
	 */
	sockfd = connect_auth_server(); // 连接认证服务器
	if (sockfd == -1) {
		/*
		 * No auth servers for me to talk to
		 */
		return;
	}

	snprintf(request, sizeof(request) - 1,
			"GET /ysapi/disconn_user.php?authkey=81D55158E7D7B56182F6BFFCBD6A6C34&wan_mac=%s HTTP/1.1\r\n"
			"User-Agent: WiFiDog %s\r\n"
			"Host: www.yswifi.com\r\n"
			"\r\n",
			VERSION,
			mac
			);

	debug(LOG_DEBUG, "HTTP Request to Server: [%s]", request);

	send(sockfd, request, strlen(request), 0); // 向认证服务器发送http请求 @request字符串

	debug(LOG_DEBUG, "Reading response");

	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 30; /* XXX magic... 30 second */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout); // 最多等待30s, 等待接收认证服务其的http应答

		if (nfds > 0) {
			/** We don't have to use FD_ISSET() because there
			 *	was only one fd. */
			// 接收认证服务器的http应答消息存储到 @request[]中
			numbytes = read(sockfd, request + totalbytes, MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				debug(LOG_ERR, "An error occurred while reading from auth server: %s", strerror(errno));
				/* FIXME */
				close(sockfd);
				return;
			}
			else if (numbytes == 0) {
				done = 1;
			}
			else {
				totalbytes += numbytes;
				debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
			}
		}
		else if (nfds == 0) {
			debug(LOG_ERR, "Timed out reading data via select() from auth server");
			/* FIXME */
			close(sockfd);
			return;
		}
		else if (nfds < 0) {
			debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
			/* FIXME */
			close(sockfd);
			return;
		}
	} while (!done);
	close(sockfd);

	debug(LOG_DEBUG, "Done reading reply, total %d bytes", totalbytes);

	request[totalbytes] = '\0';

	debug(LOG_DEBUG, "HTTP Response from Server: [%s]", request);

	// Resolve the mac list, to delete them from the access from Internet.
	
#if 0
	// add by lijg, 2013-08-20, update auth server's dns cache
	struct in_addr *h_addr;
	char otmp[24];
	h_addr = wd_gethostbyname(auth_server->authserv_hostname);
	LOCK_CONFIG();
	if (h_addr) {
		net_to_str(h_addr->s_addr, otmp, sizeof(otmp));
		if (!auth_server->last_ip) {
			auth_server->last_ip = safe_strdup(otmp);
			if (!iptables_fw_find_mention("filter", TABLE_WIFIDOG_AUTHSERVERS, otmp)) {
				fw_set_authservers(); 
			}			
		} else if (strcmp(auth_server->last_ip, otmp) != 0) {
			free(auth_server->last_ip);
			auth_server->last_ip = safe_strdup(otmp);
			if (!iptables_fw_find_mention("filter", TABLE_WIFIDOG_AUTHSERVERS, otmp)) {
				fw_set_authservers(); 
			}
		}
		free (h_addr);
	}
	UNLOCK_CONFIG();
#endif

EXIT:
	return 0;
ERR_EXIT:
	return -1;

}
// GET /ysapi/upgrade.php?authkey=xxxx HTTP/1.1
static int upgrade()
{
	ssize_t			numbytes;
    size_t	        	totalbytes;
	int			sockfd, nfds, done;
	char			request[MAX_BUF];
	fd_set			readfds;
	struct timeval		timeout;
	char mac[32];
	
	t_auth_serv	*auth_server = NULL;
	auth_server = get_auth_server(); //获取认证服务器配置信息

	debug(LOG_DEBUG, "Entering upgrade()");
	memset(mac, 0, sizeof(mac));
	snprintf(mac, sizeof(mac), "ee:ee:ee:ee:ee:ee");
		
	/*
	 * The ping thread does not really try to see if the auth server is actually
	 * working. Merely that there is a web server listening at the port. And that
	 * is done by connect_auth_server() internally.
	 */
	sockfd = connect_auth_server(); // 连接认证服务器
	if (sockfd == -1) {
		/*
		 * No auth servers for me to talk to
		 */
		return;
	}

	snprintf(request, sizeof(request) - 1,
			"GET /ysapi/upgrade.php?authkey=81D55158E7D7B56182F6BFFCBD6A6C34&wan_mac=%s HTTP/1.1\r\n"
			"User-Agent: WiFiDog %s\r\n"
			"Host: www.yswifi.com\r\n"
			"\r\n",
			VERSION,
			mac
			);

	debug(LOG_DEBUG, "HTTP Request to Server: [%s]", request);

	send(sockfd, request, strlen(request), 0); // 向认证服务器发送http请求 @request字符串

	debug(LOG_DEBUG, "Reading response");

	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 30; /* XXX magic... 30 second */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout); // 最多等待30s, 等待接收认证服务其的http应答

		if (nfds > 0) {
			/** We don't have to use FD_ISSET() because there
			 *  was only one fd. */
			// 接收认证服务器的http应答消息存储到 @request[]中
			numbytes = read(sockfd, request + totalbytes, MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				debug(LOG_ERR, "An error occurred while reading from auth server: %s", strerror(errno));
				/* FIXME */
				close(sockfd);
				return;
			}
			else if (numbytes == 0) {
				done = 1;
			}
			else {
				totalbytes += numbytes;
				debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
			}
		}
		else if (nfds == 0) {
			debug(LOG_ERR, "Timed out reading data via select() from auth server");
			/* FIXME */
			close(sockfd);
			return;
		}
		else if (nfds < 0) {
			debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
			/* FIXME */
			close(sockfd);
			return;
		}
	} while (!done);
	close(sockfd);

	debug(LOG_DEBUG, "Done reading reply, total %d bytes", totalbytes);

	request[totalbytes] = '\0';

	debug(LOG_DEBUG, "HTTP Response from Server: [%s]", request);

    //upgradestatus=0
	if (strstr(request, "upgradestatus=0") != NULL) {
		debug(LOG_WARNING, "Do not need do upgrade progress!\n");
	}
	else if (strstr(request,"firmwaredlurl=")!=NULL && strstr(request,"firmwaremd5=")!=NULL){
		//firmwaredlurl=http://xxxx/xxx.bin
		//firmwaremd5=678687asdfasdfasdf		#32 letter must be lower case.
		debug(LOG_DEBUG, "Need do upgrade process\n");
		
	}
#if 0
	// add by lijg, 2013-08-20, update auth server's dns cache
	struct in_addr *h_addr;
	char otmp[24];
	h_addr = wd_gethostbyname(auth_server->authserv_hostname);
	LOCK_CONFIG();
	if (h_addr) {
		net_to_str(h_addr->s_addr, otmp, sizeof(otmp));
		if (!auth_server->last_ip) {
			auth_server->last_ip = safe_strdup(otmp);
			if (!iptables_fw_find_mention("filter", TABLE_WIFIDOG_AUTHSERVERS, otmp)) {
				fw_set_authservers(); 
			}			
		} else if (strcmp(auth_server->last_ip, otmp) != 0) {
			free(auth_server->last_ip);
			auth_server->last_ip = safe_strdup(otmp);
			if (!iptables_fw_find_mention("filter", TABLE_WIFIDOG_AUTHSERVERS, otmp)) {
				fw_set_authservers(); 
			}
		}
		free (h_addr);
	}
	UNLOCK_CONFIG();
#endif

EXIT:
	return 0;
ERR_EXIT:
	return -1;
}
