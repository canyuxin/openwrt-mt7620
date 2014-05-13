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
#include <sys/stat.h>
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
#include "client_list.h"

// add by lijg , 2013-08-20 
#include "conf.h"
#include "fw_iptables.h"
extern pthread_mutex_t	config_mutex;
extern pthread_mutex_t	client_list_mutex;

static void ping(void);
static int upgrade();
static int disconnect_user();
static int rep_userstatus();
static int dev_status();

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

// add by lijg, 2013-12-31, 
void clean_acl_list_timeout(void);

// add by weeds, 2014-05-13, to add the timeout control.
void clean_timeout_client(void)
{
	t_client *ptr = NULL;;
	time_t curtime = time(NULL);
	ptr = client_get_first_client();
	while (NULL != ptr)
	{
		if (ptr->sessiontimeout >0 && ptr->start_time > 0)
		{
			if ((ptr->start_time + ptr->sessiontimeout) < curtime)
			{
				ptr->start_time = 0;
				ptr->sessiontimeout = 0;
				fw_deny(ptr->ip, ptr->mac, 0);
				client_fwrule_clear(ptr->ip);
			}
			else
			{
				printf("%s(%d): Time is still valid\n", __FUNCTION__, __LINE__);
			}
		}
		ptr = ptr->next;
	}
}
/** Launches a thread that periodically checks in with the wifidog auth server to perform heartbeat function.
@param arg NULL
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
// called by main_loop(), wifidog
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
		//ping(); // 向认证服务器上报http请求心跳
		rep_userstatus();
		dev_status();
		disconnect_user();
		upgrade();
		clean_timeout_client();

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
/*****
 *  func: to make up the content need to be POST to server.
 *  format: username mac_address ip_address flag someotherthing duration(0/0) bdown(0/0) bup(0/0)\n
 * 			username mac_address ip_address flag someotherthing duration(0/0) bdown(0/0) bup(0/0)\n
 * 			username mac_address ip_address flag someotherthing duration(0/0) bdown(0/0) bup(0/0)
 */

static char * user_status()
{
	/*snprintf(content, sizeof(content) - 1, "status={ \"record\": \"- AA-BB-CC-DD-EE-FF 10.1.1.4 dnat " \
		"5366088700000003 0/0 0/0 0/0\nhalo 11-22-33-44-55-66 192.168.1.192 pass 5366085900000002" \
		"105/86400 381707/0 115903/0\n- aa-bb-bb-bb-cc-dd 192.168.1.106 dnat 5366066000000001 0/0 0/0 0/0\" }" \
		"&auth_key=81D55158E7D7B56182F6BFFCBD6A6C34&wan_mac=%s", get_iface_mac_formatA(config->gw_interface));*/

    FILE *proc;
	char ip[16];
	char mac[18];
	char iface[8];
	char content[2*MAX_BUF];
	int flag = 0;
	
	memset(ip, 0, sizeof(ip));
	memset(mac, 0, sizeof(mac));
	memset(content, 0, sizeof(content));
	
    if (!(proc = fopen("/proc/net/arp", "r"))) {
        return NULL;
    }

    /* Skip first line */
	while (!feof(proc) && fgetc(proc) != '\n');

    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %8[A-Za-z0-9.-]", ip, mac, iface) == 3)) 
	{
		if(flag && (strlen(content) > 0))
		{
			snprintf(content+strlen(content), sizeof(content)-strlen(content), "\n");
		}
		
		printf("iface=%s\n", iface);
		if(strstr(iface, "br-lan2"))
		{
			printf("br-lan2\n");
			flag = 1;
			snprintf(content+strlen(content), sizeof(content)-strlen(content), "user %s %s %s pass weeds 0/0 0/0 0/0", ip, mac, iface);
		}
		else if(strstr(iface, "br-lan"))
		{
			printf("br-lan\n");
			flag = 1;
			snprintf(content+strlen(content), sizeof(content)-strlen(content), "user %s %s %s dnat weeds 0/0 0/0 0/0", ip, mac, iface);
		}
		else
		{
			flag = 0;
		}
		printf("content=%s\n", content);
	}

	printf("content all=%s\n", content);
    fclose(proc);

	return content;
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
	char			request[MAX_BUF*2];
	char	content[MAX_BUF];
	fd_set			readfds;
	struct timeval		timeout;
	
	t_auth_serv *auth_server = NULL;
	const s_config *config = config_get_config();
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
	printf("You are in rep_status.php request procedure!\n");
	snprintf(content, sizeof(content) - 1, "status={ \"record\": \"%s\" }" \
				"&auth_key=81D55158E7D7B56182F6BFFCBD6A6C34&wan_mac=%s", 
				user_status(), get_iface_mac_formatA(config->gw_interface));
	printf("You are in rep_status.php request procedure 2!\n");
	snprintf(request, sizeof(request) - 1,
			"POST /ysapi/rep_userstatus.php HTTP/1.1\r\n"
			"User-Agent: WiFiDog %s\r\n"
			"Host: www.yswifi.com\r\n"
			"Accept: */*\r\n"
			"Content-Length: %d\r\n"
			"\r\n"
			"%s",
			VERSION,
			strlen(content),
			content
			);
	printf("You are in rep_status.php request procedure 3!\n");
	
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

static char * hostname()
{
	
}

#define FIRMWARE_VERSION_PATH "/etc/yswifi/custom_version"
#define FIRMWARE_VERSION	"firmware_version="
static char * firmware_revision()
{
	char buf[32];
	char *ptr = NULL, *ptr1 = NULL;
	FILE *fp = NULL;

	memset(buf, 0, sizeof buf);

	fp = fopen(FIRMWARE_VERSION_PATH, "r");
	if (NULL == fp)
	{
		return NULL;
	}

	while(fread(buf, 32, 1, fp) >=0)
	{
		printf("%s", buf);
		if (feof(fp))
		{
			break;
		}
	}
	
	ptr = strstr(buf, FIRMWARE_VERSION);
	if (NULL != ptr)
	{
		ptr = ptr+strlen(FIRMWARE_VERSION);
		//printf("FW_VERSION=%s\n", ptr);
		if (ptr1 = strstr(ptr, "\n"))
		{
			*ptr1 = '\0';
		}
		if (ptr1 = strstr(ptr, "\r"))
		{
			*ptr1 = '\0';
		}
	}
	fclose(fp);
	return ptr;
}
/***
 * func: config_in
 * execute operation to write the new config to the configuration file.
 */
#define FILE_PATH "/etc/yswifi/wireless"
int config_in(char *ssid_pri, char *key, char *ssid_hs)
{
	FILE *fp = NULL;
	char *ptr = NULL, *ptr1 = NULL, *ptr2 = NULL;
	char *buf;
	char *bufw;
	int len = 0, len_old = 0, i = 0, j = 0, k = 0;
	char *pssid_pri =ssid_pri, *pkey = key, *pssid_hs = ssid_hs;
	struct stat bufst;
	
	stat(FILE_PATH, &bufst);
	printf("%s file size=%d\n", FILE_PATH, bufst.st_size);
	
	printf ("ssid_pri:%s, key=%s, ssid_hs=%s\n", ssid_pri, key, ssid_hs);
	
	buf = (char *)malloc(bufst.st_size);
	bufw = (char *)malloc(bufst.st_size + strlen(ssid_pri) + strlen(key) + strlen(ssid_hs));
	printf("Get here\n");
	/*if (NULL == ssid_pri || NULL == key || NULL == ssid_hs)
	{
		printf("%d: Parameters have NULL\n", __LINE__);
		goto ERR_EXIT;
	}*/
	
	memset(buf, 0, bufst.st_size);
	memset(bufw, 0, bufst.st_size + strlen(ssid_pri) + strlen(key) + strlen(ssid_hs));
	fp = fopen(FILE_PATH, "r+");
	if (NULL == fp)
	{
		printf("File not exist\n");
		goto ERR_EXIT;
	}
	printf("%d: sizeof buf=%d\n",__LINE__, sizeof(buf));
	while (!feof(fp) && (strlen(buf) != bufst.st_size))
	{
		printf("len=%d, buf=%s\n", strlen(buf), buf);
		len = fread(buf+strlen(buf), bufst.st_size-strlen(buf), 1, fp);
	}
	printf("buf=%s\n", buf);
	printf("##################len=%d###############\n", strlen(buf));
	if (strlen(buf) <= 0)
	{
		printf("%d:Bad configuration\n", __LINE__);
		goto ERR_EXIT;
	}
	ptr = strstr(buf, "option ssid '");
	if (NULL == ptr)
	{
		printf("%d:Bad configuration\n", __LINE__);
		goto ERR_EXIT;
	}
	ptr1 = strstr(ptr + strlen("option ssid '") + 1, "'");
	if (NULL == ptr1)
	{
		printf("%d:Bad configuration\n", __LINE__);
		goto ERR_EXIT;
	}
	len_old = ptr1 - ptr - strlen("option ssid '");
	
	while (i <= (ptr - buf + strlen("option ssid '") - 1))
	{
		bufw[i] = buf[i];
		i++;
	}
	j = i;
	printf("%s(%d): i=%d, len_old=%d\n", __FUNCTION__, __LINE__, i, len_old);
	i += len_old;
	printf("%s(%d): i=%d, len_old=%d\n", __FUNCTION__, __LINE__, i, len_old);
	printf("%s(%d): len=%d, bufw=%s\n", __FUNCTION__, __LINE__, strlen(bufw), bufw);
	len = strlen(ssid_hs); // new ssid length
	if (len >0)
	{
		while (len && *pssid_hs)
		{
			len--;
			bufw[j] = *pssid_hs;
			printf("bufw[%d]=%c\n", j, bufw[j]);
			printf("ssid_hs=%c\n", *pssid_hs);
			pssid_hs++;
			j++;
			
		}
	}
	else
	{
		i -= len_old;
	}
	//bufw[strlen(bufw)+1] = '\0';
	printf("%s(%d)\n",__FUNCTION__, __LINE__);
	printf("%d:bufw=%s\n", __LINE__, bufw);

	ptr = strstr(ptr1, "option ssid '");
	if (NULL == ptr)
	{
		printf("%d:Bad configuration\n", __LINE__);
		goto ERR_EXIT;
	}
	ptr2 = strstr(ptr + strlen("option ssid '") + 1, "'");
	
	if (NULL == ptr2)
	{
		printf("%d:Bad configuration\n", __LINE__);
		goto ERR_EXIT;
	}
	len_old = ptr2 - ptr - strlen("option ssid '");
	
	while (k <= (ptr - ptr1 + strlen("option ssid '") - 1))
	{
		k++;
		bufw[j++] = buf[i++];
	}
	printf("%s(%d): i=%d, len_old=%d\n", __FUNCTION__, __LINE__, i, len_old);
	printf("%d:bufw=%s\n", __LINE__, bufw);
	i += len_old;
	printf("%s(%d): i=%d, len_old=%d\n", __FUNCTION__, __LINE__, i, len_old);
	len = strlen(ssid_pri);
	if (len > 0)
	{
		while (len && *pssid_pri)
		{
			len--;
			bufw[j] = *pssid_pri;
			printf("%d:ssid_pri=%c\n", __LINE__, *pssid_pri);
			printf("%d:bufw[%d]=%c\n", __LINE__, j, bufw[j]);
			pssid_pri++;
			j++;
		}
	}
	else
	{
		i -= len_old;
	}
	//bufw[strlen(bufw)+1] = '\0';
	printf("%s(%d)\n",__FUNCTION__, __LINE__);
	printf("%d:bufw=%s\n", __LINE__, bufw);
	

	ptr = strstr(ptr2 , "option key '");
	if (NULL == ptr)
	{
		printf("%d:Bad configuration\n", __LINE__);
		goto ERR_EXIT;
	}
	
	ptr1 = strstr(ptr + strlen("option key '") + 1, "'");
	if (NULL == ptr1)
	{
		printf("%d:Bad configuration\n", __LINE__);
		goto ERR_EXIT;
	}

	len_old = ptr1 - ptr - strlen("option key '");
	printf("$$$$$$$$$$$$$$len_old=%d, [%s]#############\n", len_old, ptr1);
	len = strlen(key);
	
	// wirte value between last ssid and key.
	k = 0;
	while(k <= (ptr - ptr2 + strlen("option key '") - 1))
	{
		k++;
		bufw[j] = buf[i];
		j++; i++;
	}
	printf("%s(%d): i=%d, len_old=%d\n", __FUNCTION__, __LINE__, i, len_old);
	i += len_old; // i increase the length of the last ssid
	printf("%s(%d): i=%d, len_old=%d\n", __FUNCTION__, __LINE__, i, len_old);
	printf("%s(%d): bufw=%s, buf len=%d, i=%d\n", __FUNCTION__, __LINE__, bufw, strlen(buf), i);
	if (len > 0)
	{
		while (len && *pkey)
		{
			len --;
			bufw[j] = *pkey;
			printf("%s(%d):bufw[%d]=%c\n", __FUNCTION__, __LINE__, j, bufw[j]);
			printf("%s(%d):pkey=%c\n", __FUNCTION__, __LINE__, *pkey);
			pkey++;
			j++;
		}
	}
	else
	{
		i -= len_old;
	}
	//bufw[strlen(bufw)+1] = '\0';
	printf("%s(%d)\n",__FUNCTION__, __LINE__);
	printf("%d:bufw=%s\n", __LINE__, bufw);

	printf("len=%d, i=%d\n", strlen(buf), i);
	while (strlen(buf) > i)
	{
		bufw[j] = buf[i];
		printf("%d: bufw[%d]=%c\n", __LINE__, j, bufw[j]);
		printf("%d: buf[%d]=%c\n", __LINE__, i, bufw[i]);
		j++;i++;
	}
	//bufw[strlen(bufw)+1] = '\0';
	printf("%d:bufw=%s\n", __LINE__, bufw);
#if 1
	/*if (0 != lseek(fp, 0, SEEK_SET))
	{
		printf("lseek failed\n");
	}*/
	fclose(fp);
	unlink(FILE_PATH);
	if (0 == access(FILE_PATH, F_OK))
	{
		printf("unlink failed, try again\n");
		unlink(FILE_PATH);
	}
	else
	{
REOPEN:
		printf("File deleted\n");
		//sleep(10);
		fp = NULL;
		fp = fopen(FILE_PATH, "w+");
		if (NULL == fp)
		{
			printf("File not exist\n");
			goto REOPEN;
		}
		fwrite(bufw, strlen(bufw), 1, fp);
		fflush(fp);
		fclose(fp);
	}
	//rewind(fp);
#endif
	free (buf);
	free (bufw);
	return 0;
ERR_EXIT:
	free (buf);
	free (bufw);
	return -1;
}
/***
 * func: update_config
 *  config the wireless related configuration like ssid, ssid_hs, ssid key, and so on.
 * author: weeds
 */
static int update_config(char *data)
{
	char *ptr = NULL, *ptr1 = NULL;
	char *tmp = data;
	char ssid_pri[32+1], ssid_hs[32+1], key[256];
	int action = 0;
	
	memset(ssid_pri, 0, sizeof(ssid_pri));
	memset(ssid_hs, 0, sizeof(ssid_hs));
	memset(key, 0, sizeof(key));
	
	if (NULL == tmp)
	{
		printf("NULL is illegal string, update_config\n");
		return -1;
	}
	if (NULL != (tmp = strstr(tmp, "\r\n\r\n")))
	{
		tmp = tmp + strlen("\r\n\r\n");
	}
	
	if ((NULL !=strstr(tmp, "action=reboot")) || (NULL !=strstr(tmp, "reboot")))
	{
		printf("%s(%d): action=reboot\n", __FUNCTION__, __LINE__);
		action = 1;
	}
	// parse string from content
	/**************
	 * wifi_ssid_pri=  [with wpa2psk(AES)]
	 * wifi_key=
	 * wifi_ssid_hs=	[need authenticate with server]
	 * action=reboot
	 **************/
	ptr = strstr(tmp, "wifi_ssid_pri=");
	if (NULL != ptr)
	{
		// *(ptr + strlen("wifi_ssid_pri="))= '\0';
		ptr1 = strstr(ptr, "\n");
		if (ptr1)
		{
			*ptr1 = '\0';
			tmp = ptr1 + 1;
		}
		printf ("%d:wifi_ssid_pri=%s\n", __LINE__, ptr);
		snprintf(ssid_pri, sizeof(ssid_pri), "%s", ptr+strlen("wifi_ssid_pri="));
	}

	printf ("%s(%d): %s\n", __FUNCTION__, __LINE__, ptr);
	ptr = strstr(tmp, "wifi_key=");
	if (NULL != ptr)
	{
		ptr1 = strstr(ptr, "\n");
		if (ptr1)
		{
			*ptr1 = '\0';
			tmp = ptr1 + 1;
		}
		printf("%d:wifi_key=%s\n", __LINE__, ptr+strlen("wifi_key="));
		snprintf(key, sizeof(key), "%s", ptr+strlen("wifi_key="));
	}
	printf ("%s(%d): %s\n", __FUNCTION__, __LINE__, ptr);
	ptr = strstr(tmp, "wifi_ssid_hs=");
	if (NULL != ptr)
	{
		ptr1 = strstr(ptr, "\n");
		if (ptr1)
		{
			*ptr1 = '\0';
			tmp = ptr1 + 1;
		}
		printf("%d:wifi_ssid_hs=%s\n", __LINE__, ptr+strlen("wifi_ssid_hs="));
		snprintf(ssid_hs, sizeof(ssid_hs), "%s", ptr+strlen("wifi_ssid_hs="));
	}
	printf ("%s(%d): %s\n", __FUNCTION__, __LINE__, ptr);
	// set the configuration to the config file.
	printf("pri=%s\nkey=%s\nhs=%s\n", ssid_pri, key, ssid_hs);
	
	if (-1 == config_in(ssid_pri, key, ssid_hs))
	{
		printf("Configuration not modify right\n");
		return -1;
	}
	
	if (1 == action)
	{
		system("reboot");
	}
	return 0;
	
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
	
	t_auth_serv *auth_server = NULL;
	const s_config *config = config_get_config();
	auth_server = get_auth_server(); //获取认证服务器配置信息

	debug(LOG_DEBUG, "Entering dev_status()");

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
		 printf("auth failed\n");
		return;
	}
	printf("You are in dev_status.php request procedure!\n");
	snprintf(request, sizeof(request) - 1,
			"GET /ysapi/dev_status.php?authkey=81D55158E7D7B56182F6BFFCBD6A6C34&hostname=MT7620N&devicename=&firmware=MT7620N"
			"&firmware_revision=%s&online_user_num=0&uptime=0&cpu=25%%&memfree=0&wan_iface=eth2.2"
			"&wan_ip=192.168.1.143&wan_bup=0&wan_bdown=0&wifi_bup=0&wifi_iface=ra1&wifi_iface_hs=ra0&wifi_mac=&wifi_ip=&wifi_ssid_hs=YSWiFi"
			"&wifi_ssid=MyWiFi&wifi_encryption=psk2&wifi_key=12345678&wifi_channel_mode=manual&wifi_signal=&wifi_maxassoc=&wan_mac=%s HTTP/1.1\r\n"
			"User-Agent: WiFiDog %s\r\n"
			"Host: www.yswifi.com\r\n"
			"\r\n",
			firmware_revision(),
			get_iface_mac_formatA(config->gw_interface),
			VERSION
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
		update_config(request);
	}
	else {
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
/***
 * func: delete_user
 * delete the mac list return by the server 
 * author: weeds
 */
static int delete_user(char *list)
{
	char *ptr = NULL;
	char *tmp = list;
	char *mac = NULL;
	int count = 1;
	t_client *client = NULL, *p1 = NULL;
	printf("ALl: %s\n", list);
	if (NULL == tmp)
	{
		printf("NULL is illegal string\n");
		return -1;
	}
	if (NULL != (tmp = strstr(tmp, "\r\n\r\n")))
	{
		tmp = tmp + strlen("\r\n\r\n");
	}
	printf("MAC list need to be deleted:\n%s\n", tmp);
	// in case, the only one mac don't have '\n'
	if (NULL == strstr(tmp, "\n"))
	{
		if (17 == strlen(tmp))
		{
			printf("One Mac address: %s\n", tmp);
			goto MAC_CMP;
		}
	}
	printf("$$$$$$$$$$$$$$$$$$$$$\n");
	while(NULL != (ptr = strstr(tmp,"\n")))
	{
		*ptr = '\0';
		printf("NEXT is LOCK CLIENT LIST\n");
MAC_CMP:
		LOCK_CLIENT_LIST();
		printf("trans mac formatA\n");
		trans_mac_formatA(tmp);
		printf("MAC address : %s\n", tmp);
		client = client_list_find_by_mac(tmp);
		if (NULL == client)
		{
			printf("The desired client mac not in the list: mac=%s\n", tmp);
			//UNLOCK_CLIENT_LIST();
			//continue;
		}
		else
		{
			fw_deny(client->ip, client->mac, 0);
			client_fwrule_clear(client->ip);
			p1 = client_list_find(client->ip, client->mac);
			if (NULL != p1)
			{
				client_list_delete(p1);
				p1 = NULL;
			}
			else
			{
				printf("client %s have been deleted\n", client->ip);
			}
		}
		UNLOCK_CLIENT_LIST();
		if (NULL == ptr)
		{
			printf("NULL is not permitted 1\n");
			break;
		}
		tmp = ptr + 1;
		if (NULL == tmp)
		{
			printf("NULL is not permitted 2\n");
			break;
		}
		
	}
	// in case the last mac do not have '\n'
	if (NULL == strstr(tmp, "\n") && count)
	{
		if ((NULL != tmp) && (17 == strlen(tmp)))
		{
			printf("One Mac address: %s\n", tmp);
			ptr = NULL;
			count = 0;
			goto MAC_CMP;
		}
	}
	return 0;
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
	
	t_auth_serv *auth_server = NULL;
	const s_config *config = config_get_config();
	auth_server = get_auth_server(); //获取认证服务器配置信息

	debug(LOG_DEBUG, "Entering disconnect_user()");
		
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
		printf("You are in disconn_user.php request procedure!\n");
		goto ERR_EXIT;
	}
	printf("You are in rep_status.php request procedure!\n");
	snprintf(request, sizeof(request) - 1,
			"GET /ysapi/disconn_user.php?authkey=81D55158E7D7B56182F6BFFCBD6A6C34&wan_mac=%s HTTP/1.1\r\n"
			"User-Agent: WiFiDog %s\r\n"
			"Host: www.yswifi.com\r\n"
			"\r\n",
			get_iface_mac_formatA(config->gw_interface),
			VERSION
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

	delete_user(request);
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
/***
 * func: upgrade_status
 * upgrade the firmware from below url, and md5.
 * author: weeds
 */
static int upgrade_status(char * response)
{
	char *tmp = response, *ptr=NULL, *ptr1=NULL, *ptr2=NULL;
	char md5[32+1];
	char url[256];
	int ret = 0;
	FILE *fp;
	char buf[256];
	char cmd_url[256];
	char filename[256];
	
	memset(md5, 0, sizeof md5);
	memset(url, 0, sizeof url);
	memset(cmd_url, 0, sizeof cmd_url);
	memset(buf, 0, sizeof buf);
	
	if (NULL == tmp)
	{
		printf("NULL is illegal string\n");
		return -1;
	}
	if (NULL != (tmp = strstr(tmp, "\r\n\r\n")))
	{
		tmp = tmp + strlen("\r\n\r\n");
	}
	printf("tmp=%s\n", tmp);
	ptr = strstr(tmp, "firmwaremd5=");
	ptr2 = strstr(tmp, "firmwaredlurl=");
	if ((NULL != ptr) && (NULL != ptr2))
	{ 
		if (ptr2 > ptr)
		{
			ptr1 = strstr(tmp, "\n");
			if (NULL == ptr1)
			{
				printf("No CRLF found\n");
				return -1;
			}
			else
			{
				*ptr1 = '\0';
				tmp = ptr1+1;
			}
			
			snprintf(md5, sizeof(md5), "%s", ptr+strlen("firmwaremd5="));
			if (32 != strlen(md5))
			{
				printf("MD5 sum error 1\n");
				return -1;
			}
			printf("%d:md5=%s\n", __LINE__, md5);
			
			ptr = strstr(tmp, "firmwaredlurl=");
			if (NULL != ptr)
			{
				ptr1 = strstr(ptr, "\n");
				if (NULL != ptr1)
				{
					*ptr1 = '\0';
				}
				snprintf(url, sizeof(url), "%s", ptr+strlen("firmwaredlurl="));
				printf("%d:url=%s\n", __LINE__, url);
			}
		}
		else if (ptr > ptr2)
		{
			ptr1 = strstr(tmp, "\n");
			if (NULL == ptr1)
			{
				printf("No CRLF found\n");
				return -1;
			}
			else
			{
				*ptr1 = '\0';
				tmp = ptr1+1;
			}
			
			snprintf(url, sizeof(url), "%s", ptr2+strlen("firmwaredlurl="));
			
			ptr2 = strstr(tmp, "firmwaremd5=");
			if (NULL != ptr2)
			{
				ptr1 = strstr(ptr2, "\n");
				if (NULL != ptr1)
				{
					*ptr1 = '\0';
				}
				
				snprintf(md5, sizeof(md5), "%s", ptr2+strlen("firmwaremd5="));
				printf("%d:md5=%s\n", __LINE__, md5);
				if (32 != strlen(md5))
				{
					printf("MD5 sum error 2\n");
					return -1;
				}
			}
		}
	}
	else
	{
		printf("MD5 or URL not exist\n");
		return -1;
	}
	
	snprintf(cmd_url, sizeof cmd_url, "wget -P /tmp/ %s",url);
	printf("%d:cmd_url=%s\n", __LINE__, cmd_url);
	ret = system(cmd_url);
	if (ret < 0)
	{
		// do something to mend this problem.
		//ret = system(cmd_url);
	}
	// calculate the md5 value.
	memset(cmd_url, 0, sizeof cmd_url);
	
	ptr = url;
	ptr1 = NULL;
	
	if (NULL != (ptr1 = strrchr(ptr, '/')))
	{
		*ptr1 = '\0';
		ptr = ptr1 + 1;
	}
#define md5_path "/tmp/firmwaremd5"
	
	memset(filename, 0, sizeof filename);
	snprintf(filename, sizeof filename, "/tmp/%s", ptr);
	
	if (0 != access(filename, R_OK))
	{
		printf("file not exist, %s\n", filename);
		return -2;
	}
	snprintf(cmd_url, sizeof cmd_url, "md5sum %s >%s", filename, md5_path);
	
	system(cmd_url);
	fp = fopen(md5_path, "r");
	if (NULL == fp)
	{
		printf("md5_path=%s, file not exist\n", md5_path);
		return -2;
	}
	
	while(fread(buf, 256, 1, fp) >=0)
	{
		printf("%s", buf);
		if (feof(fp))
		{
			break;
		}
	}
	fclose(fp);
	printf("%d: buf=%s\n", __LINE__, buf);
	
	if (NULL == buf)
	{
		printf("md5 content should not be empty\n");
		return -2;
	}
	
	ptr1 = strstr(buf, " ");
	if (NULL != ptr1)
	{
		*ptr1 = '\0';
	}
	printf("%d: buf=%s\n", __LINE__, buf);
	
	if (32 != strlen(buf))
	{
		printf("Md5 value length is not right\n");
		return -2;
	}
	printf("%d:md5=%s\n", __LINE__, md5);
	if (0 != strcasecmp(md5, buf))
	{
		printf("md5 compare not the same, please check it\n");
		return -2;
	}
	
	memset(cmd_url, 0, sizeof(cmd_url));
	
	snprintf(cmd_url, sizeof cmd_url, "sysupgrade %s", filename);
	printf(cmd_url);
	ret = system(cmd_url);
	if (0 != ret)
	{
		printf("%d:try again\n",__LINE__);
		system(cmd_url);
	}
	return 0;
}
// GET /ysapi/upgradeapi.php?authkey=xxxx HTTP/1.1
static int upgrade()
{
	ssize_t			numbytes;
    size_t	        	totalbytes;
	int			sockfd, nfds, done;
	char			request[MAX_BUF];
	fd_set			readfds;
	struct timeval		timeout;
	
	t_auth_serv	*auth_server = NULL;
	const s_config *config = config_get_config();
	auth_server = get_auth_server(); //获取认证服务器配置信息
	
	debug(LOG_DEBUG, "Entering upgrade()");
		
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
		printf("You are in upgrade.php request procedure!\n");
		goto ERR_EXIT;
	}
	printf("You are in upgrade.php request procedure!\n");
	
	snprintf(request, sizeof(request) - 1,
			"GET /ysapi/upgradeapi.php?authkey=81D55158E7D7B56182F6BFFCBD6A6C34&wan_mac=%s HTTP/1.1\r\n"
			"User-Agent: WiFiDog %s\r\n"
			"Host: www.yswifi.com\r\n"
			"\r\n",
			get_iface_mac_formatA(config->gw_interface),
			VERSION
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
		upgrade_status(request);
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
