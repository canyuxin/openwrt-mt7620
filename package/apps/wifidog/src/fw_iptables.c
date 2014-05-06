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

/* $Id: fw_iptables.c 1454 2010-03-03 20:53:06Z gbastien $ */
/** @internal
  @file fw_iptables.c
  @brief Firewall iptables functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

#include "safe.h"
#include "conf.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "debug.h"
#include "util.h"
#include "client_list.h"

static int iptables_do_command(const char *format, ...);
static char *iptables_compile(const char *, const char *, const t_firewall_rule *);
static void iptables_load_ruleset(const char *, const char *, const char *);

extern pthread_mutex_t	client_list_mutex;
extern pthread_mutex_t	config_mutex;

/**
Used to supress the error output of the firewall during destruction */
static int fw_quiet = 0;

/** @internal
 * @brief Insert $ID$ with the gateway's id in a string.
 *
 * This function can replace the input string with a new one. It assumes
 * the input string is dynamically allocted and can be free()ed safely.
 *
 * This function must be called with the CONFIG_LOCK held.
 */
 // called by iptables_fw_destroy_mention(), 格式化并替换字符串@input中的标签"$ID$"
static void
iptables_insert_gateway_id(char **input)
{
	char *token;
	const s_config *config;
	char *buffer;

	if (strstr(*input, "$ID$")==NULL)
		return;


	while ((token=strstr(*input, "$ID$"))!=NULL)
		/* This string may look odd but it's standard POSIX and ISO C */
		memcpy(token, "%1$s", 4);

	config = config_get_config();
	safe_asprintf(&buffer, *input, config->gw_interface);

	free(*input);
	*input=buffer;
}

/** @internal
 * */
static int
iptables_do_command(const char *format, ...)
{
	va_list vlist;
	char *fmt_cmd;
	char *cmd;
	int rc;

	va_start(vlist, format);
	safe_vasprintf(&fmt_cmd, format, vlist);
	va_end(vlist);

	safe_asprintf(&cmd, "iptables %s", fmt_cmd);
	free(fmt_cmd);

	iptables_insert_gateway_id(&cmd);

	debug(LOG_DEBUG, "Executing command: %s", cmd);

	rc = execute(cmd, fw_quiet);

	if (rc!=0) {
		// If quiet, do not display the error
		if (fw_quiet == 0)
			debug(LOG_ERR, "iptables command failed(%d): %s", rc, cmd);
		else if (fw_quiet == 1)
			debug(LOG_DEBUG, "iptables command failed(%d): %s", rc, cmd);
	}

	free(cmd);

	return rc;
}

/**
 * @internal
 * Compiles a struct definition of a firewall rule into a valid iptables
 * command.
 * @arg table Table containing the chain.
 * @arg chain Chain that the command will be (-A)ppended to.
 * @arg rule Definition of a rule into a struct, from conf.c.
 */
	static char *
iptables_compile(const char * table, const char *chain, const t_firewall_rule *rule)
{
	char	command[MAX_BUF],
		*mode;

	memset(command, 0, MAX_BUF);

	if (rule->block_allow == 1) {
		mode = safe_strdup("ACCEPT");
	} else {
		mode = safe_strdup("REJECT");
	}

	snprintf(command, sizeof(command),  "-t %s -A %s ",table, chain);
	if (rule->mask != NULL) {
		snprintf((command + strlen(command)), (sizeof(command) -
					strlen(command)), "-d %s ", rule->mask);
	}
	if (rule->protocol != NULL) {
		snprintf((command + strlen(command)), (sizeof(command) -
					strlen(command)), "-p %s ", rule->protocol);
	}
	if (rule->port != NULL) {
		snprintf((command + strlen(command)), (sizeof(command) -
					strlen(command)), "--dport %s ", rule->port);
	}
	snprintf((command + strlen(command)), (sizeof(command) -
				strlen(command)), "-j %s", mode);

	free(mode);

	/* XXX The buffer command, an automatic variable, will get cleaned
	 * off of the stack when we return, so we strdup() it. */
	return(safe_strdup(command));
}

/**
 * @internal
 * Load all the rules in a rule set.
 * @arg ruleset Name of the ruleset
 * @arg table Table containing the chain.
 * @arg chain IPTables chain the rules go into
 */
	static void
iptables_load_ruleset(const char * table, const char *ruleset, const char *chain)
{
	t_firewall_rule		*rule;
	char			*cmd;

	debug(LOG_DEBUG, "Load ruleset %s into table %s, chain %s", ruleset, table, chain);

	for (rule = get_ruleset(ruleset); rule != NULL; rule = rule->next) {
		cmd = iptables_compile(table, chain, rule);
		debug(LOG_DEBUG, "Loading rule \"%s\" into table %s, chain %s", cmd, table, chain);
		iptables_do_command(cmd);
		free(cmd);
	}

	debug(LOG_DEBUG, "Ruleset %s loaded into table %s, chain %s", ruleset, table, chain);
}

	void
iptables_fw_clear_authservers(void)
{
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_AUTHSERVERS);
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_AUTHSERVERS);
}

	void
iptables_fw_set_authservers(void)
{
	const s_config *config;
	t_auth_serv *auth_server;

	config = config_get_config();

	for (auth_server = config->auth_servers; auth_server != NULL; auth_server = auth_server->next) {
		if (auth_server->last_ip && strcmp(auth_server->last_ip, "0.0.0.0") != 0) {
			iptables_do_command("-t filter -A " TABLE_WIFIDOG_AUTHSERVERS " -d %s -j ACCEPT", auth_server->last_ip);
			iptables_do_command("-t nat -A " TABLE_WIFIDOG_AUTHSERVERS " -d %s -j ACCEPT", auth_server->last_ip);
		}
	}

}

// add by lijg, 2013-08-14, Load wwlist conf from @cfgname file
static void load_wwlist_conf(const char *cfgname)
{
	FILE *fp = NULL;
	char buff[128];
	int cnum = 0;
	char *ptr = NULL;
	char *ip = NULL; 
	char *mac = NULL;
	char bits = 0;
	char ipaddr[32];
	char macaddr[32];

	if (NULL == (fp = fopen(cfgname, "r"))) {
		return ;
	}

	ipaddr[0] = 0;
	macaddr[0] = 0;

	while (cnum < 256 && fgets(buff, sizeof(buff), fp) != NULL) {
		unsigned int len = strlen(buff);
		if (buff[len-1] == '\r' || buff[len-1] == '\n') {
			buff[len-1] = '\0';
		}
		debug(LOG_DEBUG, "wwlist read line [%s]", buff);
		if (NULL != strstr(buff, "option ip") ) {
			ip = strtok_r(buff, "\t '", &ptr);
			if (!ip) continue;
			ip = strtok_r(NULL, "\t' ", &ptr);
			if (!ip) continue;
			ip = strtok_r(NULL, "\t' ", &ptr);
			if (!ip) continue;
			strncpy(ipaddr, ip, sizeof(ipaddr)-1);
			ipaddr[sizeof(ipaddr)-1] = 0;
			bits |= 0x01;
			//debug(LOG_DEBUG, "wwlist get ip [%s] %d", ipaddr, cnum);
		} else if ( NULL != strstr(buff, "option hw") ) {
			mac = strtok_r(buff, "\t '", &ptr);
			if (!mac) continue;
			mac = strtok_r(NULL, "\t' ", &ptr);
			if (!mac) continue;
			mac = strtok_r(NULL, "\t' ", &ptr);
			if (!mac) continue;
			strncpy(macaddr, mac, sizeof(macaddr)-1);
			macaddr[sizeof(macaddr)-1] = 0;
			bits |= 0x02;
			//debug(LOG_DEBUG, "wwlist get mac [%s] %d", macaddr, cnum);
		} else if (NULL != strstr(buff, "config rule") && ipaddr[0] != 0 && macaddr[0] == 0) {
			debug(LOG_DEBUG, "add white list %s no mac", ipaddr);
			iptables_do_command("-t filter -A " TABLE_WIFIDOG_WLIST " -s %s -j ACCEPT", ipaddr);
			iptables_do_command("-t nat -A " TABLE_WIFIDOG_WLIST " -s %s -j ACCEPT", ipaddr);
			bits = 0;
			cnum ++;
			ipaddr[0] = 0;
			continue;
		}

		if (bits != 0x3) continue;

		// add firewall rule for white list
		debug(LOG_DEBUG, "add white list %s %s", ipaddr, macaddr);
		iptables_do_command("-t filter -A " TABLE_WIFIDOG_WLIST " -s %s -m mac --mac-source %s -j ACCEPT", ipaddr, macaddr);
		iptables_do_command("-t nat -A " TABLE_WIFIDOG_WLIST " -s %s -m mac --mac-source %s -j ACCEPT", ipaddr, macaddr);
		bits = 0;
		cnum ++;
		ipaddr[0] = 0;
		macaddr[0] = 0;
	}

	if (ipaddr[0] != 0) {  // the last ip no mac
		debug(LOG_DEBUG, "add white list %s no mac last", ipaddr);
		iptables_do_command("-t filter -A " TABLE_WIFIDOG_WLIST " -s %s -j ACCEPT", ipaddr);
		iptables_do_command("-t nat -A " TABLE_WIFIDOG_WLIST " -s %s -j ACCEPT", ipaddr);
	}

	fclose(fp);	
}

//add by lijg, 2013-10-09, iptables: Resource temporarily unavailable, must restart it
#define IPT_DO_CMMD(cmd...) \
	if (iptables_do_command(cmd) != 0) exit(-1);

/** Initialize the firewall rules
*/// 1. called by fw_init()<--main(), 创建自定义规则链
	int
iptables_fw_init(void)
{
	const s_config *config;
	char * ext_interface = NULL;  // 获取WAN口名称
	int gw_port = 0;
	t_trusted_mac *p;

	fw_quiet = 0;

	LOCK_CONFIG();
	config = config_get_config();
	gw_port = config->gw_port;
	if (config->external_interface) {
		ext_interface = safe_strdup(config->external_interface);
	} else {
		ext_interface = get_ext_iface(); // 获取WAN口名称
	}

	if (ext_interface == NULL) {
		UNLOCK_CONFIG();
		debug(LOG_ERR, "FATAL: no external interface");
		return 0;
	}
	/*
	 *
	 * Everything in the MANGLE table
	 *
	 */

	/* Create new chains */// 创建自定义规则链
	// modified by lijg, 2013-05-17, 取消打标记
	//iptables_do_command("-t mangle -N " TABLE_WIFIDOG_TRUSTED);
	IPT_DO_CMMD("-t mangle -N " TABLE_WIFIDOG_OUTGOING);
	IPT_DO_CMMD("-t mangle -N " TABLE_WIFIDOG_INCOMING);

	/* Assign links and rules to these new chains */
	// modified by lijg, 2013-04-24, avoid confliting with QoS
	IPT_DO_CMMD("-t mangle -I PREROUTING 1 -i %s -j " TABLE_WIFIDOG_OUTGOING, config->gw_interface);
	//iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " TABLE_WIFIDOG_TRUSTED, config->gw_interface);//this rule will be inserted before the prior one


	IPT_DO_CMMD("-t mangle -I POSTROUTING 1 -o %s -j " TABLE_WIFIDOG_INCOMING, config->gw_interface);

    // modified by lijg, 2013-05-17, avoid confliting with QoS
    //for (p = config->trustedmaclist; p != NULL; p = p->next)
	//	iptables_do_command("-t mangle -A " TABLE_WIFIDOG_TRUSTED " -m mac --mac-source %s -j MARK --or-mark %d", p->mac, FW_MARK_KNOWN);

	/*
	 *
	 * Everything in the NAT table
	 *
	 */

	/* Create new chains */
	IPT_DO_CMMD("-t nat -N " TABLE_WIFIDOG_OUTGOING);
	IPT_DO_CMMD("-t nat -N " TABLE_WIFIDOG_WIFI_TO_ROUTER);
	IPT_DO_CMMD("-t nat -N " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	IPT_DO_CMMD("-t nat -N " TABLE_WIFIDOG_GLOBAL);
	IPT_DO_CMMD("-t nat -N " TABLE_WIFIDOG_UNKNOWN);
	IPT_DO_CMMD("-t nat -N " TABLE_WIFIDOG_AUTHSERVERS);

	// add by lijg, 2013-08-14, create chains for white list
	IPT_DO_CMMD("-t nat -N " TABLE_WIFIDOG_WLIST);

	/* Assign links and rules to these new chains */
	IPT_DO_CMMD("-t nat -A PREROUTING -i %s -j " TABLE_WIFIDOG_OUTGOING, config->gw_interface);

	IPT_DO_CMMD("-t nat -A " TABLE_WIFIDOG_OUTGOING " -d %s -j " TABLE_WIFIDOG_WIFI_TO_ROUTER, config->gw_address);
	IPT_DO_CMMD("-t nat -A " TABLE_WIFIDOG_WIFI_TO_ROUTER " -j ACCEPT");

	IPT_DO_CMMD("-t nat -A " TABLE_WIFIDOG_OUTGOING " -j " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	// modified by lijg, 2013-04-24, match mark mask = ff00
	IPT_DO_CMMD("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%04x/0xff00 -j ACCEPT", FW_MARK_KNOWN);
	IPT_DO_CMMD("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%04x/0xff00 -j ACCEPT", FW_MARK_PROBATION);

	// add by lijg, 2013-08-14, add a white list chain
	IPT_DO_CMMD("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_WLIST);
	
	IPT_DO_CMMD("-t nat -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_UNKNOWN);

	IPT_DO_CMMD("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -j " TABLE_WIFIDOG_AUTHSERVERS);
	// modified by lijg, 2013-05-17, 取消该规则
	//iptables_do_command("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -j " TABLE_WIFIDOG_GLOBAL);
	IPT_DO_CMMD("-t nat -A " TABLE_WIFIDOG_UNKNOWN " -p tcp --dport 80 -j REDIRECT --to-ports %d", gw_port);


	/*
	 *
	 * Everything in the FILTER table
	 *
	 */

	/* Create new chains */
	IPT_DO_CMMD("-t filter -N " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	IPT_DO_CMMD("-t filter -N " TABLE_WIFIDOG_AUTHSERVERS);
	IPT_DO_CMMD("-t filter -N " TABLE_WIFIDOG_LOCKED);
	IPT_DO_CMMD("-t filter -N " TABLE_WIFIDOG_GLOBAL);
	IPT_DO_CMMD("-t filter -N " TABLE_WIFIDOG_VALIDATE);
	IPT_DO_CMMD("-t filter -N " TABLE_WIFIDOG_KNOWN);
	IPT_DO_CMMD("-t filter -N " TABLE_WIFIDOG_UNKNOWN);

	// add by lijg, 2013-08-14, create chains for white list
	IPT_DO_CMMD("-t filter -N " TABLE_WIFIDOG_WLIST);

	/* Assign links and rules to these new chains */

	/* Insert at the beginning */
	IPT_DO_CMMD("-t filter -I FORWARD -i %s -j " TABLE_WIFIDOG_WIFI_TO_INTERNET, config->gw_interface);


	//IPT_DO_CMMD("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m state --state INVALID -j DROP");

	/* XXX: Why this? it means that connections setup after authentication
	   stay open even after the connection is done...
	   iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m state --state RELATED,ESTABLISHED -j ACCEPT");*/

	//Won't this rule NEVER match anyway?!?!? benoitg, 2007-06-23
	//iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -i %s -m state --state NEW -j DROP", ext_interface);

	/* TCPMSS rule for PPPoE */
	// modified by lijg, 2013-05-28, cancel this fw rule , repeated in openwrt FW rules
	//iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", ext_interface);

	IPT_DO_CMMD("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_AUTHSERVERS);
	iptables_fw_set_authservers();

	// modified by lijg, 2013-05-17, 取消匹配标记
	//iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%04x/0xff00 -j " TABLE_WIFIDOG_LOCKED, FW_MARK_LOCKED);
	//iptables_load_ruleset("filter", "locked-users", TABLE_WIFIDOG_LOCKED);

	//iptables_do_command("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_GLOBAL);
	//iptables_load_ruleset("filter", "global", TABLE_WIFIDOG_GLOBAL);
	//iptables_load_ruleset("nat", "global", TABLE_WIFIDOG_GLOBAL);

	// modified by lijg, 2013-05-17, 取消该规则
	IPT_DO_CMMD("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%04x/0xff00 -j " TABLE_WIFIDOG_VALIDATE, FW_MARK_PROBATION);
	iptables_load_ruleset("filter", "validating-users", TABLE_WIFIDOG_VALIDATE);

	// add by lijg, 2013-08-14, add a white list chain
	IPT_DO_CMMD("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_WLIST);

	// modified by lijg, 2013-05-17, 取消打标记
	IPT_DO_CMMD("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -m mark --mark 0x%04x/0xff00 -j " TABLE_WIFIDOG_KNOWN, FW_MARK_KNOWN);
	iptables_load_ruleset("filter", "known-users", TABLE_WIFIDOG_KNOWN);

	IPT_DO_CMMD("-t filter -A " TABLE_WIFIDOG_WIFI_TO_INTERNET " -j " TABLE_WIFIDOG_UNKNOWN);
	iptables_load_ruleset("filter", "unknown-users", TABLE_WIFIDOG_UNKNOWN);
	IPT_DO_CMMD("-t filter -A " TABLE_WIFIDOG_UNKNOWN " -j REJECT --reject-with icmp-port-unreachable");

	// add by lijg, 2013-08-14, Load wwlist config rule
	load_wwlist_conf("/etc/config/wwlist");

	UNLOCK_CONFIG();

	// add by lijg, 2013-05-17,
	free(ext_interface);
	return 1;
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog and when it starts to make
 * sure there are no rules left over
 */ // called by main_loop(), 首先初始化清除所有防火墙规则, 清除自定义的规则以及链
	int
iptables_fw_destroy(void)
{
	fw_quiet = 1;

	debug(LOG_DEBUG, "Destroying our iptables entries");

	/*
	 *
	 * Everything in the MANGLE table
	 *
	 */
	debug(LOG_DEBUG, "Destroying chains in the MANGLE table");
	// 清除自定义链中的规则
	// modified by lijg, 2013-05-17
	//iptables_fw_destroy_mention("mangle", "FORWARD", TABLE_WIFIDOG_TRUSTED);
	//iptables_fw_destroy_mention("mangle", "FORWARD", TABLE_WIFIDOG_OUTGOING);

	iptables_fw_destroy_mention("mangle", "PREROUTING", TABLE_WIFIDOG_OUTGOING);
	iptables_fw_destroy_mention("mangle", "POSTROUTING", TABLE_WIFIDOG_INCOMING);

	// 清除自定义的链
	// modified by lijg, 2013-05-17
	//iptables_do_command("-t mangle -F " TABLE_WIFIDOG_TRUSTED);
	iptables_do_command("-t mangle -F " TABLE_WIFIDOG_OUTGOING);
	iptables_do_command("-t mangle -F " TABLE_WIFIDOG_INCOMING);
	//iptables_do_command("-t mangle -X " TABLE_WIFIDOG_TRUSTED);
	iptables_do_command("-t mangle -X " TABLE_WIFIDOG_OUTGOING);
	iptables_do_command("-t mangle -X " TABLE_WIFIDOG_INCOMING);

	/*
	 *
	 * Everything in the NAT table
	 *
	 */
	debug(LOG_DEBUG, "Destroying chains in the NAT table");
	iptables_fw_destroy_mention("nat", "PREROUTING", TABLE_WIFIDOG_OUTGOING);
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_AUTHSERVERS);
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_OUTGOING);
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_WIFI_TO_ROUTER);
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_GLOBAL);
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_UNKNOWN);
	// add by lijg, 2013-08-14, clear white list chain
	iptables_do_command("-t nat -F " TABLE_WIFIDOG_WLIST);
	
	iptables_do_command("-t nat -X " TABLE_WIFIDOG_AUTHSERVERS);
	iptables_do_command("-t nat -X " TABLE_WIFIDOG_OUTGOING);
	iptables_do_command("-t nat -X " TABLE_WIFIDOG_WIFI_TO_ROUTER);
	iptables_do_command("-t nat -X " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	iptables_do_command("-t nat -X " TABLE_WIFIDOG_GLOBAL);
	iptables_do_command("-t nat -X " TABLE_WIFIDOG_UNKNOWN);
	// add by lijg, 2013-08-14, clear white list chain
	iptables_do_command("-t nat -X " TABLE_WIFIDOG_WLIST);
	

	/*
	 *
	 * Everything in the FILTER table
	 *
	 */
	debug(LOG_DEBUG, "Destroying chains in the FILTER table");
	iptables_fw_destroy_mention("filter", "FORWARD", TABLE_WIFIDOG_WIFI_TO_INTERNET);
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_AUTHSERVERS);
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_LOCKED);
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_GLOBAL);
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_VALIDATE);
	// add by lijg, 2013-08-14, clear white list chain
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_WLIST);
	
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_KNOWN);
	iptables_do_command("-t filter -F " TABLE_WIFIDOG_UNKNOWN);
	iptables_do_command("-t filter -X " TABLE_WIFIDOG_WIFI_TO_INTERNET);
	iptables_do_command("-t filter -X " TABLE_WIFIDOG_AUTHSERVERS);
	iptables_do_command("-t filter -X " TABLE_WIFIDOG_LOCKED);
	iptables_do_command("-t filter -X " TABLE_WIFIDOG_GLOBAL);
	iptables_do_command("-t filter -X " TABLE_WIFIDOG_VALIDATE);
	iptables_do_command("-t filter -X " TABLE_WIFIDOG_KNOWN);
	iptables_do_command("-t filter -X " TABLE_WIFIDOG_UNKNOWN);
	// add by lijg, 2013-08-14, clear white list chain
	iptables_do_command("-t filter -X " TABLE_WIFIDOG_WLIST);

	return 1;
}

// add by lijg, 2013-05-30,  Find keyword @mention in firewall rule table = @table and chain = @chain
// return : 0 - not found, 1 - found it .
int iptables_fw_find_mention(
		const char * table,
		const char * chain,
		const char * mention
		) {
	FILE *p = NULL;
	char *command = NULL;
	char line[MAX_BUF];
	char *victim = safe_strdup(mention);
	int found = 0;

    // 1.1 @victim="WiFiDog_br-lan_Trusted"
	iptables_insert_gateway_id(&victim);

	debug(LOG_DEBUG, "Attempting to find all mention of %s from %s.%s", victim, table, chain);

	safe_asprintf(&command, "iptables -t %s -L %s -n --line-numbers -v", table, chain);
	iptables_insert_gateway_id(&command);

    //1.2 执行命令 iptables -t mangle -L PREROUTING -n --line-numbers -v, 逐行输出链中规则
	if ((p = popen(command, "r"))) {
		/* Skip first 2 lines */
		while (!feof(p) && fgetc(p) != '\n');
		while (!feof(p) && fgetc(p) != '\n');
		/* Loop over entries */
		while (fgets(line, sizeof(line), p)) {  // 匹配链中每条规则
			/* Look for victim */
			if (strstr(line, victim)) {  // 根据客户端IP地址进行匹配
				found = 1;
				break;
			}
		}
		pclose(p);
	}

	free(command);
	free(victim);


	return (found);
}

/*
 * Helper for iptables_fw_destroy
 * @param table The table to search
 * @param chain The chain in that table to search
 * @param mention A word to find and delete in rules in the given table+chain
 */
// 1. called by iptables_fw_destroy(), @table="mangle",@chain="PREROUTING",@mention="WiFiDog_$ID$_Trusted"
// 2. called by iptables_fw_counters_update(), 如果出错则清除某个客户端IP的规则(位于具体规则链中)
//  @table= "filter", @chain="WiFiDog_br-lan_Known", @mention="198.130.223.195"
//  清除用户自定义链中的规则
int
iptables_fw_destroy_mention(
		const char * table,
		const char * chain,
		const char * mention
		) {
	FILE *p = NULL;
	char *command = NULL;
	char *command2 = NULL;
	char line[MAX_BUF];
	char rulenum[10];
	char *victim = safe_strdup(mention);
	int deleted = 0;

    // 1.1 @victim="WiFiDog_br-lan_Trusted"
	iptables_insert_gateway_id(&victim);

	debug(LOG_DEBUG, "Attempting to destroy all mention of %s from %s.%s", victim, table, chain);

	safe_asprintf(&command, "iptables -t %s -L %s -n --line-numbers -v", table, chain);
	iptables_insert_gateway_id(&command);

    //1.2 执行命令 iptables -t mangle -L PREROUTING -n --line-numbers -v, 逐行输出链中规则
	if ((p = popen(command, "r"))) {
		/* Skip first 2 lines */
		while (!feof(p) && fgetc(p) != '\n');
		while (!feof(p) && fgetc(p) != '\n');
		/* Loop over entries */
		while (fgets(line, sizeof(line), p)) {  // 匹配链中每条规则,清除用户自定义链中的规则
			/* Look for victim */
			if (strstr(line, victim)) {  // 2. 根据客户端IP地址进行匹配(删除该IP的所有规则)
				/* Found victim - Get the rule number into rulenum*/
				if (sscanf(line, "%9[0-9]", rulenum) == 1) { // 获取该规则的序号 => @rulenum
					/* Delete the rule: */
					debug(LOG_DEBUG, "Deleting rule %s from %s.%s because it mentions %s", rulenum, table, chain, victim);
					safe_asprintf(&command2, "-t %s -D %s %s", table, chain, rulenum); // 删除序号为@rulenum的规则
					iptables_do_command(command2);
					free(command2);
					deleted = 1;
					/* Do not keep looping - the captured rulenums will no longer be accurate */
					break;
				}
			}
		}
		pclose(p);
	}

	free(command);
	free(victim);

	if (deleted) {
		/* Recurse just in case there are more in the same table+chain */
		iptables_fw_destroy_mention(table, chain, mention);
	}

	return (deleted);
}

#define WCLIENT_CONF  "/tmp/wifidog_client.conf"
// add by lijg , 2013-08-13, called by client authen success
// save validiated client info to config file /etc/wifidog_client.conf
void client_fwrule_save(const char *ip, const char *mac, const char *token)
{
	client_fwrule_clear(ip);  // delete the ip item avoiding repeated
	
	FILE *fp = NULL;
	if (NULL == (fp = fopen(WCLIENT_CONF, "a"))) { // Open  for appending (writing at end of file)
		return;
	}
	
	fprintf(fp, "%s %s %s\n", ip, mac, token);
	fclose(fp);
	debug(LOG_DEBUG, "save client %s %s %s", ip, mac, token);
}

// clear timeout's client info from /etc/wifidog_client.conf, delete firewall rule for  @ip
// /bin/sed -i '/192.168.1.11 /d'  /etc/wifidog_client.conf
void client_fwrule_clear(const char *ip)
{
	FILE *output = NULL;
	char cmd[128];
	snprintf(cmd, sizeof(cmd), "/bin/sed -i '/%s /d' %s", ip, WCLIENT_CONF);
	output = popen(cmd, "w");
	pclose(output);
	debug(LOG_DEBUG, "clear client %s ", ip);
}

void load_fwrule_conf(void)
{
	FILE *fp = NULL;
	char buff[128];
	int cnum = 0;
	char *ptr = NULL;
	char *ip = NULL; 
	char *mac = NULL;
	char *token = NULL;
	t_client	*client;

	if (NULL == (fp = fopen(WCLIENT_CONF, "r"))) {
		return ;
	}

	while (cnum < 256 && fgets(buff, sizeof(buff), fp) != NULL) {
		unsigned int len = strlen(buff);
		if (buff[len-1] == '\r' || buff[len-1] == '\n') {
			buff[len-1] = '\0';
		}

		ip = strtok_r(buff, " ", &ptr);
		if (!ip) continue;
		mac = strtok_r(NULL, " ", &ptr);
		if (!mac) continue;
		token = strtok_r(NULL, " ", &ptr);
		if (!token) continue;

		// alloc a client and append it to client list 
		if ((client = client_list_find_by_ip(ip)) == NULL) {
			client = client_list_append(ip, mac, token);
			client->fw_connection_state = FW_MARK_KNOWN;
			fw_allow(ip, mac, FW_MARK_KNOWN); 
			debug(LOG_DEBUG, "load client %s %s %s", ip, mac, token);
		}
		
		cnum ++;
	}

	fclose(fp);
}


/** Set if a specific client has access through the firewall */
	int
iptables_fw_access(fw_access_t type, const char *ip, const char *mac, int tag)
{
	int rc;

	fw_quiet = 0;

	// add by lijg, 2013-06-04,
	char tmpip[16];
	snprintf(tmpip, sizeof(tmpip), "%s ", ip);

	switch(type) {
		case FW_ACCESS_ALLOW:

			// add by lijg, 2013-05-18, 尝试删除重复添加的规则
			debug(LOG_DEBUG, "Attempt deleting firewall rules for (%s) in table %s", tmpip, TABLE_WIFIDOG_OUTGOING);
			iptables_fw_destroy_mention("mangle", TABLE_WIFIDOG_OUTGOING, tmpip);
			debug(LOG_DEBUG, "Attempt deleting firewall rules for (%s) in table %s", tmpip, TABLE_WIFIDOG_INCOMING);
			iptables_fw_destroy_mention("mangle", TABLE_WIFIDOG_INCOMING, tmpip);

			// modified by lijg, 2013-05-17, 取消打标记
			iptables_do_command("-t mangle -A " TABLE_WIFIDOG_OUTGOING " -s %s -m mac --mac-source %s -j MARK --or-mark %d", ip, mac, tag);
			rc = iptables_do_command("-t mangle -A " TABLE_WIFIDOG_INCOMING " -d %s -j ACCEPT", ip);
			break;
		case FW_ACCESS_DENY:
			// modified by lijg, 2013-05-17, 取消打标记
			debug(LOG_DEBUG, "Attempt S deleting firewall rules for (%s) in table %s", tmpip, TABLE_WIFIDOG_OUTGOING);
			iptables_fw_destroy_mention("mangle", TABLE_WIFIDOG_OUTGOING, tmpip);
			debug(LOG_DEBUG, "Attempt S deleting firewall rules for (%s) in table %s", tmpip, TABLE_WIFIDOG_INCOMING);
			iptables_fw_destroy_mention("mangle", TABLE_WIFIDOG_INCOMING, tmpip);
			rc = 0;
			break;
		default:
			rc = -1;
			break;
	}

	return rc;
}

/** Update the counters of all the clients in the client list */
	int
iptables_fw_counters_update(void)
{
	FILE *output;
	char *script,
	     ip[16],
	     rc;
	unsigned long long int counter;
	t_client *p1;
	struct in_addr tempaddr;

	debug(LOG_DEBUG, "begin iptables_fw_counters_update");

	/* Look for outgoing traffic */
	// modified by lijg , 2013-05-18, 修改获取上行流量
	safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " TABLE_WIFIDOG_OUTGOING);
	iptables_insert_gateway_id(&script);
	output = popen(script, "r");
	free(script);
	if (!output) {
		debug(LOG_ERR, "popen(): %s", strerror(errno));
		return -1;
	}

	/* skip the first two lines */
	while (('\n' != fgetc(output)) && !feof(output))
		;
	while (('\n' != fgetc(output)) && !feof(output))
		;
	while (output && !(feof(output))) {
		rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %15[0-9.] %*s %*s %*s %*s %*s %*s", &counter, ip);
		//rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %15[0-9.] %*s %*s %*s %*s %*s 0x%*u", &counter, ip);
		//debug(LOG_DEBUG, "outgoing >> %s -- %llu  (%u)", ip, counter, rc);
		if (2 == rc && EOF != rc) {
			/* Sanity*/
			if (!inet_aton(ip, &tempaddr)) {
				debug(LOG_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
				continue;
			}
			debug(LOG_DEBUG, "Read outgoing traffic for %s: Bytes=%llu", ip, counter);
			LOCK_CLIENT_LIST();
			if ((p1 = client_list_find_by_ip(ip))) {
				if ((p1->counters.outgoing - p1->counters.outgoing_history) < counter) {
					p1->counters.outgoing = p1->counters.outgoing_history + counter;
					p1->counters.last_updated = time(NULL);
					debug(LOG_DEBUG, "%s - Updated counter.outgoing to %llu bytes.  Updated last_updated to %d", ip, counter, p1->counters.last_updated);
				}
			} else {
				debug(LOG_ERR, "iptables_fw_counters_update(): Could not find %s in client list, this should not happen unless if the gateway crashed", ip);

				debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, TABLE_WIFIDOG_OUTGOING);
				iptables_fw_destroy_mention("mangle", TABLE_WIFIDOG_OUTGOING, ip);
				debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, TABLE_WIFIDOG_INCOMING);
				iptables_fw_destroy_mention("mangle", TABLE_WIFIDOG_INCOMING, ip);
			}
			UNLOCK_CLIENT_LIST();
		}
	}
	pclose(output);

	/* Look for incoming traffic */
	safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " TABLE_WIFIDOG_INCOMING);
	iptables_insert_gateway_id(&script);
	output = popen(script, "r");
	free(script);
	if (!output) {
		debug(LOG_ERR, "popen(): %s", strerror(errno));
		return -1;
	}

	/* skip the first two lines */
	while (('\n' != fgetc(output)) && !feof(output))
		;
	while (('\n' != fgetc(output)) && !feof(output))
		;
	while (output && !(feof(output))) {
		rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %*s %15[0-9.]", &counter, ip);
		if (2 == rc && EOF != rc) {
			/* Sanity*/
			if (!inet_aton(ip, &tempaddr)) {
				debug(LOG_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
				continue;
			}
			debug(LOG_DEBUG, "Read incoming traffic for %s: Bytes=%llu", ip, counter);
			LOCK_CLIENT_LIST();
			if ((p1 = client_list_find_by_ip(ip))) {
				if ((p1->counters.incoming - p1->counters.incoming_history) < counter) {
					p1->counters.incoming = p1->counters.incoming_history + counter;
					debug(LOG_DEBUG, "%s - Updated counter.incoming to %llu bytes", ip, counter);
				}
			} else {
				debug(LOG_ERR, "iptables_fw_counters_update(): Could not find %s in client list, this should not happen unless if the gateway crashed", ip);

				debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, TABLE_WIFIDOG_OUTGOING);
				iptables_fw_destroy_mention("mangle", TABLE_WIFIDOG_OUTGOING, ip);
				debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, TABLE_WIFIDOG_INCOMING);
				iptables_fw_destroy_mention("mangle", TABLE_WIFIDOG_INCOMING, ip);
			}
			UNLOCK_CLIENT_LIST();
		}
	}
	pclose(output);

	debug(LOG_DEBUG, "end iptables_fw_counters_update\n\n");

	return 1;
}
