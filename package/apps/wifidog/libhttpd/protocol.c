/*
** Copyright (c) 2002  Hughes Technologies Pty Ltd.  All rights
** reserved.
**
** Terms under which this software may be used or copied are
** provided in the  specific license associated with this product.
**
** Hughes Technologies disclaims all warranties with regard to this
** software, including all implied warranties of merchantability and
** fitness, in no event shall Hughes Technologies be liable for any
** special, indirect or consequential damages or any damages whatsoever
** resulting from loss of use, data or profits, whether in an action of
** contract, negligence or other tortious action, arising out of or in
** connection with the use or performance of this software.
**
**
** $Id: protocol.c 1429 2009-11-04 14:21:07Z gbastien $
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#if defined(_WIN32)
#else
#include <unistd.h>
#include <sys/file.h>
#endif

#include "config.h"
#include "httpd.h"
#include "httpd_priv.h"

int _httpd_net_read(sock, buf, len)
	int	sock;
	char	*buf;
	int	len;
{
#if defined(_WIN32)
	return( recv(sock, buf, len, 0));
#else
	/*return( read(sock, buf, len));*/
	/* XXX Select based IO */

	int		nfds;
	fd_set		readfds;
	struct timeval	timeout;

	FD_ZERO(&readfds);
	FD_SET(sock, &readfds);
	timeout.tv_sec = 3;  // modified by lijg, 2013-06-24, cut down timeout
	timeout.tv_usec = 0;
	nfds = sock + 1;

	nfds = select(nfds, &readfds, NULL, NULL, &timeout);

	if (nfds > 0) {
		return(read(sock, buf, len));
	}
	return(nfds);
#endif
}


int _httpd_net_write(sock, buf, len)
	int	sock;
	char	*buf;
	int	len;
{
#if defined(_WIN32)
	return( send(sock, buf, len, 0));
#else
	return( write(sock, buf, len));
#endif
}

// reads the next character from @r->readBuf[]
// @return -- 0 : read none , read EOF;  1 : read a character ;
int _httpd_readChar(request *r, char *cp)
{
	if (r->readBufRemain == 0)
	{
		bzero(r->readBuf, HTTP_READ_BUF_LEN + 1);
		r->readBufRemain = _httpd_net_read(r->clientSock,
			r->readBuf, HTTP_READ_BUF_LEN);
		if (r->readBufRemain < 1)
			return(0);
		r->readBuf[r->readBufRemain] = 0;
		r->readBufPtr = r->readBuf;
	}
	*cp = *r->readBufPtr++;
	r->readBufRemain--;
	return(1);
}

// reads in at most one less than @len characters from @r->readBufPtr[] , and stores them into the buffer pointed to by @destBuf
// If a newline ('\n') is read, A terminating null byte ('\0') is stored after the last character in the buffer.
// called by httpdReadRequest() , read a line data from http client
int _httpd_readLine(request *r, char *destBuf, int len)
{
	char	curChar,
		*dst;
	int	count;


	count = 0;
	dst = destBuf;
	while(count < len)
	{
		if (_httpd_readChar(r, &curChar) < 1) {
			*dst = 0;  // add by lijg, 2013-06-26, safing string
			return(0);
		}
		// Fixed by Mina - if we read binary junk it's probably not a regular HTTP client
		//if (curChar == '\n')
		if (curChar == '\n' || !isascii(curChar))
		{
			*dst = 0;
			return(1);
		}
		if (curChar == '\r')
		{
			continue;
		}
		else
		{
			*dst++ = curChar;
			count++;
		}
	}
	*dst = 0;
	return(1);
}


int _httpd_readBuf(request *r, char *destBuf, int len)
{
	char	curChar,
		*dst;
	int	count;


	count = 0;
	dst = destBuf;
	while(count < len)
	{
		if (_httpd_readChar(r, &curChar) < 1)
			return(0);
		*dst++ = curChar;
		count++;
	}
	return(1);
}

void _httpd_writeAccessLog(httpd *server, request *r)
{
	char	dateBuf[30];
	struct 	tm *timePtr;
	time_t	clock;
	int	responseCode;


	if (server->accessLog == NULL)
		return;
	clock = time(NULL);
	timePtr = localtime(&clock);
	strftime(dateBuf, 30, "%d/%b/%Y:%T %Z",  timePtr);
	responseCode = atoi(r->response.response);
	fprintf(server->accessLog, "%s - - [%s] %s \"%s\" %d %d\n",
		r->clientAddr, dateBuf, httpdRequestMethodName(r),
		httpdRequestPath(r), responseCode,
		r->response.responseLength);
}

void _httpd_writeErrorLog(httpd *server, request *r, char *level, char *message)
{
	char	dateBuf[30];
	struct 	tm *timePtr;
	time_t	clock;


	if (server->errorLog == NULL)
		return;
	clock = time(NULL);
	timePtr = localtime(&clock);
	strftime(dateBuf, 30, "%a %b %d %T %Y",  timePtr);
	if (r != NULL && *r->clientAddr != 0)
	{
		fprintf(server->errorLog, "[%s] [%s] [client %s] %s\n",
			dateBuf, level, r->clientAddr, message);
	}
	else
	{
		fprintf(server->errorLog, "[%s] [%s] %s\n",
			dateBuf, level, message);
	}
}



int _httpd_decode (bufcoded, bufplain, outbufsize)
	char *		bufcoded;
	char *		bufplain;
	int		outbufsize;
{
	static char six2pr[64] = {
    		'A','B','C','D','E','F','G','H','I','J','K','L','M',
    		'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    		'a','b','c','d','e','f','g','h','i','j','k','l','m',
    		'n','o','p','q','r','s','t','u','v','w','x','y','z',
    		'0','1','2','3','4','5','6','7','8','9','+','/'
	};

	static unsigned char pr2six[256];

	/* single character decode */
#	define DEC(c) pr2six[(int)c]
#	define _DECODE_MAXVAL 63

	static int first = 1;

	int nbytesdecoded, j;
	register char *bufin = bufcoded;
	register char *bufout = bufplain;
	register int nprbytes;

	/*
	** If this is the first call, initialize the mapping table.
	** This code should work even on non-ASCII machines.
	*/
	if(first)
	{
		first = 0;
		for(j=0; j<256; j++) pr2six[j] = _DECODE_MAXVAL+1;
		for(j=0; j<64; j++) pr2six[(int)six2pr[j]] = (unsigned char)j;
	}

   	/* Strip leading whitespace. */

   	while(*bufcoded==' ' || *bufcoded == '\t') bufcoded++;

	/*
	** Figure out how many characters are in the input buffer.
	** If this would decode into more bytes than would fit into
	** the output buffer, adjust the number of input bytes downwards.
	*/
	bufin = bufcoded;
	while(pr2six[(int)*(bufin++)] <= _DECODE_MAXVAL);
	nprbytes = bufin - bufcoded - 1;
	nbytesdecoded = ((nprbytes+3)/4) * 3;
	if(nbytesdecoded > outbufsize)
	{
		nprbytes = (outbufsize*4)/3;
	}
	bufin = bufcoded;

	while (nprbytes > 0)
	{
		*(bufout++)=(DEC(*bufin)<<2|DEC(bufin[1])>>4);
		*(bufout++)=(DEC(bufin[1])<<4|DEC(bufin[2])>>2);
		*(bufout++)=(DEC(bufin[2])<<6|DEC(bufin[3]));
		bufin += 4;
		nprbytes -= 4;
	}
	if(nprbytes & 03)
	{
		if(pr2six[(int)bufin[-2]] > _DECODE_MAXVAL)
		{
			nbytesdecoded -= 2;
		}
		else
		{
			nbytesdecoded -= 1;
		}
	}
	bufplain[nbytesdecoded] = 0;
	return(nbytesdecoded);
}



char _httpd_from_hex (c)
        char    c;
{
    return  c >= '0' && c <= '9' ?  c - '0'
            : c >= 'A' && c <= 'F'? c - 'A' + 10
            : c - 'a' + 10;     /* accept small letters just in case */
}

// unescape http url 
char * _httpd_unescape(str)
        char    *str;
{
    char * p = str;
    char * q = str;
    static char blank[] = "";

    if (!str)
        return(blank);
    while(*p) {
        if (*p == '%') {
            p++;
            if (*p) *q = _httpd_from_hex(*p++) * 16;
            if (*p) *q = (*q + _httpd_from_hex(*p++));
            q++;
        } else {
            if (*p == '+') {
                *q++ = ' ';
                p++;
            } else {
                *q++ = *p++;
              }
        }
    }

    *q++ = 0;
    return str;
}


void _httpd_freeVariables(var)
	httpVar	*var;
{
	httpVar	*curVar, *lastVar;

	if (var == NULL)
		return;
	_httpd_freeVariables(var->nextVariable);
	var->nextVariable = NULL;
	curVar = var;
	while(curVar)
	{
		lastVar = curVar;
		curVar = curVar->nextValue;
		//fprintf(stderr, "http release %s -- %s\n", lastVar->name, lastVar->value);
		free(lastVar->name);
		free(lastVar->value);
		free(lastVar);
	}
	return;
}

// called by httpdReadRequest(), store param such as "name=value1&name2=value2&..." into @r->variables list
void _httpd_storeData(request *r, char *query)
{
        char    *cp,
		*cp2,
                *var,
                *val,
		*tmpVal;

        if (!query)
                return;

	var = (char *)malloc(strlen(query)+1);  // modified by lijg, 2013-08-27, fixing it

	cp = query;
	cp2 = var;
        bzero(var, strlen(query));
	val = NULL;
        while(*cp)
        {
                if (*cp == '=')
                {
                        cp++;
			*cp2 = 0;
                        val = cp;
                        continue;
                }
                if (*cp == '&')
                {
			*cp = 0;
			tmpVal = _httpd_unescape(val);
			*cp2 = 0;  // add by lijg, 2013-08-27, fix it string
			httpdAddVariable(r, var, tmpVal);
                        cp++;
                        cp2 = var;
			val = NULL;
                        continue;
                }
		if (val)
		{
			cp++;
		}
		else
		{
                	*cp2 = *cp++;
            /*
			if (*cp2 == '.')
			{
				strcpy(cp2,"_dot_");
				cp2 += 5;
			}
			else
			{
            */
				cp2++;
            /*
			}
            */
		}
        }
    if (val != NULL) {
	    *cp = 0;
	    tmpVal = _httpd_unescape(val);
	    *cp2 = 0;  // add by lijg, 2013-08-27, fix it string
	    httpdAddVariable(r, var, tmpVal);
    }
	free(var);
}


void _httpd_formatTimeString(char *ptr, int clock)
{
	struct 	tm *timePtr;
	time_t t;

	t = (clock == 0) ? time(NULL) : clock;
	timePtr = gmtime(&t);
	strftime(ptr, HTTP_TIME_STRING_LEN,"%a, %d %b %Y %T GMT",timePtr);
}


void _httpd_sendHeaders(request *r, int contentLength, int modTime)
{
	char	tmpBuf[80],
		timeBuf[HTTP_TIME_STRING_LEN];

	if(r->response.headersSent)
		return;

	r->response.headersSent = 1;
	_httpd_net_write(r->clientSock, "HTTP/1.0 ", 9);
	_httpd_net_write(r->clientSock, r->response.response,
		strlen(r->response.response));
	_httpd_net_write(r->clientSock, r->response.headers,
		strlen(r->response.headers));

	_httpd_formatTimeString(timeBuf, 0);
	_httpd_net_write(r->clientSock,"Date: ", 6);
	_httpd_net_write(r->clientSock, timeBuf, strlen(timeBuf));
	_httpd_net_write(r->clientSock, "\r\n", 2);

	_httpd_net_write(r->clientSock, "Connection: close\r\n", 19);
	_httpd_net_write(r->clientSock, "Content-Type: ", 14);
	_httpd_net_write(r->clientSock, r->response.contentType,
		strlen(r->response.contentType));
	_httpd_net_write(r->clientSock, "\r\n", 2);

	if (contentLength > 0)
	{
		_httpd_net_write(r->clientSock, "Content-Length: ", 16);
		snprintf(tmpBuf, sizeof(tmpBuf), "%d", contentLength);
		_httpd_net_write(r->clientSock, tmpBuf, strlen(tmpBuf));
		_httpd_net_write(r->clientSock, "\r\n", 2);

		if (modTime > 0) {
			_httpd_formatTimeString(timeBuf, modTime);
			_httpd_net_write(r->clientSock, "Last-Modified: ", 15);
			_httpd_net_write(r->clientSock, timeBuf, strlen(timeBuf));
			_httpd_net_write(r->clientSock, "\r\n", 2);
		}
	}
	_httpd_net_write(r->clientSock, "\r\n", 2);
}

// @dir = "/" OR "/v3" OR "/wifidog/" OR "/ad/302"
httpDir *_httpd_findContentDir(server, dir, createFlag)
	httpd	*server;
	char	*dir;
	int	createFlag;
{
	char	buffer[HTTP_MAX_URL],
		*curDir;
	httpDir	*curItem,
		*curChild;

	char *ptr = NULL;  // add by lijg, 2013-08-19 

	strncpy(buffer, dir, HTTP_MAX_URL);
        buffer[HTTP_MAX_URL-1]=0;
	curItem = server->content;
	curDir = strtok_r(buffer, "/", &ptr); //modified by lijg, 2013-08-19 , k thread safe
	while(curDir)
	{
		curChild = curItem->children;
		while(curChild)
		{
			if (strcmp(curChild->name, curDir) == 0)
				break;
			curChild = curChild->next;
		}
		if (curChild == NULL)
		{
			if (createFlag == HTTP_TRUE)
			{
				curChild = malloc(sizeof(httpDir));
				bzero(curChild, sizeof(httpDir));
				curChild->name = strdup(curDir);
				curChild->next = curItem->children;
				curItem->children = curChild;
			}
			else
			{
				return(NULL);
			}
		}
		curItem = curChild;
		curDir = strtok_r(NULL, "/", &ptr); //modified by lijg, 2013-08-19 , k thread safe
	}
	return(curItem);
}


httpContent *_httpd_findContentEntry(request *r, httpDir *dir, char *entryName)
{
	httpContent *curEntry;

	curEntry = dir->entries;
	while(curEntry)
	{
		if (curEntry->type == HTTP_WILDCARD ||
		    curEntry->type ==HTTP_C_WILDCARD)
			break;
		if (*entryName == 0 && curEntry->indexFlag)
			break;
		if (strcmp(curEntry->name, entryName) == 0)
			break;
		curEntry = curEntry->next;
	}
	if (curEntry)
		r->response.content = curEntry;
	return(curEntry);
}


void _httpd_send304(request *r)
{
	httpdSetResponse(r, "304 Not Modified\n");
	_httpd_sendHeaders(r,0,0);
}


void _httpd_send403(request *r)
{
	httpdSetResponse(r, "403 Permission Denied\n");
	_httpd_sendHeaders(r,0,0);
	_httpd_sendText(r,
		"<HTML><HEAD><TITLE>403 Permission Denied</TITLE></HEAD>\n");
	_httpd_sendText(r,
		"<BODY><H1>Access to the request URL was denied!</H1>\n");
}

#include "gap_mclist.h"

static LIST_HEAD(acl_list);
pthread_mutex_t acl_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static int acl_num = 0;

struct ip_acl {
	struct list_head n;
	char cip[16];
	char host[48];
	char url[512];
	//time_t lasttime;
	unsigned int accnum;
};

// 一分钟最多访问的次数
#define MAX_ACCNUM  8

int filter_ip_acl(request *r)
{
	struct ip_acl *acl, *tmp;
	pthread_mutex_lock(&acl_list_mutex);
	list_for_each_entry_safe(acl, tmp, &acl_list, n) {
		if (0 == strcmp(acl->cip, r->clientAddr) && 
			strncasecmp(acl->url, httpdRequestPath(r), sizeof(acl->url)-1) == 0 && 
			strncasecmp(acl->host, r->request.host, sizeof(acl->host)-1) == 0) {  // 匹配到
			if (acl->accnum < MAX_ACCNUM) {
				acl->accnum ++;
			} else {
				acl->accnum ++;
				pthread_mutex_unlock(&acl_list_mutex);
				fprintf(stderr, "ip url deny %s %s %u\n", acl->cip, httpdRequestPath(r), acl->accnum);
				return -1;
			}

			fprintf(stderr, "ip url pass %s %s %u\n", acl->cip, httpdRequestPath(r), acl->accnum);
			list_move(&acl->n, &acl_list);  // 删除添加到链表头
			pthread_mutex_unlock(&acl_list_mutex);
			return 0;
		}
	}

	// 没有匹配到,新增一个节点
	if (acl_num >= 256) {
		pthread_mutex_unlock(&acl_list_mutex);
		fprintf(stderr, "acl ip list number %d, overlimit\n", acl_num);
		return 0;
	}
	acl = (struct ip_acl *)malloc(sizeof(struct ip_acl));
	strncpy(acl->cip, r->clientAddr, sizeof(acl->cip)-1);
	acl->cip[sizeof(acl->cip)-1] = 0;
	strncpy(acl->host, r->request.host, sizeof(acl->host)-1);
	acl->host[sizeof(acl->host)-1] = 0;
	strncpy(acl->url, httpdRequestPath(r), sizeof(acl->url)-1);
	acl->url[sizeof(acl->url)-1] = 0;
	acl->accnum = 1;
	list_add(&acl->n, &acl_list);  // 添加到链表头
	acl_num ++;
	pthread_mutex_unlock(&acl_list_mutex);
	return 0;
}

void clean_acl_list_timeout(void)
{
	struct ip_acl *acl, *tmp;
	pthread_mutex_lock(&acl_list_mutex);
	list_for_each_entry_safe(acl, tmp, &acl_list, n) {
		list_del(&acl->n);
		free(acl);
	}
	acl_num = 0;
	pthread_mutex_unlock(&acl_list_mutex);
}

// called by httpdProcessRequest(), 澶勭悊涓�涓湭鐭ATH鐨刪ttp璇锋眰
void _httpd_send404(httpd *server, request *r)
{
	//char	msg[HTTP_MAX_URL];

	//snprintf(msg, HTTP_MAX_URL,
	//	"File does not exist: %s\n", r->request.path);
	//_httpd_writeErrorLog(server, r, LEVEL_ERROR, msg);
	//fprintf(stdout, "call _httpd_send404 \n");

	// add by lijg, 2013-12-31, 过滤重复的url && IP (一段时间内)
	if (filter_ip_acl(r) ) {
		return;
	}

	if (server->handle404 && server->handle404->function) {
		/*
		 * There's a custom C 404 handler defined with httpdAddC404Content
		 */
		(server->handle404->function)(server, r);  // call http_callback_404()
	}
	else {
		/*
		 * Send stock 404
		 */
		httpdSetResponse(r, "404 Not Found\n");
		_httpd_sendHeaders(r,0,0);
		_httpd_sendText(r,
			"<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD>\n");
		_httpd_sendText(r,
			"<BODY><H1>The request URL was not found!</H1>\n");
		_httpd_sendText(r, "</BODY></HTML>\n");
	}
}


void _httpd_catFile(request *r, char *path)
{
	int	fd,
		len;
	char	buf[HTTP_MAX_LEN];

	fd = open(path,O_RDONLY);
	if (fd < 0)
		return;
	len = read(fd, buf, HTTP_MAX_LEN);
	while(len > 0)
	{
		r->response.responseLength += len;
		_httpd_net_write(r->clientSock, buf, len);
		len = read(fd, buf, HTTP_MAX_LEN);
	}
	close(fd);
}


void _httpd_sendStatic(httpd *server, request *r, char *data)
{
	if (_httpd_checkLastModified(r, server->startTime) == 0)
	{
		_httpd_send304(r);
	}
	_httpd_sendHeaders(r, server->startTime, strlen(data));
	httpdOutput(r, data);
}



void _httpd_sendFile(httpd *server, request *r, char *path)
{
	char	*suffix;
	struct 	stat sbuf;

	suffix = strrchr(path, '.');
	if (suffix != NULL)
	{
		if (strcasecmp(suffix,".gif") == 0)
			strcpy(r->response.contentType,"image/gif");
		if (strcasecmp(suffix,".jpg") == 0)
			strcpy(r->response.contentType,"image/jpeg");
		if (strcasecmp(suffix,".xbm") == 0)
			strcpy(r->response.contentType,"image/xbm");
		if (strcasecmp(suffix,".png") == 0)
			strcpy(r->response.contentType,"image/png");
	}
	if (stat(path, &sbuf) < 0)
	{
		_httpd_send404(server, r);
		return;
	}
	if (_httpd_checkLastModified(r, sbuf.st_mtime) == 0)
	{
		_httpd_send304(r);
	}
	else
	{
		_httpd_sendHeaders(r, sbuf.st_size, sbuf.st_mtime);
		_httpd_catFile(r, path);
	}
}


int _httpd_sendDirectoryEntry(httpd *server, request *r, httpContent *entry,
		char *entryName)
{
	char		path[HTTP_MAX_URL];

	snprintf(path, HTTP_MAX_URL, "%s/%s", entry->path, entryName);
	_httpd_sendFile(server, r, path);
	return(0);
}


void _httpd_sendText(request *r, char *msg)
{
	r->response.responseLength += strlen(msg);
	_httpd_net_write(r->clientSock,msg,strlen(msg));
}


int _httpd_checkLastModified(request *r, int modTime)
{
	char 	timeBuf[HTTP_TIME_STRING_LEN];

	_httpd_formatTimeString(timeBuf, modTime);
	if (strcmp(timeBuf, r->request.ifModified) == 0)
		return(0);
	return(1);
}


static unsigned char isAcceptable[96] =

/* Overencodes */
#define URL_XALPHAS     (unsigned char) 1
#define URL_XPALPHAS    (unsigned char) 2

/*      Bit 0           xalpha          -- see HTFile.h
**      Bit 1           xpalpha         -- as xalpha but with plus.
**      Bit 2 ...       path            -- as xpalpha but with /
*/
    /*   0 1 2 3 4 5 6 7 8 9 A B C D E F */
    {    7,0,0,0,0,0,0,0,0,0,7,0,0,7,7,7,       /* 2x   !"#$%&'()*+,-./ */
         7,7,7,7,7,7,7,7,7,7,0,0,0,0,0,0,       /* 3x  0123456789:;<=>?  */
         7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,       /* 4x  @ABCDEFGHIJKLMNO */
         7,7,7,7,7,7,7,7,7,7,7,0,0,0,0,7,       /* 5X  PQRSTUVWXYZ[\]^_ */
         0,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,       /* 6x  `abcdefghijklmno */
         7,7,7,7,7,7,7,7,7,7,7,0,0,0,0,0 };     /* 7X  pqrstuvwxyz{\}~ DEL */

#define ACCEPTABLE(a)   ( a>=32 && a<128 && ((isAcceptable[a-32]) & mask))

static char *hex = "0123456789ABCDEF";


char *_httpd_escape(str)
        const char *str;
{
    unsigned char mask = URL_XPALPHAS;
    const char * p;
    char * q;
    char * result;
    int unacceptable = 0;
    for(p=str; *p; p++)
        if (!ACCEPTABLE((unsigned char)*p))
                unacceptable +=2;
    result = (char *) malloc(p-str + unacceptable + 1 + 4); // modified by lijg, 2013-08-19, fix it
    bzero(result,(p-str + unacceptable + 1));

    if (result == NULL)
    {
	return(NULL);
    }
    for(q=result, p=str; *p; p++) {
        unsigned char a = *p;
        if (!ACCEPTABLE(a)) {
            *q++ = '%';  /* Means hex commming */
            *q++ = hex[a >> 4];
            *q++ = hex[a & 15];
        }
        else *q++ = *p;
    }
    *q++ = 0;                   /* Terminate */
    return result;
}


// called by httpdReadRequest(), 
// @url = "/servlet/MaintainServlet"
// @url = "/v3/safeup_miniup.cab?autoupdate=true&pid=softmgr&uid=1&ver=8.6.0.2002&sysver=5.1.2600.256.1.3"
void _httpd_sanitiseUrl(url)
	char	*url;
{
	char	*from,
		*to,
		*last;

	/*
	** Remove multiple slashes
	*/ // "//" ==> "/"
	from = to = url;
	while(*from)
	{
		if (*from == '/' && *(from+1) == '/')
		{
			from++;
			continue;
		}
		*to = *from;
		to++;
		from++;
	}
	*to = 0;


	/*
	** Get rid of ./ sequences
	*/
	from = to = url;
	while(*from)
	{
		if (*from == '/' && *(from+1) == '.' && *(from+2)=='/')
		{
			from += 2;
			continue;
		}
		*to = *from;
		to++;
		from++;
	}
	*to = 0;


	/*
	** Catch use of /../ sequences and remove them.  Must track the
	** path structure and remove the previous path element.
	*/
	from = to = last = url;
	while(*from)
	{
		if (*from == '/' && *(from+1) == '.' &&
			*(from+2)=='.' && *(from+3)=='/')
		{
			to = last;
			from += 3;
			continue;
		}
		if (*from == '/')
		{
			last = to;
		}
		*to = *from;
		to++;
		from++;
	}
	*to = 0;
}
