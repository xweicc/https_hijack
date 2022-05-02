
#ifndef __MAIN_H__
#define __MAIN_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h> 
#include <ctype.h>
#include <list.h>
#include <timer.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define SESSION_MAX_NUM 10240
#define SESSION_HLIST_MASK 0xFFFF
#define SESSION_HLIST_SIZE 0x10000
#define SESSION_TIMEOUT 60
#define SSL_MAX_MSS	16384		//2^14
#define DATA_BUF_LEN (SSL_MAX_MSS*2)


#define HTTPS_CA_CRT      "./ca.crt"
#define HTTPS_SERVER_KEY  "./server.key"
#define HTTPS_SERVER_CRT  "./server.crt"

enum CT_STATE{
	CT_STATE_INIT=0,
	CT_STATE_SUCCESS,
	CT_STATE_SERVER_CLOSE,
};

enum SESSION_STATE{
	SESSION_STATE_NONE,
	SESSION_STATE_CONNECTING,
	SESSION_STATE_CONNECTED,
};

enum DATA_FROM{
	DATA_FROM_SERVER=0,
	DATA_FROM_CLIENT,
};


struct httpssGlobalVariable{
	struct pollfd pollArray[SESSION_MAX_NUM];
	struct list_head sessionHead;
	struct hlist_head clientSockHlistHead[SESSION_HLIST_SIZE];
	struct hlist_head serverSockHlistHead[SESSION_HLIST_SIZE];
	int sock;
	int pollUsedNum;
	unsigned short proxyServerPort;
	int debug;
	
	SSL_CTX *sslServerCtx;
	SSL_CTX *sslClientCtx;
	unsigned long long rxBytes;
	unsigned long long txBytes;
	unsigned long long rxBytesPrev;
	unsigned long long txBytesPrev;
	struct timer_list speedTimer;
};

typedef struct{
	struct list_head list;					//list to sessionHead
	struct hlist_node hashToClientSock;		//hash to clientSockHlistHead
	struct hlist_node hashToServerSock;		//hash to serverSockHlistHead
	struct timer_list timer;				//session超时的timer
	struct in_addr ipaddr;					//服务器地址
	struct sockaddr_in serverAddr;			//服务器地址
	SSL* clientSsl;							//与客户端通信的SSL
	SSL* serverSsl;							//与服务器通信的SSL
	int serverSock;							//与服务器通信的socket
	int clientSock;							//与客户端通信的socket
	int from;								//应该从服务器还是客户端接收数据
	int serverSockPollId;					//server socket 在poll里的ID
	int clientSockPollId;					//client socket 在poll里的ID
	char *serverBuf;						//从服务器收到的数据
	char *clientBuf;						//从客户端收到的数据
	int serverBufUsed;						//serverBuf 已使用的长度
	int clientBufUsed;						//clientBuf 已使用的长度
	int serverBufSize;						//serverBuf 总大小
	unsigned short port;					//服务器的端口
	unsigned short ctState;					//session的状态 enum CT_STATE
	int state;								//连接服务器的状态 enum SESSION_STATE
	int sslAccept;							//SSL_accept 是否完成
	int sslConnect;							//SSL_connect 是否完成
	FILE *fp;								//写文件的fd
	char host[64];							//服务器域名
}httpsSession;


#define Printf(format,args...) do{if(httpss.debug>1)printf("[%s:%d]:"format,__FUNCTION__,__LINE__,##args);}while(0)
#define Perror(format,args...) do{if(httpss.debug){printf("Error:[%s:%d]:"format". error info: ",__FUNCTION__,__LINE__,##args);fflush(stdout);perror("");}}while(0)


//内联函数定义
static inline void *memMalloc(int size)
{
	void *p=malloc(size);
	if(p){
		memset(p, 0, size);
	}
	return p;
}
static inline void memFree(void *buf)
{
	if(buf){
		free(buf);
	}
}

static inline int checkErrno(int errNo)
{
	if(errNo==EINTR || errNo==EAGAIN || errNo==EINPROGRESS || errNo==EWOULDBLOCK || errNo==EALREADY || errNo==ERESTART || errNo==0){
		return 0;	//非阻塞socket，这些errno可以继续执行
	}else{
		return 1;
	}
}

int sendDataToServer(httpsSession *ss);


#endif
