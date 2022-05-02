
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
	struct timer_list timer;				//session��ʱ��timer
	struct in_addr ipaddr;					//��������ַ
	struct sockaddr_in serverAddr;			//��������ַ
	SSL* clientSsl;							//��ͻ���ͨ�ŵ�SSL
	SSL* serverSsl;							//�������ͨ�ŵ�SSL
	int serverSock;							//�������ͨ�ŵ�socket
	int clientSock;							//��ͻ���ͨ�ŵ�socket
	int from;								//Ӧ�ôӷ��������ǿͻ��˽�������
	int serverSockPollId;					//server socket ��poll���ID
	int clientSockPollId;					//client socket ��poll���ID
	char *serverBuf;						//�ӷ������յ�������
	char *clientBuf;						//�ӿͻ����յ�������
	int serverBufUsed;						//serverBuf ��ʹ�õĳ���
	int clientBufUsed;						//clientBuf ��ʹ�õĳ���
	int serverBufSize;						//serverBuf �ܴ�С
	unsigned short port;					//�������Ķ˿�
	unsigned short ctState;					//session��״̬ enum CT_STATE
	int state;								//���ӷ�������״̬ enum SESSION_STATE
	int sslAccept;							//SSL_accept �Ƿ����
	int sslConnect;							//SSL_connect �Ƿ����
	FILE *fp;								//д�ļ���fd
	char host[64];							//����������
}httpsSession;


#define Printf(format,args...) do{if(httpss.debug>1)printf("[%s:%d]:"format,__FUNCTION__,__LINE__,##args);}while(0)
#define Perror(format,args...) do{if(httpss.debug){printf("Error:[%s:%d]:"format". error info: ",__FUNCTION__,__LINE__,##args);fflush(stdout);perror("");}}while(0)


//������������
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
		return 0;	//������socket����Щerrno���Լ���ִ��
	}else{
		return 1;
	}
}

int sendDataToServer(httpsSession *ss);


#endif
