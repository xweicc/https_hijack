
#include <main.h>

struct httpssGlobalVariable httpss;


static void signalHandler(int signo)
{
	Printf("signo=%d\n",signo);
	exit(0);
}

void initSignalHandler(void)
{
	struct sigaction sa;

	memset(&sa,0,sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, 0);
	signal(SIGINT, signalHandler);
	signal(SIGTERM, signalHandler);
	signal(SIGHUP, SIG_IGN);
}

int initList()
{
	int i=0;

	for(i=0;i<SESSION_HLIST_SIZE;i++){
		INIT_HLIST_HEAD(&httpss.clientSockHlistHead[i]);
	}
	for(i=0;i<SESSION_HLIST_SIZE;i++){
		INIT_HLIST_HEAD(&httpss.serverSockHlistHead[i]);
	}
	INIT_LIST_HEAD(&httpss.sessionHead);
	
	return 0;
}

void initPoll()
{
	int i=0;
	for(i=0;i<SESSION_MAX_NUM;i++){
		httpss.pollArray[i].fd=-1;
	}
}

unsigned int Gethostbyname(const char *host)
{
	struct hostent *he;

	he = gethostbyname(host);
	if(!he){
		return 0;
	}
    
	if(he->h_addrtype == AF_INET){
		return *((unsigned int *)he->h_addr);
	}

    return 0;
}


/*
	示例: 输入123456789, 返回117.75 M
*/
char *transByte(unsigned long long byte)
{
	unsigned long long tmp;
	int Gbyte=0,Mbyte=0,Kbyte=0,Byte=0;
	static char str[64]={0};
	int len=0;

	if(byte>1023){
		tmp=byte;
		Byte=tmp%1024;
		Kbyte=(tmp-Byte)/1024;
		if(Kbyte>1023){
			tmp=Kbyte;
			Kbyte=tmp%1024;
			Mbyte=(tmp-Kbyte)/1024;
			if(Mbyte>1023){
				tmp=Mbyte;
				Mbyte=tmp%1024;
				Gbyte=(tmp-Mbyte)/1024;
			}
		}
	}else{
		Byte=(typeof(Byte))byte;
	}
	if(Gbyte){
		len+=snprintf(str+len, sizeof(str)-len, "%d.%02d G", Gbyte, Mbyte/10>99?99:Mbyte/10);
		return str;
	}
	if(Mbyte){
		len+=snprintf(str+len, sizeof(str)-len, "%d.%02d M", Mbyte, Kbyte/10>99?99:Kbyte/10);
		return str;
	}
	if(Kbyte){
		len+=snprintf(str+len, sizeof(str)-len, "%d.%02d K", Kbyte, Byte/10>99?99:Byte/10);
		return str;
	}

	len+=snprintf(str+len, sizeof(str)-len, "%d B", Byte);
	return str;
}


void speedTimerRun(unsigned long data)
{
	unsigned long long txSpeed, rxSpeed;

	txSpeed=httpss.txBytes-httpss.txBytesPrev;
	rxSpeed=httpss.rxBytes-httpss.rxBytesPrev;
	httpss.txBytesPrev=httpss.txBytes;
	httpss.rxBytesPrev=httpss.rxBytes;

	mod_timer(&httpss.speedTimer, jiffies+1*HZ);
	
	printf("  send:%s ",transByte(httpss.txBytes));
	printf("recv:%s ",transByte(httpss.rxBytes));
	printf("upSpeed:%s/S ",transByte(txSpeed));
	printf("downSpeed:%s/S",transByte(rxSpeed));
	printf("             \r");
	fflush(stdout);
}

void initSpeedTimer()
{
	setup_timer(&httpss.speedTimer, speedTimerRun, 0);
#ifdef SHOW_SPEED
	mod_timer(&httpss.speedTimer, jiffies+1*HZ);
#endif
}


int httpsServerSslInit(void)
{
	//SSL库初始化
	SSL_library_init();

	//载入SSL错误消息
	SSL_load_error_strings();

	//加载加密算法
	OpenSSL_add_all_algorithms();

	//创建会话环境
	httpss.sslServerCtx = SSL_CTX_new(SSLv23_server_method());
	if(httpss.sslServerCtx == NULL){
		ERR_print_errors_fp(stderr);
		printf("SSL_CTX_new failed!\n");
		return -1;
	}

	//客户端证书验证方式:不验证
	SSL_CTX_set_verify(httpss.sslServerCtx,SSL_VERIFY_NONE,NULL);

	//加载CA证书
	SSL_CTX_load_verify_locations(httpss.sslServerCtx,HTTPS_CA_CRT,NULL);

	//设置SSL要加载的证书的口令
	SSL_CTX_set_default_passwd_cb_userdata(httpss.sslServerCtx, (void*)"123456");

	//载入用户数字证书
	if(SSL_CTX_use_certificate_file(httpss.sslServerCtx, HTTPS_SERVER_CRT, SSL_FILETYPE_PEM)==0){
		ERR_print_errors_fp(stderr);
		printf("httpss SSL_CTX_use_certificate_file failed!\n");
		return -1;
	}

	//载入用户私钥
	if(SSL_CTX_use_PrivateKey_file(httpss.sslServerCtx, HTTPS_SERVER_KEY, SSL_FILETYPE_PEM)==0){	
		ERR_print_errors_fp(stderr);
		printf("httpss SSL_CTX_use_PrivateKey_file failed!\n");
		return -1;
	}

	//验证私钥和证书是否相符
	if(SSL_CTX_check_private_key(httpss.sslServerCtx)==0){
		ERR_print_errors_fp(stderr);
		printf("set httpss crt file failed!\n");
		return -1;
	}

	return 0;
}

int httpsClientSslInit(void)
{
	RAND_poll();
	while(RAND_status() == 0){
		unsigned short rand_ret = rand() % 65536;
		RAND_seed(&rand_ret, sizeof(rand_ret));
	}

	//创建会话环境
	httpss.sslClientCtx = SSL_CTX_new(SSLv23_client_method());
	if(!httpss.sslClientCtx){
        ERR_print_errors_fp(stderr);
		return -1;
    }

	return 0;
}

int setNonblock(int sockfd)
{
#if 1
    if(fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0)|O_NONBLOCK) == -1) {
        return -1;
    }
#endif
	return 0;
}

int setBlock(int sockfd)
{
    if(fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) & ~O_NONBLOCK) == -1) {
        return -1;
    }
	return 0;
}


int setrwtimeout(int sockfd, int sec, int usec)
{
	struct timeval tv;
	
	tv.tv_sec = sec;
	tv.tv_usec = usec;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	return 0;
}

int sockAddPoll(int sock)
{
	int i;
	
	for(i=0;i<SESSION_MAX_NUM;i++){
		if(httpss.pollArray[i].fd == -1){
			httpss.pollArray[i].fd=sock;
			break;
		}
	}
	if(i==SESSION_MAX_NUM){
		Printf("socket %d add poll false\n",sock);
		return -1;
	}
	httpss.pollArray[i].events = POLLIN;
	if (i >= httpss.pollUsedNum){
		httpss.pollUsedNum = i+1;
	}
	
	return i;
	
}


int httpsSeverInit(unsigned int ip, unsigned short port, int lisnum)
{
	int sock;
	int optval = 1;
	struct sockaddr_in my_addr;

	sock = socket(PF_INET, SOCK_STREAM, 0);

	if(sock == -1){
		perror("socket");
		return -1;
	} 

	setNonblock(sock);

	bzero(&my_addr, sizeof(my_addr));
	my_addr.sin_family = PF_INET;
	my_addr.sin_port = htons(port);
	my_addr.sin_addr.s_addr = htonl(ip);

	optval = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&optval, sizeof(optval));

	if(bind(sock, (struct sockaddr *) &my_addr, sizeof(struct sockaddr)) == -1){
		perror("bind");
		goto out;
	}
	if (listen(sock, lisnum) == -1) {
		perror("listen");
		return -1;
	}
	sockAddPoll(sock);
	httpss.sock=sock;

	return 0;
out:
	close(sock);
	return -1;
}


int initHttpss(void)
{
	srand(time(NULL));
	memset(&httpss,0,sizeof(httpss));

	jiffies_init();
	init_timers_cpu();
	initList();
	initPoll();
	initSignalHandler();
	initSpeedTimer();

	if(httpsServerSslInit()){
		Printf("httpsServerSslInit failed\n");
		goto out;
	}
	if(httpsClientSslInit()){
		Printf("httpsServerSslInit failed\n");
		goto out;
	}

	//初始化服务器监听Socket
	if(httpsSeverInit(INADDR_ANY, 443, SOMAXCONN)){
		Printf("https_sever_init failed\n");
		goto out;
	}

	
	return 0;
out:
	return -1;
}

void httpsSslConnClose(httpsSession *ss)
{
	if(ss->clientSsl){
		//SSL_shutdown(ss->clientSsl);
		//SSL_CTX_remove_session(httpss.sslServerCtx, ss->clientSsl->session);
		SSL_free(ss->clientSsl);
		ss->clientSsl = NULL;
	}
	if(ss->serverSsl){
		//SSL_shutdown(ss->serverSsl);
		//SSL_CTX_remove_session(httpss.sslClientCtx, ss->serverSsl->session);
		SSL_free(ss->serverSsl);
		ss->serverSsl = NULL;
	}
}

int httpsSessionDelete(httpsSession *ss)
{
	int i=0,pollUsedNum=0;
	
	httpsSslConnClose(ss);
	
	if(ss->serverSockPollId){
		close(httpss.pollArray[ss->serverSockPollId].fd);
		httpss.pollArray[ss->serverSockPollId].fd=-1;
	}
	if(ss->clientSockPollId){
		close(httpss.pollArray[ss->clientSockPollId].fd);
		httpss.pollArray[ss->clientSockPollId].fd=-1;
	}
	for(i=0;i<httpss.pollUsedNum && i<SESSION_MAX_NUM;i++){
		if(httpss.pollArray[i].fd>=0){
			pollUsedNum=i;
		}
	}
	httpss.pollUsedNum=pollUsedNum+1;//重置pollUsedNum
	Printf("httpss.pollUsedNum=%d\n",httpss.pollUsedNum);
	
	del_timer(&ss->timer);
	list_del(&ss->list);
	hlist_del(&ss->hashToClientSock);
	if(ss->serverSock){
		hlist_del(&ss->hashToServerSock);
	}
	if(ss->serverBuf){
		memFree(ss->serverBuf);
	}
	if(ss->clientBuf){
		memFree(ss->clientBuf);
	}
	if(ss->fp){
		fclose(ss->fp);
	}
	
	memFree(ss);

	Printf("httpsSessionDelete\n");
	return 0;
}


void SessionTimeout(unsigned long data)
{
	httpsSession *ss=(httpsSession *)data;

	Printf("SessionTimeout\n");
	httpsSessionDelete(ss);
}

/*关闭与服务器的连接*/
void httpsServerConnClose(httpsSession *ss)
{
	//SSL_CTX_remove_session(httpss.sslClientCtx, ss->serverSsl->session);
	SSL_free(ss->serverSsl);
	ss->serverSsl = NULL;
	close(ss->serverSock);
	httpss.pollArray[ss->serverSockPollId].fd=-1;
	ss->serverSockPollId=0;
	ss->ctState=CT_STATE_SERVER_CLOSE;
}


int httpsAccept(httpsSession* ss,int fd)
{
	int ret;

	ss->clientSsl = SSL_new(httpss.sslServerCtx);
	SSL_set_fd(ss->clientSsl,fd);

	#if 1
	setNonblock(fd);
	SSL_set_accept_state(ss->clientSsl);
	#else
	setrwtimeout(fd, 1, 0);
	#endif
	ret=SSL_accept(ss->clientSsl);
	if(ret==1){
		Printf("SSL_accept ok\n");
		ss->sslAccept = 1;
		return 0;
	}else{
		int err = SSL_get_error(ss->clientSsl, ret);
		if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE){
			ss->sslAccept = 0;	//SSL_accept未完成,继续
			return 0;
		}else{
			Perror("SSL_accept");
			httpsSslConnClose(ss);	//SSL_accept出错
			memFree(ss);
			return -1;
		}
	}
}


int httpsSessionAdd(int sock)
{
	httpsSession *ss=memMalloc(sizeof(*ss));
	int ret=0;
	
	if(!ss) return -1;

	if(httpsAccept(ss,sock)){
		return -1;
	}

	ret=sockAddPoll(sock);
	if(ret<0){
		goto err;
	}
	ss->clientSockPollId=ret;
	ss->clientSock=sock;
	setNonblock(sock);
	
	init_timer(&ss->timer);
	ss->timer.data=(unsigned long)ss;
	ss->timer.function=SessionTimeout;
	mod_timer(&ss->timer, jiffies+SESSION_TIMEOUT*HZ);
	
	list_add(&ss->list,&httpss.sessionHead);
	hlist_add_head(&ss->hashToClientSock, &httpss.clientSockHlistHead[sock&SESSION_HLIST_MASK]);
	return 0;
	
err:
	memFree(ss);
	return -1;
}

httpsSession *httpsSessionFind(int sock)
{
	httpsSession *ss;
	struct hlist_node *pos;

	hlist_for_each(pos, &httpss.clientSockHlistHead[sock&SESSION_HLIST_MASK]){
		ss=list_entry(pos, httpsSession, hashToClientSock);
		if(sock==ss->clientSock){
			ss->from=DATA_FROM_CLIENT;
			mod_timer(&ss->timer, jiffies+SESSION_TIMEOUT*HZ);
			return ss;
		}
	}
	hlist_for_each(pos, &httpss.serverSockHlistHead[sock&SESSION_HLIST_MASK]){
		ss=list_entry(pos, httpsSession, hashToServerSock);
		if(sock==ss->serverSock){
			ss->from=DATA_FROM_SERVER;
			mod_timer(&ss->timer, jiffies+SESSION_TIMEOUT*HZ);
			return ss;
		}
	}
	
	return NULL;
}

int httpsAcceptContinue(httpsSession *ss)
{
	int ret;

	ret=SSL_accept(ss->clientSsl);
	if(ret==1){
		Printf("SSL_accept ok\n");
		ss->sslAccept = 1;
		return 0;
	}else{
		int err = SSL_get_error(ss->clientSsl, ret);
		if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE){
			ss->sslAccept = 0;
			return 0;
		}else{
			Perror("SSL_accept failed err=%d\n",err);
			return -1;
		}
	}
}

/*
	返回值 0:忽略, -1:断开
*/
int httpsRecv(httpsSession *ss, void *buf, int num)
{
	int ret,err,id;
	SSL *ssl=NULL;

	if(ss->from==DATA_FROM_SERVER){
		ssl=ss->serverSsl;
		id=ss->serverSockPollId;
	}else{
		ssl=ss->clientSsl;
		id=ss->clientSockPollId;
	}

	ret = SSL_read(ssl,buf,num);
	if(ret>0){
		return ret;
	}
	err = SSL_get_error(ssl,ret);
	Printf("SSL_get_error:%d ret:%d\n",err,ret);
	switch (err){
		case SSL_ERROR_NONE:
			break;
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			httpss.pollArray[id].events = POLLIN|POLLOUT;
		case SSL_ERROR_WANT_X509_LOOKUP:
			ret=0;
			break;
		case SSL_ERROR_SSL:
		case SSL_ERROR_SYSCALL:
		case SSL_ERROR_ZERO_RETURN:
			ret=-1;
			Perror("SSL_get_error");
			break;
		default:
			ret=-1;
			break;
	}
	return ret;
}

int httpsSslConnect(httpsSession *ss)
{
	int ret;
	SSL *ssl = NULL;

	ssl = SSL_new(httpss.sslClientCtx);
	if(!ssl){
		ERR_print_errors_fp(stderr);
		goto out;
	}

	if(SSL_set_fd(ssl, ss->serverSock) == 0){
		ERR_print_errors_fp(stderr);
		goto out;
	}

	SSL_set_connect_state(ssl);
	SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
	Printf("SSL_connect....\n");
	ret=SSL_connect(ssl);
	if(ret==1){
		Printf("SSL_connect ok....\n");
		ss->serverSsl=ssl;
		ss->sslConnect=1;
		return 0;
	}
	ret=SSL_get_error(ssl, ret);
	if(ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE){
		ss->serverSsl=ssl;
		ss->sslConnect=0;	//SSL_connect未完成,继续
		return 0;
	}else{
		Printf("SSL_connect failed....\n");
		goto out;
	}

out:
	if(ssl){
		SSL_free(ssl);
	}
	return -1;
}

int connectHttpsServer(httpsSession *ss)
{
	int sock=0;
	int ret=0;
	struct sockaddr_in addr={
		.sin_family=AF_INET,
		.sin_addr=ss->ipaddr,
		.sin_port=htons(ss->port),
		.sin_zero={0},
	};
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock<=0){
		Perror("socket");
		return -1;
	}

	setNonblock(sock);
	ss->state=SESSION_STATE_CONNECTING;
	Printf("connect to %s:%u\n",inet_ntoa(ss->ipaddr),ss->port);
	if(-1==connect(sock,(struct sockaddr*)&addr,sizeof(addr))){
		if(errno==EINPROGRESS){
			ss->serverAddr=addr;
			goto out;
		}
		Perror("connect");
		close(sock);
		return -1;
	}
	Printf("connect ok\n");

	if(httpsSslConnect(ss)){
		close(sock);
		return -1;
	}
	ss->state=SESSION_STATE_CONNECTED;
	
out:
	ret=sockAddPoll(sock);
	if(ret<0){
		close(sock);
		return -1;
	}
	ss->serverSock=sock;
	ss->serverSockPollId=ret;
	hlist_add_head(&ss->hashToServerSock, &httpss.serverSockHlistHead[sock&SESSION_HLIST_MASK]);
	return 0;
	
}

int sslConnectContinue(httpsSession *ss)
{
	int ret;
	
	//Printf("sslConnectContinue....\n");
	ret=SSL_connect(ss->serverSsl);
	if(ret==1){
		Printf("sslConnectContinue ok....\n");
		ss->sslConnect=1;
		return 0;
	}
	ret=SSL_get_error(ss->serverSsl, ret);
	if(ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE){
		ss->sslConnect=0;	//SSL_accept未完成,继续
		return 0;
	}else{
		Printf("sslConnectContinue failed....\n");
		httpsSessionDelete(ss);
		return -1;
	}
}

int connectServerContinue(httpsSession *ss)
{
	if(-1==connect(ss->serverSock,(struct sockaddr*)&ss->serverAddr,sizeof(ss->serverAddr))){
		if(errno==EISCONN){
			goto out;	//connect成功
		}
		Perror("connect");
		httpsSessionDelete(ss);
		return -1;
	}

out:
	Printf("connect server ok\n");
	//TODO:非阻塞处理
	if(-1==httpsSslConnect(ss)){
		httpsSessionDelete(ss);
		return -1;
	}
	ss->state=SESSION_STATE_CONNECTED;
	if(!ss->sslConnect){
		return 0;
	}
	if(sendDataToServer(ss)){
		httpsSessionDelete(ss);
	}
	return 0;
}


int parseHttpFirst(httpsSession *ss)
{
	char *buf=ss->clientBuf;
	char *p=ss->clientBuf;
	char host[64]={0};
	int i=0;

	p=strstr(buf,"Host: ");
	if(!p){
		Printf("Host: \n");
		goto out;
	}
	p+=6;	//strlen(Host: ")==6
	
	while(*p!=':' && *p!='\r' && *p!='\n' && i<64){
		host[i++]=*p++;
	}
	ss->port=443;
	Printf("Gethostbyname:%s\n",host);
	ss->ipaddr.s_addr=Gethostbyname(host);
	if(ss->ipaddr.s_addr==0){
		Printf("hostToIp error %s\n",host);
		return -1;
	}
	strncpy(ss->host,host,sizeof(ss->host));
	Printf("hostToIp:%s ok\n",host);

	if(connectHttpsServer(ss)){
		Printf("connectHttpsServer error \n");
		goto out;
	}
	Printf("new connect: ip=%s port=%d\n",inet_ntoa(ss->ipaddr),ss->port);
	
	if(ss->state==SESSION_STATE_CONNECTING || !ss->sslConnect){
		httpss.pollArray[ss->serverSockPollId].events |= POLLOUT;
		return 0;
	}

	Printf("call sendDataToServer\n");
	if(sendDataToServer(ss)){
		goto out;
	}
	return 0;
out:
	return -1;
}


int connectServerBefore(httpsSession *ss)
{
	char *p=ss->clientBuf;

	if(!strncmp(p,"GET",3) || !strncmp(p,"POST",4)){	
		if(parseHttpFirst(ss)){
			goto out;
		}
	}else{
		Printf("data error\n");
		goto out;
	}
	return 0;
out:
	return -1;
}

int httpsSslWrite(SSL *ssl,const void *buf,int num)
{
	int ret;

	if(!ssl){
		return 0;
	}
	ret=SSL_write(ssl,buf,num);
	switch(SSL_get_error(ssl,ret))
	{
		case SSL_ERROR_NONE:
			break;
		case SSL_ERROR_WANT_WRITE:
			ret = 0;
			break;
		case SSL_ERROR_WANT_READ:
			ret = 0;
			break;
		case SSL_ERROR_WANT_X509_LOOKUP:
			ret = -1;
			break;
		case SSL_ERROR_SYSCALL:
			ret = -1;
			break;
		case SSL_ERROR_SSL:
			ret = -1;
			break;
		case SSL_ERROR_ZERO_RETURN:
			ret=0;
			break;
		default:
			break;
	}
	
	return ret;
}


/*
	返回值 0:忽略, -1:断开
*/
int httpsSend(httpsSession *ss, void *data, int datalen)
{
	int ret=0;
	SSL *ssl=NULL;

	if(ss->from==DATA_FROM_SERVER){
		ssl=ss->clientSsl;
	}else{
		ssl=ss->serverSsl;
	}

	ret=SSL_write(ssl,data,datalen);
	if(ret>0){
		return ret;
	}
	switch(SSL_get_error(ssl,ret)){
		case SSL_ERROR_NONE:
			break;
		case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_X509_LOOKUP:
			ret=0;
			break;
		case SSL_ERROR_SSL:
		case SSL_ERROR_SYSCALL:
		case SSL_ERROR_ZERO_RETURN:
			ret=-1;
			break;
		default:
			ret=-1;
			break;
	}
	
	return ret;
}

void modifyHttpsData(httpsSession *ss, void *data, int len)
{
    //TODO:修改HTTPS数据
}

void saveHttpsData(httpsSession *ss, void *data, int len)
{
    //TODO:保存HTTPS数据
}

int sendDataToServer(httpsSession *ss)
{
	int ret=0;

	if(!ss->serverSock){
		if(connectServerBefore(ss)){
			return -1;
		}
		return 0;
	}
	
	if(!ss->clientBufUsed || !ss->sslConnect || ss->state==SESSION_STATE_CONNECTING){
		return 0;
	}
	
	Printf("ss->serverSock=%d ss->clientBufUsed=%d\n",ss->serverSock,ss->clientBufUsed);
	//Pinfo("send:\n%s\n",ss->clientBuf);

	ss->from=DATA_FROM_CLIENT;
    modifyHttpsData(ss,ss->clientBuf,ss->clientBufUsed);
	ret=httpsSend(ss,ss->clientBuf,ss->clientBufUsed);
	if(ret<0){
		Perror("httpsSend");
		return -1;
	}
	if(ret>0){
		saveHttpsData(ss, ss->clientBuf, ret);
		httpss.txBytes+=ret;
	}
	
	ss->clientBufUsed-=ret;
	if(ss->clientBufUsed){
		memmove(ss->clientBuf,ss->clientBuf+ret,ss->clientBufUsed);
		Printf("send continue. left %d bytes\n",ss->clientBufUsed);
		httpss.pollArray[ss->serverSockPollId].events |= POLLOUT;
	}else{
		httpss.pollArray[ss->serverSockPollId].events &= ~POLLOUT;
	}
	return 0;
}


int recvClientData(httpsSession *ss)
{
	int len=0;

	if(!ss->clientBuf){
		ss->clientBuf=(char *)memMalloc(DATA_BUF_LEN);
		if(!ss->clientBuf){
			Perror("malloc");
			goto out;
		}
	}
	
	if(DATA_BUF_LEN-ss->clientBufUsed==0){
		goto send;	//clientBuf满了,先处理一部分
	}

	len=httpsRecv(ss,ss->clientBuf+ss->clientBufUsed,DATA_BUF_LEN-ss->clientBufUsed);
	if(!len){
		Perror("httpsRecv");
		goto send;
	}
	if(len<0){
		Perror("httpsRecv");
		goto out;
	}
	Printf("recv: %d bytes\n",len);
	//Pinfo("%s", ss->clientBuf);
	ss->clientBufUsed+=len;
	mod_timer(&ss->timer, jiffies+SESSION_TIMEOUT*HZ);


send:
	if(sendDataToServer(ss)){
		goto out;
	}
	
	return 0;
out:
	httpsSessionDelete(ss);
	return -1;
	
}

int sendDataToClient(httpsSession *ss)
{
	int ret=0;

	if(!ss->serverBufUsed){
		return 0;
	}
	if(ss->ctState==CT_STATE_INIT){
		ss->ctState=CT_STATE_SUCCESS;
	}

	ss->from=DATA_FROM_SERVER;
    modifyHttpsData(ss,ss->clientBuf,ss->clientBufUsed);
	ret=httpsSend(ss,ss->serverBuf,ss->serverBufUsed);
	if(ret<0){
		Perror("httpsSend");
		return -1;
	}
	if(ret>0){
		saveHttpsData(ss, ss->serverBuf, ret);
		httpss.rxBytes+=ret;
	}
	ss->serverBufUsed-=ret;
	if(ss->serverBufUsed){
		memmove(ss->serverBuf,ss->serverBuf+ret,ss->serverBufUsed);
		httpss.pollArray[ss->clientSockPollId].events |= POLLOUT;
	}else{
		httpss.pollArray[ss->clientSockPollId].events &= ~POLLOUT;
		if(ss->ctState==CT_STATE_SERVER_CLOSE){	//服务器已经关了
			Printf("ss->ctState==CT_STATE_CLOSE\n");
			httpsSessionDelete(ss);
			return 0;
		}
	}

	if(ret>0){
		Printf("send %d bytes. left %d bytes\n",ret,ss->serverBufUsed);
	}
	return 0;
}


int recvServerData(httpsSession * ss)
{
	int len=0;

	if(!ss->serverBuf){
		ss->serverBuf=(char *)memMalloc(DATA_BUF_LEN);
		if(!ss->serverBuf){
			Perror("malloc");
			goto out;
		}
		ss->serverBufSize=DATA_BUF_LEN;
	}

	if(ss->serverBufSize-ss->serverBufUsed<SSL_MAX_MSS){
		goto send;	//Buf过小,先处理
	}
	len=httpsRecv(ss, ss->serverBuf+ss->serverBufUsed, ss->serverBufSize-ss->serverBufUsed);
	if(!len){
		Perror("httpsRecv");
		goto send;
	}
	if(len<0){
		Perror("httpsRecv");
		if(ss->serverBufUsed){	//服务器关闭连接，发送剩余数据
			Printf("Server Close. send left %d bytes\n",ss->serverBufUsed);
			httpsServerConnClose(ss);
			goto send;
		}
		goto out;
	}
	Printf("recv %d bytes\n",len);
	ss->serverBufUsed+=len;
	mod_timer(&ss->timer, jiffies+SESSION_TIMEOUT*HZ);

send:
	if(sendDataToClient(ss)){
		goto out;
	}
	return 0;
	
out:
	httpsSessionDelete(ss);
	return -1;
}


int runPoll(int timeout)
{
	int i=1;
	int new_fd;
	httpsSession *ss;

	int nready = poll(httpss.pollArray, httpss.pollUsedNum, timeout);

	if(nready < 1){
		return 0;
	}
	
	if(httpss.pollArray[0].revents & POLLIN)	//listen sock
	{
		while(1){
			new_fd = accept(httpss.sock, NULL, NULL);
			if (new_fd < 0){
				break;
			}else{
				Printf("new client connect...\n");
				if(httpsSessionAdd(new_fd)){	//添加的是client的连接
					close(new_fd);
				}
			}
		}
		if(--nready <= 0){
			return 0;
		}
	}
	for(i=1;i<httpss.pollUsedNum;i++)
	{
		if(httpss.pollArray[i].fd<0){
			continue;
		}
		if(httpss.pollArray[i].revents & (POLLIN | POLLOUT | POLLERR))
		{
			ss=httpsSessionFind(httpss.pollArray[i].fd);
			if(!ss){
				Printf("not find ss, sock=%d\n",httpss.pollArray[i].fd);
				close(httpss.pollArray[i].fd);
				httpss.pollArray[i].fd = -1;
			}else if(httpss.pollArray[i].revents & POLLIN){
				if(ss->from==DATA_FROM_SERVER){
					if(ss->state==SESSION_STATE_CONNECTING){
						connectServerContinue(ss);	//connect未完成,继续
					}if(!ss->sslConnect){
						sslConnectContinue(ss);		//SSL_connect未完成,继续
					}else{
						recvServerData(ss);			//接收服务器的数据
					}
				}else{
					if(ss->clientSsl && (ss->sslAccept == 0)){
						//继续处理未完成的SSL_accept
						if(httpsAcceptContinue(ss)){
							httpsSessionDelete(ss);
						}
					}else{
						recvClientData(ss);			//接收客户端的数据
					}
				}
			}else if(httpss.pollArray[i].revents & POLLOUT){
				if(ss->from==DATA_FROM_SERVER){
					if(ss->state==SESSION_STATE_CONNECTING){
						connectServerContinue(ss);	//connect未完成,继续
					}if(!ss->sslConnect){
						sslConnectContinue(ss);		//SSL_connect未完成,继续
					}else{
						if(sendDataToServer(ss)){	//发送剩余数据到服务器
							httpsSessionDelete(ss);
						}
					}
				}else{
					if(sendDataToClient(ss)){		//发送剩余数据到客户端
						httpsSessionDelete(ss);
					}
				}
			}else{
				Printf("httpss.pollArray[i].revents error\n");
				httpsSessionDelete(ss);				//revents错误, 删除session
			}
			if(--nready <= 0){
				return 0;
			}
		}
	}
	return 0;
}


int main(int argc, char **argv)
{
	if(initHttpss()){
		return -1;
	}
	if(argc==2){
		httpss.debug=atoi(argv[1]);
	}
	
	Printf("Start httpss. v1.0\n");
	
	while(1){
		runPoll(100);
		run_timers();
	}

	return 0;
}
