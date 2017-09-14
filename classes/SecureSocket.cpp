#include <iostream>

#include "SecureSocket.h"

extern "C" {
	#include <sys/ioctl.h>
}


using namespace LanConnect;

// static member variable definitions
bool SecureSocket::mSslInitDone = false;
bool SecureSocket::mStopServer = false;
std::mutex SecureSocket::mSslMutex;


// member function definitions
SecureSocket::SecureSocket() {
	mSecPath = new std::string("./");
	mServerActive = false;
	mClientActive = false;
	mSocketInited = false;
	mCTX = NULL;
	mSSL = NULL;
	mListenfd = -1;
}

SecureSocket::SecureSocket(const char *sec_path) {
	mSecPath = new std::string(sec_path);
	mServerActive = false;
	mClientActive = false;
	mSocketInited = false;
	mCTX = NULL;
	mSSL = NULL;
	mListenfd = -1;
}


// destructor
SecureSocket::~SecureSocket() {
	delete mSecPath;

	if (mServerActive) {
		mServerActive = false;

		std::cout << "warning: application is not closing server Socket (" << this << ") properly!\n";
		CloseConnection(-1);

		// closing listening socket
		if (mListenfd != -1) {
			std::cout << "closing listening socket \n";
			#if TILL_YOU_FIX_CLOSE_OF_MLISTENFD_ISSUE
			if (close(mListenfd) == -1)
				std::cout << "closing error \n\n";
			#endif
		}
	}

	if (mClientActive) {
		mClientActive = false;
		std::cout << "warning: application is not closing client Socket (" << this << ") properly!\n";
		Disconnect(-1);
	}

	std::cout << "SecureSocket object destroyed!!\n";
}

int SecureSocket::CloseListenFd() {
	return close(mListenfd);
}


void SecureSocket::closeConnection(const char *soc_str) {
	if (mSSL) {
    	// clean up ssl
		SSL_free(mSSL);
		mSSL = NULL;
	}

	if (mCTX) {
		SSL_CTX_free(mCTX);
		mCTX = NULL;
	}
}


void SecureSocket::CloseConnection(int connfd) {
	if (mServerActive) {
		std::cout << "SecureSocket Session (Server) Ended!\n";
		mServerActive = false;
	}

	closeConnection("Server");

	if (connfd > 0) {
		if (close(connfd) == -1) {
    		/* parent closes connected socket */
			std::cout << "close error";
		}
	}
}


void SecureSocket::Disconnect(int connfd) {
	if (mClientActive) {
		std::cout << "SecureSocket Session (Client) Ended!\n";
		mClientActive = false;
	}

	closeConnection("Client");

	if (connfd > 0) {
		if (close(connfd) == -1) {
    		/* parent closes connected socket */
			std::cout << "close error";
		}
	}
}


void SecureSocket::sigAlarm(int sig) {
	//std::cout << __func__ << "()\n";
}


int SecureSocket::StopConnections(void) {
	mStopServer = true;
	return 0;
}


int SecureSocket::sSocket(int family, int type, int protocol)
{
	int n;

	if((n = socket(family, type, protocol)) < 0)
		std::cout << "socket error\n\n";

	return (n);
}


void SecureSocket::sBind(int fd, const struct sockaddr *sa, socklen_t salen)
{
	if(bind(fd, sa, salen) < 0)
		std::cout << "bind error\n\n";
}


void SecureSocket::sListen(int fd, int backlog)
{
	char *ptr;

        /*4can override 2nd argument with environment variable */
	if((ptr = getenv("LISTENQ")) != NULL)
		backlog = atoi(ptr);

	if(listen(fd, backlog) < 0)
		std::cout << "listen error\n\n";
}


SigFunc* SecureSocket::sSignal(int signo, SigFunc *func)        /* for our signal() function */
{
	SigFunc *sigfunc;

	if((sigfunc = signal(signo, func)) == SIG_ERR)
		std::cout << "signal error\n\n";

	return (sigfunc);
}


SSL_CTX* SecureSocket::sslInitContext(enum eSocketType role) {
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	mSslMutex.lock();
	if (mSslInitDone == false) {
		mSslInitDone = true;
		SSL_library_init();

    /* load & register all cryptos, etc. */
		OpenSSL_add_all_algorithms();

    /* load all error messages */
		SSL_load_error_strings();
	}
	mSslMutex.unlock();

	if (role == SERVER_SOCKET) {
    	/* create new server-method instance */
		method = TLSv1_2_server_method();
	}
	else {
		/* create new client-method instance */
		method = TLSv1_2_client_method();
	}

    /* create new context from method */
	ctx = SSL_CTX_new(method);
	if(ctx == NULL) {
		ERR_print_errors_fp(stderr);
		std::cout << "Unable to create new SSL Context\n";
	}

	return ctx;
}


int SecureSocket::sslLoadCertificate(SSL_CTX *ctx) {
	char CertFileName[] = "cacert.pem";
	char KeyFileName[] = "private.pem";
	char CertFile[512];
	char KeyFile[512];

	if ((ctx == NULL) || (mSecPath == NULL)) {
		return -1;
	}

	// verify security files
	sprintf(CertFile, "%s/%s", mSecPath->c_str(), CertFileName);
	if (access(CertFile, F_OK) != 0) {
		std::cout << "Unable access " << CertFile << "\n";
		return -1;
	}
	sprintf(KeyFile, "%s/%s", mSecPath->c_str(), KeyFileName);
	if (access(KeyFile, F_OK) != 0) {
		std::cout << "Unable access " << KeyFile << "\n";
		return -1;
	}

    // set the local certificate from CertFile */
	if(0 >= SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM)) {
		ERR_print_errors_fp(stderr);
		std::cout << "Error loading file \"" << CertFile << "\"\n";
		return -1;
	}

    // set the private key from KeyFile */
	if(0 >= SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM)) {
		ERR_print_errors_fp(stderr);
		std::cout << "Error loading file \"" << KeyFile << "\"\n";
		return -1;
	}

    // verify private key */
	if(!SSL_CTX_check_private_key(ctx)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	std::cout << "Successfully loaded " << CertFile << " & " << KeyFile << "\n";
	return 0;
}


void SecureSocket::sslShowCertificate(SSL *ssl, enum eSocketType role) {
	X509 *cert;
	char *line, *caller, *callee;
	long res;
	char client[] = "Client";
	char server[] = "Server";

    /* get the server's certificate */
	cert = SSL_get_peer_certificate(ssl);
	if (role == CLIENT_SOCKET) {
		caller = client;
		callee = server;
	}
	else {
		caller = server;
		callee = client;
	}

	if(cert != NULL) {
		std::cout << callee << " certificate:\n";
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		std::cout << "\tSubject: " << line << "\n";
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		std::cout << "\tIssuer: " << line << "\n";
		free(line);

		X509_free(cert);
	}
	else {
		std::cout << "OpenSSL: No certificates from " << callee << ".\n";
		res = SSL_get_verify_result(ssl);
		if(X509_V_OK != res) {
			std::cout << "Certificate error code: " << res << "\n";
			ERR_print_errors_fp(stderr);
		}
	}
	std::cout << "\n";
}


int SecureSocket::OpenConnection() {
	int 					connfd = -1;
	int                     en = 1;
	socklen_t               clilen;
	struct sockaddr_in      cliaddr, servaddr;
	void sig_chld(int);

	if (!mSocketInited) {
		mCTX = sslInitContext(SERVER_SOCKET);
		if (mCTX == NULL)
			return -1;

		if (0 > sslLoadCertificate(mCTX))
			return -1;

		mListenfd = sSocket(AF_INET, SOCK_STREAM, 0);
		if (setsockopt(mListenfd, SOL_SOCKET, SO_REUSEADDR, &en, sizeof(en)) < 0)
			std::cout << "setsockopt(SO_REUSEADDR) failed\n";

		// bind a socket and listen for connections
		bzero(&servaddr, sizeof(servaddr));
		servaddr.sin_family      = AF_INET;
		servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
		servaddr.sin_port        = htons(SERV_PORT);
		sBind(mListenfd, (SA *) &servaddr, sizeof(servaddr));
		sListen(mListenfd, LISTENQ); // check LISTENQ to increase more clients
		std::cout << "listening for incoming socket...\n";
	}

	do {
		int rv;
		fd_set fdset;
		struct timeval timeout;

		FD_ZERO(&fdset); /* clear the set */
		FD_SET(mListenfd, &fdset); /* add our file descriptor to the set */
		timeout.tv_sec = 0;
		timeout.tv_usec = 500*1000; // 100 ms

		// block until input arrives on one or more active sockets
		rv = select(mListenfd+1, &fdset, NULL, NULL, &timeout);
		if (rv < 0) {
	    	perror("select"); /* an error accured */
	    	return -1;
		}
		else if (rv == 0) {
		}
		else {
			if (FD_ISSET(mListenfd, &fdset)) {
				//  accept conn. based on mListenfd and create new socket - mConnfd
				if((connfd = accept(mListenfd, (SA *) &cliaddr, &clilen)) < 0) {
					if (errno != EINTR) {
						std::cout << "accept error\n\n";
					}
					return -1;
				}
				break;
			}
			else {
				std::cout << "warning: ignoring a socket as it is non intented to this server\n";
			}
		}
	} while (!mStopServer);
	if (mStopServer) {
		return -1;
	}

    // convert mConnfd to a secure socket
	mSSL = SSL_new(mCTX);
	SSL_set_fd(mSSL, connfd);
	if(-1 == SSL_accept(mSSL))
		ERR_print_errors_fp(stderr);

	// print certificates for server admin
	mSocketInited = true;
	std::cout << "Start of SecureSocket (server) session \n";
	sslShowCertificate(mSSL, SERVER_SOCKET);
	mServerActive = true;

	return connfd;
}


int SecureSocket::Connect(const char *ip) {
	return Connect(ip, SERV_PORT);
}

int SecureSocket::Connect(const char *ip, int port) {
	int connfd;
	struct sockaddr_in servaddr;
	SigFunc *sigfunc;

	if (ip == NULL) {
		std::cout << __func__ << ": invalid input!\n";
		return -1;
	}

	mCTX = sslInitContext(CLIENT_SOCKET);
	if(mCTX == NULL) {
		std::cout << "SSL context init failed\n";
		return -1;
	}

	connfd = sSocket(AF_INET, SOCK_STREAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	if (inet_pton(AF_INET, ip, &servaddr.sin_addr) < 0) {
		std::cout << "inet_pton error for port: " << port << "\n";
		return -1;
	}

	// set timeout for connect call
	sigfunc = sSignal(SIGALRM, sigAlarm);
	if (ualarm(200*1000, 0)) // 1st in usec, 2nd interval is off
		std::cout << __func__ << "(): alarm was already set\n";

	if (connect(connfd, (SA *) &servaddr, sizeof(servaddr)) < 0) {
		if (errno == EINTR) {
			errno = ETIMEDOUT;
			ualarm(0, 0);
			sSignal(SIGALRM, sigfunc); // restore previous signal handler
		}
		else {
			std::cout << __func__ << "(): connect error - " << strerror(errno) << " (" << ip << ")\n";
		}

		return -1;
	}
	ualarm(0, 0);
	sSignal(SIGALRM, sigfunc); // restore previous signal handler

    // convert to a secure socket
	mSSL = SSL_new(mCTX);
	SSL_set_fd(mSSL, connfd);

    // perform the connection
	if(SSL_connect(mSSL) == -1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	else {
		mSocketInited = true;
		std::cout << "\nStart of SecureSocket (client) session\n";
		sslShowCertificate(mSSL, CLIENT_SOCKET);
	}
	mClientActive = true;

	return connfd;
}


int SecureSocket::Send(char *data, int length) {
	int bytes;

	if (!mSocketInited) {
		std::cout << "Send called before initializing the socket\n";
		return -1;
	}

	if ((data == NULL) || (length < 1)) {
		std::cout << __func__ << ": invalid inputs\n";
		return -1;
	}

	// send data over secure socket
	bytes = SSL_write(mSSL, data, length);

	return bytes;
}


int SecureSocket::recvFromSslSock(SSL *ssl, char *data, int len) {
	int rcnt = 0;
	int totalcnt = 0;

	if ((ssl == NULL) || (data == NULL) || (len < 1)) {
		std::cout << __func__ << "(): invalid arguments\n";
		return -1;
	}

	// clearing old data in buffer
	memset(data, 0, len);

	do {
        // read a chunk from secure socket connection
		rcnt = SSL_read(ssl, data, len - totalcnt);
		if(rcnt < 0) {
			if(errno == EINTR)
				continue;

			std::cout << __func__ << ": read error " << strerror(errno) << "\n";
			totalcnt = -1 * (totalcnt + 1);
			break;
		}

        // check for end of file
		if(rcnt == 0) {
			break;
		}

		totalcnt += rcnt;
	} while (0);

	return totalcnt;
}


int SecureSocket::Recv(char *data, int max_len) {
	if (!mSocketInited) {
		std::cout << "Recv called before initializing the socket\n";
		return -1;
	}

	return recvFromSslSock(mSSL, data, max_len);
}


void* SecureSocket::rxThread(void *arg) {
	struct RxObj *rxo;
	int rcnt = 0;

	rxo = (struct RxObj *) arg;
	if (rxo == NULL) {
		std::cout << __func__ << ": Invalid argument\n";
		return NULL;
	}

	// receive one chunk of data
	rcnt = recvFromSslSock(rxo->ssl, rxo->data, rxo->max_len);

	// pass back the data over callback function
	rxo->cb(rxo->data, rcnt);
	delete rxo;

	// exit thread -- assuming the caller would make another Async Recv call
	return NULL;
}


int SecureSocket::RecvAsync(char *data, int max_len, RvCbFunc *cb) {
	pthread_t rx_thread;
	RxObj *rx_obj;

	if (!mSocketInited) {
		std::cout << "RecvAsync called before initializing the socket\n";
		return -1;
	}

	// create new object on heap, copy data and pass to RxThread for use and delete
	rx_obj = new RxObj;
	rx_obj->data 	= data;
	rx_obj->max_len = max_len;
	rx_obj->cb 		= cb;
	rx_obj->ssl 	= mSSL;

	if (pthread_create(&rx_thread, NULL, this->rxThread, rx_obj)) {
		std::cout << __func__ << "Error creating rx thread!\n";
		return -1;
	}

	return 0;
}
