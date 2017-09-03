#include <iostream>

#include "SecureSocket.h"


using namespace LanConnect;


SecureSocket::SecureSocket() {
	mSecPath = new std::string("./");
}

SecureSocket::SecureSocket(const char *sec_path) {
	mSecPath = new std::string(sec_path);
}

SecureSocket::~SecureSocket() {
	delete mSecPath;
}


int SecureSocket::Socket(int family, int type, int protocol)
{
        int n;

        if((n = socket(family, type, protocol)) < 0)
                std::cout << "socket error";

        return (n);
}


void SecureSocket::Bind(int fd, const struct sockaddr *sa, socklen_t salen)
{
        if(bind(fd, sa, salen) < 0)
                std::cout << "bind error";
}
        

void SecureSocket::Listen(int fd, int backlog)
{       
        char *ptr;

        /*4can override 2nd argument with environment variable */
        if((ptr = getenv("LISTENQ")) != NULL)
                backlog = atoi(ptr);
        
        if(listen(fd, backlog) < 0)
                std::cout << "listen error";
}
        
        
Sigfunc* SecureSocket::Signal(int signo, Sigfunc *func)        /* for our signal() function */
{
        Sigfunc *sigfunc;

        if((sigfunc = signal(signo, func)) == SIG_ERR)
                std::cout << "signal error";

        return (sigfunc);
}


SSL_CTX* SecureSocket::SSL_InitContext(enum eSocketType role) {
	const SSL_METHOD *method;                                                         
	SSL_CTX *ctx;                                                                     

	SSL_library_init();                                                               

    /* load & register all cryptos, etc. */                                           
	OpenSSL_add_all_algorithms();                                                     

    /* load all error messages */                                                     
	SSL_load_error_strings();                                                         

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


int SecureSocket::SSL_LoadCertificate(SSL_CTX *ctx) {
	char CertFileName[] = "cacert.pem";
	char KeyFileName[] = "private.pem";
	char CertFile[512];
	char KeyFile[512];

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


void SecureSocket::SSL_ShowCertificate(SSL *ssl, enum eSocketType role) {
	X509 *cert;                                                                       
	char *line, *caller;
	long res;
	char client[] = "Client";
	char server[] = "Server";

    /* get the server's certificate */                                                
	cert = SSL_get_peer_certificate(ssl);
	if (role == CLIENT_SOCKET)
		caller = client;
	else
		caller = server;

	std::cout << "\n\n";
	if(cert != NULL) {
		std::cout << caller << " certificate:\n";             
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);              
		std::cout << "\tSubject: " << line << "\n";
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);               
		std::cout << "\tIssuer: " << line << "\n";
		free(line);

		X509_free(cert);                                                          
	}                                                                                 
	else {  
		std::cout << "OpenSSL: No certificates from server.\n";                         
		res = SSL_get_verify_result(ssl);                                         
		if(X509_V_OK != res) {
			std::cout << "Certificate error code: " << res << "\n";                      
			ERR_print_errors_fp(stderr);                                      
		}       
	}               
	std::cout << "\n";   
}


int SecureSocket::Init() {
	int                     listenfd, connfd;
	int                     en = 1;
	socklen_t               clilen;
	struct sockaddr_in      cliaddr, servaddr;
	void sig_chld(int);


	mCTX = SSL_InitContext(SERVER_SOCKET);
	if (mCTX == NULL)                                                               
		return -1;                                                                

	if (0 > SSL_LoadCertificate(mCTX))                                                
		return -1;                                                                

	listenfd = Socket(AF_INET, SOCK_STREAM, 0);                                       
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &en, sizeof(int)) < 0)          
		std::cout << "setsockopt(SO_REUSEADDR) failed\n";                              

	// bind a socket and listen for connections
	bzero(&servaddr, sizeof(servaddr));                                               
	servaddr.sin_family      = AF_INET;                                               
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);                                     
	servaddr.sin_port        = htons(SERV_PORT);                                      
	Bind(listenfd, (SA *) &servaddr, sizeof(servaddr));
	Listen(listenfd, LISTENQ); // check LISTENQ to increase more clients
	std::cout << "listening for incoming socket...\n";

	//  accept conn. based on listenfd and create new socket - connfd
	if((connfd = accept(listenfd, (SA *) &cliaddr, &clilen)) < 0) {
		if (errno != EINTR)
			std::cout << "accept error";
	}

	// close the listening socket as it is no longer required
	if(close(listenfd) == -1) {
		std::cout << "close error";
	}

    // convert connfd to a secure socket
	mSSL = SSL_new(mCTX);
	SSL_set_fd(mSSL, connfd);
	if(-1 == SSL_accept(mSSL))
		ERR_print_errors_fp(stderr);

	// print certificates for server admin
	std::cout << "\n\nStart of SecureSocket (server) session \n";
	SSL_ShowCertificate(mSSL, SERVER_SOCKET);

	return 0;
}


void SecureSocket::Stop() {
	int currfd;

	if ((mCTX == NULL) || (mSSL == NULL)) {
		std::cout << __func__ << ": mCTX or mSSL is NULL\n";
		return;
	}

	// obtain the current socket descriptor from SSL layer
	//if (role == SERVER_SOCKET) {
		currfd = SSL_get_fd(mSSL);
	//}

    // clean up ssl
	SSL_free(mSSL);

	//if (role == SERVER_SOCKET) {
		if (close(currfd) == -1) {
    		/* parent closes connected socket */
    		std::cout << "close error";
    	}
	//}
	SSL_CTX_free(mCTX);

	std::cout << "SecureSocket Session Ended!\n\n";
}


int SecureSocket::Connect(const char *ip) {
	int sockfd;
	struct sockaddr_in servaddr;

	if (ip == NULL) {
		std::cout << __func__ << ": invalid input!\n";
		return -1;
	}

	mCTX = SSL_InitContext(CLIENT_SOCKET);
	if(mCTX == NULL) {
		std::cout << "SSL context init failed\n";
		return -1;
	}

	sockfd = Socket(AF_INET, SOCK_STREAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(SERV_PORT);
	if (inet_pton(AF_INET, ip, &servaddr.sin_addr) < 0)
		std::cout << "inet_pton error for port: " << SERV_PORT << "\n";

	std::cout << "connecting to " << ip << "\n";
	if (connect(sockfd, (SA *) &servaddr, sizeof(servaddr)) < 0)
		std::cout << __func__ << ": connect error\n";

    // convert to a secure socket
	mSSL = SSL_new(mCTX);
	SSL_set_fd(mSSL, sockfd);

    // perform the connection
	if(SSL_connect(mSSL) == -1)
		ERR_print_errors_fp(stderr);
	else {
		std::cout << "\nStart of SecureSocket (client) session\n";
		SSL_ShowCertificate(mSSL, CLIENT_SOCKET);
	}

	return 0;
}


//void SecureSocket::Disconnect(enum eSocketType role) {
void SecureSocket::Disconnect() {
	Stop();
}

