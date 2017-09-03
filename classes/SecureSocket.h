#ifndef SECURE_SOCKET_H
#define SECURE_SOCKET_H

#include <string>

extern "C" {
	#include <netinet/in.h>
	#include <netinet/ip.h> /* superset of previous */
	#include <arpa/inet.h>

	#include <openssl/ssl.h>
	#include <openssl/err.h>

	#include <sys/types.h>       /* See NOTES */
	#include <sys/socket.h>
	#include <string.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <unistd.h>
}

/* Following could be derived from SOMAXCONN in <sys/socket.h>, but many                  
   kernels still #define it as 5, while actually supporting many more */                  
#define LISTENQ         1024    /* 2nd argument to listen() */                            
                
/* Define some port number that can be used for our examples */
#define SERV_PORT        9877                   /* TCP and UDP */                         
                        
/* Following shortens all the typecasts of pointer arguments: */                          
#define SA      struct sockaddr 
                                                    

namespace LanConnect {

	enum eSocketType
	{
		CLIENT_SOCKET,
		SERVER_SOCKET,
		MAX_SOCKET_TYPE
	};

	typedef void Sigfunc(int);   /* for signal handlers */


	class SecureSocket {
	public:
		SecureSocket();
		SecureSocket(const char *sec_path);
		~SecureSocket();
		int Init();				// server
		void Stop();
		int Connect(const char *ip);	// client
		void Disconnect();

	private:
		SSL_CTX  *mCTX;
		SSL *mSSL;
		std::string *mSecPath;

		SSL_CTX* SSL_InitContext(enum eSocketType role);
		int SSL_LoadCertificate(SSL_CTX *ctx);
		void SSL_ShowCertificate(SSL* ssl, enum eSocketType role);
		int Socket(int family, int type, int protocol);
		void Bind(int fd, const struct sockaddr *sa, socklen_t salen);
		void Listen(int fd, int backlog);
		Sigfunc* Signal(int signo, Sigfunc *func);
	};

}

#endif