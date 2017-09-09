#ifndef SECURE_SOCKET_H
#define SECURE_SOCKET_H

#include <string>
#include <mutex>

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
	#include <pthread.h>
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

	typedef void SigFunc(int);   				// for signal handlers
	typedef void RvCbFunc(char *data, int len);	// for Async Recv function


	struct RxObj
	{
		char *data;
		int max_len;
		RvCbFunc *cb;
		SSL *ssl;
	};


	class SecureSocket {
	public:
		SecureSocket();
		SecureSocket(const char *sec_path);
		~SecureSocket();

		int Send(char *data, int length);
		int Recv(char *data, int max_len);
		int RecvAsync(char *data, int max_len, RvCbFunc *cb);

		int OpenConnection();			// server functions
		void CloseConnection();

		int Connect(const char *ip);	// client functions
		int Connect(const char *ip, int port);
		void Disconnect();

	private:
		std::string *mSecPath; 			// path to certificats and keys
		SSL_CTX  *mCTX;
		SSL *mSSL;
		int mConnfd;
		static std::mutex mSslMutex;
		static bool mSslInitDone;
		bool mServerActive;
		bool mClientActive;

		SSL_CTX* sslInitContext(enum eSocketType role);
		int sslLoadCertificate(SSL_CTX *ctx);
		void sslShowCertificate(SSL* ssl, enum eSocketType role);
		int sSocket(int family, int type, int protocol);
		void sBind(int fd, const struct sockaddr *sa, socklen_t salen);
		void sListen(int fd, int backlog);
		SigFunc* sSignal(int signo, SigFunc *func);
		void CloseConnection(const char *soc_str);

		static void* rxThread(void *arg);
		static int recvFromSslSock(SSL *ssl, char *data, int len);
		static void sigAlarm(int sig);
	};

}

#endif
