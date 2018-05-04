/** General Socket Wrapper
*   Created By Kiritow. (https://github.com/kiritow)
*   Licensed under MIT
*/

#ifndef _gsock_h
#define _gsock_h

#include <cstdint>
#include <string>

class sock
{
public:
	sock();
    sock(const sock&)=delete;
    sock& operator = (const sock&)=delete;
    sock(sock&&);
    sock& operator = (sock&&);
    ~sock();

    /// Return:
    /// 0: Connection Established. No Error.
    /// -1: connect() call error. See errno.
    /// -2: This socket has been connected before.
    /// -3: socket() call error. Failed to create socket. See errno.
    int connect(const std::string& IPStr,int Port);

    template<typename T>
    int send(const T&);

    template<typename T>
    int recv(T&);

    /// Return:
    /// return what send() and recv() call returns.
    int send(const void* Buffer,int Length);
	int recv(void* Buffer, int MaxToRecv);

    int getsendtime(int& _out_Second,int& _out_uSecond);
    int getrecvtime(int& _out_Second,int& _out_uSecond);

    int setsendtime(int Second);
    int setrecvtime(int Second);
    
    int getlocal(std::string& IPStr,int& Port);
    int getpeer(std::string& IPStr,int& Port);

private:
    sock(int);
    friend class serversock;

    struct _impl;
    _impl* _pp;
};

class serversock
{
public:
    serversock();
    serversock(const serversock&)=delete;
    serversock& operator = (const serversock&) =delete;
    serversock(serversock&&)=delete;
    serversock& operator = (serversock&&) =delete;
    ~serversock();

    /// Return:
    /// 0: Bind Succeed. No Error.
    /// -1: bind() call error. See errno.
    /// -2: This socket has been created before.
    /// -3: socket() call error. Failed to create socket. See errno.
    int bind(int Port);

    int set_reuse();

    /// Return:
    /// return what listen() call returns
    int listen(int MaxCount);

    /// Return:
    /// 0: Accept Succeed. No Error. _out_s holds the new socket.
    /// -1: accept() call error. See errno.
    /// -2: _out_s is a connected socket, which should not be passed in.
    int accept(sock& _out_s);
private:
    struct _impl;
    _impl* _pp;
};

class udpsock
{
public:
	udpsock();
	udpsock(const udpsock&) = delete;
	udpsock& operator = (const udpsock&) = delete;
	udpsock(udpsock&&);
	udpsock& operator = (udpsock&&);
	~udpsock();

	/// Explict bind() call is only need when you have to receive data.
	int bind(int Port);

	int sendto(const std::string& IPStr, int Port, const void* buffer, int length);

	/// Must call bind() before calling recvfrom().
	int recvfrom(std::string& fromIP, void* buffer, int bufferLength);
	
	int getlasterror();
private:
	struct _impl;
	_impl* _pp;
};

/// Net Tools
int DNSResolve(const std::string& HostName,std::string& _out_IPStr);

#endif // _gsock_h