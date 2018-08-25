/** General Socket Wrapper
*   Created By Kiritow. (https://github.com/kiritow)
*   Licensed under MIT
*/

#ifndef _gsock_h
#define _gsock_h

#include <cstdint>
#include <string>
#include <vector>

enum
{
	GSOCK_OK = 0,
	GSOCK_API_ERROR = -1, // API call failed, See Errno
	GSOCK_INVALID_SOCKET = -2, // Invalid socket
	GSOCK_ERROR_CREAT = -3, // Socket cannot be created, See Errno
	GSOCK_INVALID_IP = -4, // Invalid IP Address (IPv4,IPv6)
	GSOCK_UNKNOWN_PROTOCOL = -5, // Unknown Protocol
	GSOCK_ERROR_NTOP = -6, // inet_ntop failed.
    GSOCK_MISMATCH_PROTOCOL = -7, // Protocol mismatch.
    GSOCK_BAD_PROTOCOL = -8, // Bad protocol. 
};

class vsock
{
protected:
    vsock();
    vsock(const vsock&)=delete;
    vsock& operator = (const vsock&)=delete;
    vsock(vsock&& v);
    vsock& operator = (vsock&& v);
    ~vsock();
    
    //vsock(int);
    
	struct _impl;
	_impl* _vp;

	friend class selector;
#ifdef WIN32

#else
    friend class epoll;
#endif
};

class sock : public vsock
{
public:
    // Return:
    // GSOCK_OK: Connection Established. No Error.
    // GSOCK_API_ERROR: connect() call error. See errno.
    // GSOCK_INVALID_SOCKET: This socket has been connected before.
    // GSOCK_ERROR_CREAT
	// GSOCK_INVALID_IP
    int connect(const std::string& IPStr,int Port);

    // Return:
    // return what send() and recv() call returns.
    int send(const void* Buffer,int Length);
	int recv(void* Buffer, int MaxToRecv);

    // Return:
    // GSOCK_OK
    // GSOCK_API_ERROR
    int getsendtime(int& _out_Second,int& _out_uSecond);
    int getrecvtime(int& _out_Second,int& _out_uSecond);
    int setsendtime(int Second,int Millisecond);
    int setrecvtime(int Second,int Millisecond);
    int setkeepalive(bool op);
    
    // Return:
	// 0: Success. No Error. IPv4
	// 1: Success. No Error. IPv6
    // GSOCK_API_ERROR: getlocalname() or getpeername() call error. See errno.
    // GSOCK_INVALID_SOCKET: Socket not created.
    int getpeer(std::string& IPStr, int& Port);
    int getlocal(std::string& IPStr,int& Port);
    
    friend class serversock;
private:
	struct _impl;
};

class serversock : public vsock
{
public:
	// use_family:
	// 0: Auto (Undecided now) (default)
	// 1: IPv4 (If family cannot be automatically decided, then IPv4 will be the default option)
	// 2: IPv6
	serversock(int use_family=0);
	~serversock();

    // Return:
    // GSOCK_OK: Bind Succeed. No Error.
    // GSOCK_API_ERROR: bind() call error. See errno.
    // GSOCK_INVALID_SOCKET: This socket has been created before.
    // GSOCK_ERROR_CREAT
    int bind(int Port);

    // Return:
    // GSOCK_OK
    // GSOCK_ERROR_CREAT
    // GSOCK_API_ERROR: setsockopt() call error.
    int set_reuse();

    // Return:
    // GSOCK_OK
    // GSOCK_API_ERROR: listen() call error.
    // GSOCK_INVALID_SOCKET
    int listen(int MaxCount);

    // Return:
    // GSOCK_OK: Accept Succeed. No Error. _out_s holds the new socket.
    // GSOCK_API_ERROR: accept() call error. See errno.
    // GSOCK_INVALID_SOCKET: _out_s is not an empty socket, which should not be passed in.
    int accept(sock& _out_s);
private:
	struct _impl;
	_impl* _pp;
};

class udpsock : public vsock
{
public:
	// use_family:
	// 0: Auto (Undecided now) (default)
	// 1: IPv4 (If family cannot be automatically decided, then IPv4 will be the default option)
	// 2: IPv6
 	udpsock(int use_family=0);
	~udpsock();
	
	// Use udp socket as tcp socket. (but of course it is not).
	// connect call just copy the target socket data to kernel. See connect() for more info.
	// Return:
    // GSOCK_OK: data copied.
    // GSOCK_API_ERROR: connect() call error.
    // GSOCK_INVALID_IP
    // GSOCK_MISMATCH_PROTOCOL
    // GSOCK_INVALID_SOCKET
    // GSOCK_ERROR_CREAT
	int connect(const std::string& IPStr,int Port);
    // Return:
    // Besides all returns of connect(...), adding the following:
    // GSOCK_BAD_PROTOCOL: broadcast is not supported.
	int broadcast_at(int Port);
	
	// Must be called in broadcast mode before any broadcasting.
    // Return:
    // GSOCK_OK
    // GSOCK_MISMATCH_PROTOCOL
    // GSOCK_INVALID_SOCKET
    // GSOCK_ERROR_CREAT
	int set_broadcast();

	// Explict bind() call is only need when you have to receive data.
    // Return:
    // GSOCK_OK
    // GSOCK_MISMATCH_PROTOCOL
    // GSOCK_INVALID_SOCKET
    // GSOCK_ERROR_CREAT
	int bind(int Port);

    // Return:
    // ret>=0: sendto() returns
    // GSOCK_API_ERROR(-1): sendto() call error.
    // GSOCK_INVALID_IP
    // GSOCK_MISMATCH_PROTOCOL
    // GSOCK_INVALID_SOCKET
    // GSOCK_ERROR_CREAT
	int sendto(const std::string& IPStr, int Port, const void* buffer, int length);
	// Return:
    // Besides all returns of sendto(...), adding the following:
    // GSOCK_BAD_PROTOCOL: broadcast is not supported.
    int broadcast(int Port,const void* buffer,int length);

	// Must call bind() before calling recvfrom().
    // Return:
    // ret>=0: recvfrom() returns
    // GSOCK_API_ERROR(-1): recvfrom() call error.
    // GSOCK_ERROR_NTOP
    // GSOCK_UNKNOWN_PROTOCOL
    // GSOCK_MISMATCH_PROTOCOL
    // GSOCK_INVALID_SOCKET
    // GSOCK_ERROR_CREAT
	int recvfrom(std::string& fromIP, int& fromPort, void* buffer, int bufferLength);
	
    // send() and recv() should only be called after connect(). Or it will fail.
    // Return:
    // ret>=0: send(), recv() returns.
    // GSOCK_API_ERROR(-1): send(), recv() call error.
    // GSOCK_INVALID_SOCKET: socket not created, and connect() has not been called yet.
	int send(const void* buffer,int length);
	int recv(void* buffer,int bufferLength);
private:
	struct _impl;
	_impl* _pp;
};

/// Select
class selector
{
public:
	selector();
	~selector();

	void clear();

	void add_read(const vsock&);
	void add_write(const vsock&);
	void add_error(const vsock&);

	int wait_for(int second, int ms = 0);
	int wait();

	bool can_read(const vsock&);
	bool can_write(const vsock&);
	bool is_error(const vsock&);

private:
	struct _impl;
	_impl* _pp;
};

#ifdef WIN32 // Windows: IOCP. Coming soon...

#else // Linux: epoll
#include <sys/epoll.h>
#include <functional>

class epoll
{
public:
    epoll(int MaxListen);
    // EPOLLIN, EPOLLOUT, ...
    int add(vsock& v,int event);
    int mod(vsock& v,int event);
    int del(vsock& v,int event);

    // >0: Event counts.
    // =0: Timeout.
    // <0: Error.
    // Set timeout to -1 for infinity waiting.
    // Call handle() to handle events
	int wait(int timeout);

	void handle(const std::function<void(vsock&,int)>& callback);

    ~epoll();
private:
	std::vector<struct epoll_event> _evec;
	int _n;
    int _fd;
};
#endif // End of Platform specific

/// Net Tools

// Return:
// >=0: Number of fetched results from getaddrinfo() call.
// -1: getaddrinfo() call failed.
int DNSResolve(const std::string& HostName, std::vector<std::string>& _out_IPStrVec);

// A wrapper of the vector version of DNSResolve. 
// _out_IPStr will be assigned with the first result in vector.
// Return:
// 0: Success.
// -1: getaddrinfo() call failed.
// -2: Failed to resolve. (No results in vector)
int DNSResolve(const std::string& HostName,std::string& _out_IPStr);

#endif // _gsock_h