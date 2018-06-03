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
};

class sock : public vsock
{
public:
    /// Return:
    /// 0: Connection Established. No Error.
    /// -1: connect() call error. See errno.
    /// -2: This socket has been connected before.
    /// -3: socket() call error. Failed to create socket. See errno.
	/// -4: IP Address invalid.
    int connect(const std::string& IPStr,int Port);

    /// Return:
    /// return what send() and recv() call returns.
    int send(const void* Buffer,int Length);
	int recv(void* Buffer, int MaxToRecv);

    int getsendtime(int& _out_Second,int& _out_uSecond);
    int getrecvtime(int& _out_Second,int& _out_uSecond);

    int setsendtime(int Second);
    int setrecvtime(int Second);
    
    /// Return:
    /// 0: Success. No Error.
    /// -1: getlocalname() or getpeername() call error. See errno.
    /// -2: Socket not created.
    int getlocal(std::string& IPStr,int& Port);
    int getpeer(std::string& IPStr,int& Port);
    
    friend class serversock;
private:
	struct _impl;
};

class serversock : public vsock
{
public:
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
};

class udpsock : public vsock
{
public:
	// use_family:
	// 0: Auto (Undecided now) (default)
	// 1: IPv4 (If family cannot be automatically decided, then IPv4 will be the default option)
	// 2: IPv6
 	udpsock(int use_family=0);
	
	/// Use udp socket as tcp socket. (but of course it is not).
	/// connect call just copy the target socket data to kernel. See connect() for more info.
	/// Return:
	/// -1: connect() error.
	/// -4: IP Address Invalid.
	int connect(const std::string& IPStr,int Port);
	int broadcast_at(int Port);
	
	/// Must be called in broadcast mode.
	int set_broadcast();

	/// Explict bind() call is only need when you have to receive data.
	int bind(int Port);

	int sendto(const std::string& IPStr, int Port, const void* buffer, int length);
	int broadcast(int Port,const void* buffer,int length);
	/// Must call bind() before calling recvfrom().
	int recvfrom(std::string& fromIP, int& fromPort, void* buffer, int bufferLength);
	
    /// send() and recv() should only be called after connect(). Or it will fail.
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

/// Net Tools
// Return:
// -1: getaddrinfo() call failed.
// Other: Number of fetched results from getaddrinfo() call.
int DNSResolve(const std::string& HostName, std::vector<std::string>& _out_IPStrVec);

// A wrapper of DNSResolve(...,std::vector<std::string>&)
// Return:
// -1: getaddrinfo() call failed.
// -2: Failed to resolve. (No results in vector)
// 0: Success.
int DNSResolve(const std::string& HostName,std::string& _out_IPStr);

#endif // _gsock_h