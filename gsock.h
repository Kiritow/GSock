/** General Socket Wrapper
*   Created By Kiritow. (https://github.com/kiritow)
*   Licensed under MIT
*/

#ifndef _gsock_h
#define _gsock_h

#include <cstdint>
#include <string>

class vsock
{
protected:
    vsock();
    vsock(const vsock&)=delete;
    vsock& operator = (const vsock&)=delete;
    vsock(vsock&&);
    vsock& operator = (vsock&&);
    ~vsock();
    
    vsock(int);
    
	struct _impl;
	_impl* _vp;
};

class sock : public vsock
{
public:
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
    
    /// Return:
    /// 0: Success. No Error.
    /// -1: getlocalname() or getpeername() call error. See errno.
    /// -2: Socket not created.
    int getlocal(std::string& IPStr,int& Port);
    int getpeer(std::string& IPStr,int& Port);
    
    friend class serversock;
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
};

class udpsock : public vsock
{
public:
	udpsock();
	
	/// Use udp socket as tcp socket. (but of course it is not).
	/// connect call just copy the target socket data to kernel. See connect() for more info.
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
};

/// Select
class selector
{
public:
	selector();
	void clear();
	void add_read(const vsock&);
	void add_write(const vsock&);
	void add_error(const vsock&);
	int select(int);
private:
	struct _impl;
	_impl* _pp;
};

/// Net Tools
int DNSResolve(const std::string& HostName,std::string& _out_IPStr);

#endif // _gsock_h