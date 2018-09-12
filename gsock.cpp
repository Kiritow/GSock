/** General Socket Wrapper
*   Created By Kiritow. (https://github.com/kiritow)
*   Licensed under MIT
*/

/** See VERSION for version information */

#include "gsock.h"

#ifdef GSOCK_DEBUG
#pragma message("GSock Debug mode compiled in")
#include <cstdio>
#define myliblog(fmt,...) printf("<GSock|%s> " fmt,__func__,##__VA_ARGS__)
#define myliblog_ex(cond,fmt,...) do{if(cond){myliblog(fmt,##__VA_ARGS__);}}while(0)
#else
#define myliblog(fmt,...)
#define myliblog_ex(cond,fmt,...)
#endif

#ifdef _WIN32
/* _WIN32_WINNT defines
Windows XP = 0x0501
Windows Server 2003 = 0x0502
Windows Vista, Windows Server 2008 = 0x0600
Windows 7 = 0x0601
Windows 8 = 0x0602
Windows 8.1 = 0x0603
Windows 10 = 0x0A00
*/
// Using Win10 by default
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef _MSC_VER
#pragma comment(lib,"ws2_32.lib")
#endif
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#define closesocket close
using BYTE = unsigned char;
#define WSAGetLastError() errno
#endif

#include <cstring> /// memset
#include <string>
#include <stdexcept>
#include <vector>

int InitNativeSocket()
{
	myliblog("sockaddr %d sockaddr_in %d sockaddr_in6 %d\n", sizeof(sockaddr), sizeof(sockaddr_in), sizeof(sockaddr_in6));
	/// Windows Platform need WinSock2.DLL initialization.
#ifdef _WIN32
	WORD wd;
	WSAData wdt;
	wd = MAKEWORD(2, 2);
	int ret = WSAStartup(wd, &wdt);

	myliblog("WSAStartup() Returns: %d\n", ret);

	if (ret < 0)
	{
		myliblog("WSAGetLastError: %d\n", WSAGetLastError());
		return -1;
	}
#endif

	return 0;
}

class _init_winsock2_2_class
{
public:
    _init_winsock2_2_class()
    {
		if (InitNativeSocket() < 0)
		{
			throw std::runtime_error("Unable to Initialize native socket libray.");
		}
    }
    ~_init_winsock2_2_class()
    {
        /// Windows Platform need WinSock2.DLL clean up.
#ifdef _WIN32
        WSACleanup();
        myliblog("WSACleanup() called.\n");
#endif
    }
} _init_winsock2_2_obj;

static inline const char* get_family_name(int family)
{
	switch (family)
	{
	case AF_INET:
		return "AF_INET";
	case AF_INET6:
		return "AF_INET6";
	default:
		return "Unknown";
	}
}

int GetNativeErrCode()
{
#ifdef _WIN32
	return WSAGetLastError();
#else
	return errno;
#endif
}



gerrno TranslateNativeErrToGErr(int native_errcode)
{
	switch (native_errcode)
	{
#ifdef _WIN32
	case WSAEWOULDBLOCK:
		return gerrno::WouldBlock;
	case WSAEINPROGRESS:
		return gerrno::InProgress;
	case WSAEALREADY:
		return gerrno::Already;
	case WSAEISCONN:
		return gerrno::IsConnected;
	case WSAEINTR:
		return gerrno::Interrupted;
#else
	case EWOULDBLOCK: // EAGAIN == EWOULDBLOCK
		return gerrno::WouldBlock;
	case EINPROGRESS:
		return gerrno::InProgress;
	case EALREADY:
		return gerrno::Already;
	case EISCONN:
		return gerrno::IsConnected;
	case EINTR:
		return gerrno::Interrupted;
#endif
	default:
		myliblog("Unknown Error Code: %d\n", native_errcode);
		return gerrno::UnknownError;
	}
}

struct vsock::_impl
{
	int sfd;
	bool created;
	bool nonblocking;

	// Does not set "nonblocking" flag.
	int doSetNonblocking()
	{
#ifdef _WIN32
		u_long mode = 1;
		if (ioctlsocket(sfd, FIONBIO, &mode) == 0)
		{
			return 0;
		}
		else
		{
			return -1;
		}
#else
		int flag = fcntl(sfd, F_GETFL, 0);
		if (flag < 0) return -1;
		flag |= O_NONBLOCK;
		if (fcntl(sfd, F_SETFL, flag) < 0) return -1;
		return 0;
#endif
	}
};

vsock::vsock() : _vp(new _impl)
{
	_vp->created=false;
	_vp->nonblocking = false;
}

vsock::vsock(vsock&& v)
{
	_vp=v._vp;
	v._vp=nullptr;
}

vsock& vsock::operator = (vsock&& v)
{
	this->~vsock();
	_vp=v._vp;
	v._vp=nullptr;
	return *this;
}

int vsock::setNonblocking()
{
	if (!_vp->nonblocking)
	{
		if (_vp->created)
		{
			if (_vp->doSetNonblocking() == 0)
			{
				_vp->nonblocking = true;
				return 0;
			}
			else
			{
				// Failed to set non-blocking.
				return -1;
			}
		}
		else
		{
			// Socket is not created yet. Just mark it.
			_vp->nonblocking = true;
			return 0;
		}
	}
	else
	{
		// Socket is already in non-blocking mode.
		return 0;
	}
}

bool vsock::isNonblocking()
{
	return _vp->nonblocking;
}

vsock::~vsock()
{
	if(_vp)
	{
		if(_vp->created)
		{
			myliblog("Socket closed: [%d] with _vp %p\n",_vp->sfd,_vp);
			closesocket(_vp->sfd);
			
			_vp->created=false;
		}
		
		delete _vp;
		_vp=nullptr;
	}
}

struct sock::_impl
{
	static int create_socket(vsock::_impl* _vp, int af_protocol);

	static int connect_ipv4(vsock::_impl* _vp,const std::string& IPStr, int Port);
	static int connect_ipv6(vsock::_impl* _vp,const std::string& IPStr, int Port);

	static int connect_real(vsock::_impl* _vp, int af_protocol, const sockaddr* paddr, int size);
};

// static
int sock::_impl::create_socket(vsock::_impl* _vp, int af_protocol)
{
	// If socket is not created, then create it.
	if (!_vp->created)
	{
		_vp->sfd = socket(af_protocol, SOCK_STREAM, 0);
		if (_vp->sfd < 0)
		{
			myliblog("socket() returns %d. WSAGetLastError: %d\n", _vp->sfd, WSAGetLastError());
			return GSOCK_ERROR_CREAT;
		}
		if (_vp->nonblocking && _vp->doSetNonblocking() != 0)
		{
			myliblog("Failed to set socket to nonblocking with _vp %p\n", _vp);
			// close this socket to avoid fd leak.
			closesocket(_vp->sfd);
			return GSOCK_ERROR_SETMODE;
		}

		myliblog("Socket <%s> created: [%d] with _vp %p. %s\n",
			(af_protocol == AF_INET ? "IPv4" : "IPv6"),
			_vp->sfd, _vp, (_vp->nonblocking ? "NonBlocking" : "Blocking"));
		_vp->created = true;
	}

	return 0;
}

// static
int sock::_impl::connect_ipv4(vsock::_impl* _vp, const std::string& IPStr, int Port)
{
	struct sockaddr_in saddr;

	memset(&saddr, 0, sizeof(saddr));
	if (inet_pton(AF_INET, IPStr.c_str(), &(saddr.sin_addr.s_addr)) != 1)
	{
		return GSOCK_INVALID_IP;
	}
	saddr.sin_port = htons(Port);
	saddr.sin_family = AF_INET;

	// only returns -1 or 0
	return connect_real(_vp, AF_INET, (sockaddr*)&saddr, sizeof(saddr));
}

// static
int sock::_impl::connect_ipv6(vsock::_impl* _vp, const std::string& IPStr, int Port)
{
	struct sockaddr_in6 saddr;

	memset(&saddr, 0, sizeof(saddr));
	if (inet_pton(AF_INET6, IPStr.c_str(), &(saddr.sin6_addr)) != 1)
	{
		return GSOCK_INVALID_IP;
	}
	saddr.sin6_port = htons(Port);
	saddr.sin6_family = AF_INET6;

	// only returns -1 or 0
	return connect_real(_vp, AF_INET6, (sockaddr*)&saddr, sizeof(saddr));
}

// static
int sock::_impl::connect_real(vsock::_impl* _vp, int af_protocol, const sockaddr* paddr, int namelen)
{
	// Create socket
	int ret = create_socket(_vp, af_protocol);
	if (ret != 0) return ret;
	return ::connect(_vp->sfd, paddr, namelen);
}

int sock::connect(const std::string& IPStr,int Port)
{
    myliblog("sock::connect() %p\n",this);

	if (_vp->nonblocking)
	{
		return GSOCK_MISMATCH_MODE;
	}

	if (_vp->created)
	{
		return GSOCK_INVALID_SOCKET;
	}

	if (IPStr.find(":") != std::string::npos)
	{
		// Maybe IPv6
		return sock::_impl::connect_ipv6(_vp, IPStr, Port);
	}
	else
	{
		// Maybe IPv4
		return sock::_impl::connect_ipv4(_vp, IPStr, Port);
	}
}

struct NBConnectResult::_impl
{
	int sfd;
	struct sockaddr_in saddr;
	struct sockaddr_in6 saddr6;
	bool isv4;
	// 0: Not used.
	// 1: running
	// 2: finished, connected.
	// 3: finished, failed. 
	int status;

	gerrno errcode;

	void update();
};

void NBConnectResult::_impl::update()
{
	// Already finished.
	if (status > 1) return;

	int ret;
	if (isv4)
	{
		ret = connect(sfd, (sockaddr*)&saddr, sizeof(saddr));
	}
	else
	{
		ret = connect(sfd, (sockaddr*)&saddr6, sizeof(saddr6));
	}

	if (ret == 0)
	{
		status = 2;
	}
	else // ret == -1
	{
		gerrno err = TranslateNativeErrToGErr(GetNativeErrCode());
		errcode = err;

		if (err == gerrno::InProgress || err == gerrno::WouldBlock || err == gerrno::Already)
		{
			status = 1;
		}
		else if (err == gerrno::IsConnected)
		{
			status = 2;
		}
		else
		{
			status = 3;
		}
	}

	myliblog("NBConnectResult Status updated to %d\n", status);
}

NBConnectResult::NBConnectResult() : _p(new _impl)
{
	_p->status = 0;
}

bool NBConnectResult::isFinished()
{
	_p->update();
	return (_p->status > 1);
}

bool NBConnectResult::isSuccess()
{
	return (_p->status == 2);
}

gerrno NBConnectResult::getErrCode()
{
	return _p->errcode;
}

void NBConnectResult::wait()
{
	while (!isFinished());
}

struct NBSendResult::_impl
{
	int sfd;
	const char* ptr;
	int total;
	int done;

	// When work together with epoll at ET mode, 
	//   setting this flag can avoid infinite EAGAIN send loop. 
	//   (caused by buffer full or something else)
	bool stopAtEdge;

	// 0: Not started.
	// 1: Data is being sent
	// 2: Data sent without error.
	// 3: Error occurs.
	int status;

	gerrno errcode;

	void update();
};

void NBSendResult::_impl::update()
{
	if (status > 1) return;

	int ret = send(sfd, ptr + done, total - done, 0);
	if (ret > 0)
	{
		done += ret;
		if (done == total)
		{
			status = 2;
		}
		else
		{
			status = 1;
		}
	}
	else if (ret == 0)
	{
		status = 3;
		errcode = gerrno::OK;
	}
	else // ret == -1
	{
		gerrno err = TranslateNativeErrToGErr(GetNativeErrCode());
		errcode = err;

		if (err == gerrno::WouldBlock)
		{
			if (stopAtEdge)
			{
				status = 3;
			}
			else
			{
				status = 1;
			}
		}
		else
		{
			status = 3;
		}
	}

	myliblog("NBSendResult status updated to %d\n", status);
}

NBSendResult::NBSendResult() : _p(new _impl)
{
	_p->status = 0;
	_p->stopAtEdge = false;
}

void NBSendResult::setStopAtEdge(bool flag)
{
	_p->stopAtEdge = true;
}

bool NBSendResult::isFinished()
{
	_p->update();
	return (_p->status > 1);
}

void NBSendResult::wait()
{
	while (!isFinished());
}

bool NBSendResult::isSuccess()
{
	return (_p->status == 2);
}

int NBSendResult::getBytesDone()
{
	return _p->done;
}

gerrno NBSendResult::getErrCode()
{
	return _p->errcode;
}

struct NBRecvResult::_impl
{
	int sfd;
	char* ptr;
	int maxsz;
	int done;

	// When work together with epoll at ET mode, setting this flag can avoid infinite EAGAIN recv loop.
	bool stopAtEdge;

	// 0: Not started.
	// 1: Data is being sent
	// 2: Data sent without error.
	// 3: Error occurs.
	int status;

	gerrno errcode;

	void update();
};

void NBRecvResult::_impl::update()
{
	if (status > 1) return;

	int ret = recv(sfd, ptr + done, maxsz - done, 0);
	if (ret > 0)
	{
		done += ret;
		if (done == maxsz)
		{
			status = 2;
		}
		else
		{
			status = 1;
		}
	}
	else if (ret == 0)
	{
		status = 3;
		errcode = gerrno::OK;
	}
	else // ret == -1
	{
		gerrno err = TranslateNativeErrToGErr(GetNativeErrCode());
		errcode = err;

		if (err == gerrno::WouldBlock)
		{
			if (stopAtEdge)
			{
				status = 3;
			}
			else
			{
				status = 1;
			}
		}
		else
		{
			status = 3;
		}
	}

	myliblog("NBRecvResult status updated to %d\n", status);
}

NBRecvResult::NBRecvResult() : _p(new _impl)
{
	_p->status = 0;
	_p->stopAtEdge = false;
}

void NBRecvResult::setStopAtEdge(bool flag)
{
	_p->stopAtEdge = flag;
}

bool NBRecvResult::isFinished()
{
	_p->update();
	return (_p->status > 1);
}

void NBRecvResult::wait()
{
	while (!isFinished());
}

bool NBRecvResult::isSuccess()
{
	return (_p->status == 2);
}

int NBRecvResult::getBytesDone()
{
	return _p->done;
}

gerrno NBRecvResult::getErrCode()
{
	return _p->errcode;
}

NBConnectResult sock::connect_nb(const std::string& IPStr, int Port)
{
	NBConnectResult res;
	int xret;

	if (IPStr.find(":") != std::string::npos)
	{
		// Maybe IPv6
		memset(&(res._p->saddr6), 0, sizeof(res._p->saddr6));
		if (inet_pton(AF_INET6, IPStr.c_str(), &(res._p->saddr6.sin6_addr)) != 1)
		{
			// Failed.
			res._p->status = 3;
			res._p->errcode = (gerrno)GSOCK_INVALID_IP;
			return res;
		}
		res._p->saddr6.sin6_port = htons(Port);
		res._p->saddr6.sin6_family = AF_INET6;

		res._p->isv4 = false;
		xret = _impl::connect_real(_vp, AF_INET6, (sockaddr*)&(res._p->saddr6), sizeof(res._p->saddr6));
		res._p->sfd = _vp->sfd;
	}
	else
	{
		// Maybe IPv4
		memset(&(res._p->saddr), 0, sizeof(res._p->saddr));
		if (inet_pton(AF_INET, IPStr.c_str(), &(res._p->saddr.sin_addr.s_addr)) != 1)
		{
			// Failed.
			res._p->status = 3;
			res._p->errcode = (gerrno)GSOCK_INVALID_IP;
			return res;
		}
		res._p->saddr.sin_port = htons(Port);
		res._p->saddr.sin_family = AF_INET;

		res._p->isv4 = true;
		xret = _impl::connect_real(_vp, AF_INET, (sockaddr*)&(res._p->saddr), sizeof(res._p->saddr));
		res._p->sfd = _vp->sfd;
	}

	if (xret == 0)
	{
		res._p->status = 2; // Socket is connected immediately! Amazing!!
	}
	else if (xret == -1)
	{
		res._p->status = 1;
	}
	else // xret is a GSock error
	{
		// Failed
		res._p->status = 3;
		res._p->errcode = (gerrno)xret;
	}
	return res;
}

int sock::send(const void* Buffer,int Length)
{
    return ::send(_vp->sfd,(const char*)Buffer,Length,0);
}

int sock::recv(void* Buffer,int MaxToRecv)
{
    return ::recv(_vp->sfd,(char*)Buffer,MaxToRecv,0);
}

NBSendResult sock::send_nb(const void* Buffer, int Length)
{
	NBSendResult res;
	res._p->ptr = (const char*)Buffer;
	res._p->total = Length;
	res._p->done = 0;
	res._p->sfd = _vp->sfd;
	
	res._p->update();
	return res;
}

NBRecvResult sock::recv_nb(void* Buffer, int MaxToRecv)
{
	NBRecvResult res;
	res._p->ptr = (char*)Buffer;
	res._p->maxsz = MaxToRecv;
	res._p->done = 0;
	res._p->stopAtEdge = false;
	res._p->sfd = _vp->sfd;

	res._p->update();
	return res;
}

int sock::getsendtime(int& _out_Second, int& _out_uSecond)
{
#ifdef _WIN32
    int result;
    socklen_t _not_used_t = sizeof(result);
    int ret = getsockopt(_vp->sfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&result, &_not_used_t);
    if (ret<0) return ret;
    _out_Second = result / 1000;
    _out_uSecond = result % 1000;
#else
    struct timeval outtime;
    socklen_t _not_used_t = sizeof(outtime);
    int ret = getsockopt(_vp->sfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&outtime, &_not_used_t);
    if (ret<0) return ret;
    _out_Second = outtime.tv_sec;
    _out_uSecond = outtime.tv_usec;
#endif
    return ret;
}

int sock::getrecvtime(int& _out_Second, int& _out_uSecond)
{
#ifdef _WIN32
    int result;
    socklen_t _not_used_t = sizeof(result);
    int ret = getsockopt(_vp->sfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&result, &_not_used_t);
    if (ret<0) return ret;
    _out_Second=result/1000;
    _out_uSecond = result % 1000;
#else
    struct timeval outtime;
    socklen_t _not_used_t = sizeof(outtime);
    int ret = getsockopt(_vp->sfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&outtime, &_not_used_t);
    if (ret<0) return ret;
    _out_Second=outtime.tv_sec;
    _out_uSecond=outtime.tv_usec;
#endif
    return ret;
}

int sock::setsendtime(int Second, int Millisecond)
{
#ifdef _WIN32
    int outtime = Second * 1000 + Millisecond % 1000;
#else
    struct timeval outtime;
    outtime.tv_sec = Second;
    outtime.tv_usec = Millisecond;
#endif

    return setsockopt(_vp->sfd,SOL_SOCKET,SO_SNDTIMEO,(const char*)&outtime,sizeof(outtime));
}

int sock::setrecvtime(int Second, int Millisecond)
{
#ifdef _WIN32
    int outtime = Second * 1000 + Millisecond % 1000;
#else
    struct timeval outtime;
    outtime.tv_sec = Second;
    outtime.tv_usec = Millisecond;
#endif

    return setsockopt(_vp->sfd,SOL_SOCKET,SO_RCVTIMEO,(const char*)&outtime,sizeof(outtime));
}

int sock::setkeepalive(bool op)
{
    int option = op ? 1 : 0;
    return setsockopt(_vp->sfd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&option, sizeof(option));
}

//forgive me, but writing code in hospital is really not a good experience.
using _sock_getname_callback_t = decltype(getsockname);

union _sock_getname_pack
{
	sockaddr saddr;
	sockaddr_in saddr4;
	sockaddr_in6 saddr6;
};

static int _sock_getname_call(int sfd,std::string& ip,int& port,_sock_getname_callback_t fn)
{
	_sock_getname_pack pack;
	socklen_t saddrlen=sizeof(pack);
	memset(&pack,0,saddrlen);
	int ret=fn(sfd,&pack.saddr,&saddrlen);
	if(ret<0) return ret; //don't bother errno. stop here.
	if (pack.saddr.sa_family == AF_INET)
	{
		struct sockaddr_in* paddr = &pack.saddr4;
		char ip_buff[64] = { 0 };
		const char* pret = inet_ntop(AF_INET, &(paddr->sin_addr), ip_buff, 64);
		if (pret)
		{
			ip = std::string(ip_buff);
			port = ntohs(paddr->sin_port);
			return 0;
		}
		else
		{
			// inet_ntop call failed.
			return GSOCK_ERROR_NTOP;
		}
	}
	else if (pack.saddr.sa_family == AF_INET6)
	{
		struct sockaddr_in6* paddr = &pack.saddr6;
		char ip_buff[128] = { 0 };
		const char* pret = inet_ntop(AF_INET6, &(paddr->sin6_addr), ip_buff, 128);
		if (pret)
		{
			ip = std::string(ip_buff);
			port = ntohs(paddr->sin6_port);
			return 1;
		}
		else
		{
			// inet_ntop call failed.
			return GSOCK_ERROR_NTOP;
		}
	}
	else
	{
		// protocol not supported.
		return GSOCK_UNKNOWN_PROTOCOL;
	}
}

int sock::getlocal(std::string& IPStr,int& Port)
{
	if(!(_vp->created))
	{
		return GSOCK_INVALID_SOCKET;
	}
	return _sock_getname_call(_vp->sfd,IPStr,Port,getsockname);
}

int sock::getpeer(std::string& IPStr,int& Port)
{
	if(!(_vp->created))
	{
		return GSOCK_INVALID_SOCKET;
	}
	return _sock_getname_call(_vp->sfd,IPStr,Port,getpeername);
}

struct serversock::_impl
{
public:
	int protocol;
	bool is_protocol_decided;

	int create_socket(vsock::_impl* _vp)
	{
		if (_vp->created)
		{
			return GSOCK_INVALID_SOCKET;
		}
		_vp->sfd = socket(protocol, SOCK_STREAM, 0);
		if (_vp->sfd<0)
		{
			myliblog("socket() returns %d. WSAGetLastError: %d\n", _vp->sfd, WSAGetLastError());
			return GSOCK_ERROR_CREAT;
		}
        myliblog("Socket <%s> created: [%d] with _vp %p\n", protocol == AF_INET ? "IPv4" : "IPv6", _vp->sfd, _vp);
		_vp->created = true;
		return GSOCK_OK;
	}
};

serversock::serversock(int use_family) :_pp(new _impl)
{
	if (use_family==1)
	{
		_pp->protocol = AF_INET;
		_pp->is_protocol_decided = true;
		myliblog("Protocol decided to %s in serversock %p\n", get_family_name(_pp->protocol), this);
	}
	else if (use_family == 2)
	{
		_pp->protocol = AF_INET6;
		_pp->is_protocol_decided = true;
		myliblog("Protocol decided to %s in serversock %p\n", get_family_name(_pp->protocol), this);
	}
	else
	{
		_pp->is_protocol_decided = false;
	}
}

serversock::~serversock()
{
    if (_pp)
    {
        delete _pp;
        _pp = nullptr;
    }
}

int serversock::bind(int Port)
{
    myliblog("serversock::bind() %p\n",this);

	if (!_vp->created)
	{
		if (!_pp->is_protocol_decided)
		{
			_pp->protocol = AF_INET;
			_pp->is_protocol_decided = true;
			myliblog("Protocol decided to %s in serversock %p\n", get_family_name(_pp->protocol), this);
		}
		int ret = _pp->create_socket(_vp);
		if (ret < 0)
			return ret;
	}
    
	if (_pp->protocol == AF_INET)
	{
		sockaddr_in saddr;

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_addr.s_addr = INADDR_ANY;
		saddr.sin_port = htons(Port);
		saddr.sin_family = AF_INET;
		return ::bind(_vp->sfd, (sockaddr*)&saddr, sizeof(saddr));
	}
	else
	{
		sockaddr_in6 saddr;

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin6_addr = in6addr_any;
		saddr.sin6_port = htons(Port);
		saddr.sin6_family = AF_INET6;
		return ::bind(_vp->sfd, (sockaddr*)&saddr, sizeof(saddr));
	}
}

int serversock::set_reuse()
{
	if (!_vp->created)
	{
		if (!_pp->is_protocol_decided)
		{
			_pp->protocol = AF_INET;
			_pp->is_protocol_decided = true;
			myliblog("Protocol decided to %s in serversock %p\n", get_family_name(_pp->protocol), this);
		}

		int ret = _pp->create_socket(_vp);
		if (ret < 0)
			return ret;
	}
    socklen_t opt=1;
    return setsockopt(_vp->sfd,SOL_SOCKET,SO_REUSEADDR,(const char*)&opt,sizeof(opt));
}

int serversock::listen(int MaxCount)
{
	if (!_vp->created)
	{
		// Socket is not created. Call bind() first.
		return GSOCK_INVALID_SOCKET;
	}
    return ::listen(_vp->sfd,MaxCount);
}

struct NBAcceptResult::_impl
{
	int sfd;

	bool stopAtEdge;

	// For client use
	bool isv4;
	sockaddr_in saddr;
	sockaddr_in6 saddr6;
	socklen_t saddrsz;

	sock* out_binding;
	int* out_binding_sfd;
	bool* out_binding_created;

	// 0 Not started.
	// 1 Accepting
	// 2 Accept success.
	// 3 Accept failed.
	int status;
	gerrno errcode;

	void update();
};

void NBAcceptResult::_impl::update()
{
	if (status > 1) return;

	int ret;
	if (isv4)
	{
		ret = accept(sfd, (sockaddr*)&saddr, &saddrsz);
	}
	else
	{
		ret = accept(sfd, (sockaddr*)&saddr6, &saddrsz);
	}

	if (ret >= 0)
	{
		// This is a BUG!! Fixed.
		*out_binding_sfd = ret;
		*out_binding_created = true;
		status = 2;
	}
	else // ret == -1
	{
		gerrno err = TranslateNativeErrToGErr(GetNativeErrCode());
		errcode = err;
		if (err == gerrno::InProgress || err == gerrno::Already)
		{
			status = 1;
		}
		else if (err == gerrno::WouldBlock)
		{
			if (stopAtEdge)
			{
				status = 3;
			}
			else
			{
				status = 1;
			}
		}
		else
		{
			status = 3;
		}
	}

	myliblog("NBAcceptResult status updated to %d\n", status);
}

NBAcceptResult::NBAcceptResult() : _sp(new _impl)
{
	_sp->status = 0;
	_sp->stopAtEdge = false;
}

void NBAcceptResult::stopAtEdge(bool flag)
{
	_sp->stopAtEdge = flag;
}

bool NBAcceptResult::isFinished()
{
	_sp->update();
	return (_sp->status > 1);
}

bool NBAcceptResult::isSuccess()
{
	return (_sp->status == 2);
}

sock& NBAcceptResult::get()
{
	return *(_sp->out_binding);
}

gerrno NBAcceptResult::getErrCode()
{
	return _sp->errcode;
}

int serversock::accept(sock& _out_s)
{
    if( (!_vp->created) || (_out_s._vp->created) )
    {
        /// _out_s has been connected.
        return GSOCK_INVALID_SOCKET;
    }

    sock s; /// empty socket.

    sockaddr_in saddr;
	sockaddr_in6 saddr6;
	socklen_t saddrsz = (_pp->protocol == AF_INET) ? sizeof(saddr) : sizeof(saddr6);
    
	int ret;
	if (_pp->protocol == AF_INET)
	{
		ret= ::accept(_vp->sfd, (sockaddr*)&(saddr), &saddrsz);
	}
	else
	{
		ret = ::accept(_vp->sfd, (sockaddr*)&(saddr6), &saddrsz);
	}
	
    if(ret<0)
    {
        /// accept() call failed.
        myliblog("accept() returns %d. WSAGetLastError: %d\n",ret,WSAGetLastError());
        return GSOCK_API_ERROR;
    }
    else
    {
        s._vp->sfd=ret;
        s._vp->created=true;

        myliblog("Socket opened: [%d] as sock::_vp %p by serversock::_vp: %p\n",s._vp->sfd,s._vp,_vp);

        /// Move resource.
        _out_s=std::move(s);
        return GSOCK_OK;
    }
}

NBAcceptResult serversock::accept_nb(sock& _out_s)
{
	NBAcceptResult res;
	if ((!_vp->created) || (_out_s._vp->created))
	{
		/// _out_s has been connected.
		res._sp->status = 3;
		res._sp->errcode = (gerrno)GSOCK_INVALID_SOCKET;
		return res;
	}

	res._sp->sfd = _vp->sfd;
	res._sp->out_binding = &_out_s;
	res._sp->out_binding_sfd = &(_out_s._vp->sfd);
	res._sp->out_binding_created = &(_out_s._vp->created);
	if (_pp->protocol == AF_INET)
	{
		res._sp->isv4 = true;
		res._sp->saddrsz = sizeof(res._sp->saddr);
		res._sp->update();	
	}
	else
	{
		res._sp->isv4 = false;
		res._sp->saddrsz = sizeof(res._sp->saddr6);
		res._sp->update();
	}

	return res;	
}

struct udpsock::_impl
{
	int protocol;
	bool is_protocol_decided;

    _impl()
    {
        is_protocol_decided = false;
    }

    // This function is now an internal function and should not be called outside _impl.
	int _make_decided(vsock::_impl* _vp)
	{
		if (_vp->created)
		{
			return GSOCK_INVALID_SOCKET;
		}
		else
		{
			_vp->sfd = socket(protocol, SOCK_DGRAM, 0);
			if (_vp->sfd < 0)
			{
				return GSOCK_ERROR_CREAT;
			}
			_vp->created = true;
            myliblog("Socket <%s> created: [%d] with _vp %p\n", protocol == AF_INET ? "IPv4" : "IPv6", _vp->sfd, _vp);
			return GSOCK_OK;
		}
	}

    // Decide the protocol
    // Return:
    // GSOCK_OK
    // GSOCK_MISMATCH_PROTOCOL
    // GSOCK_INVALID_SOCKET
    // GSOCK_ERROR_CREAT
    int try_decide(vsock::_impl* _vp, int in_protocol)
    {
        if (is_protocol_decided)
        {
            if (in_protocol == protocol)
            {
                return GSOCK_OK;
            }
            else
            {
                return GSOCK_MISMATCH_PROTOCOL;
            }
        }

        protocol = in_protocol;

        // Try it
        int ret = _make_decided(_vp);
        if (ret == GSOCK_OK)
        {
            is_protocol_decided = true;
            myliblog("Protocol decided to %s in udpsock with _vp %p \n", get_family_name(protocol), _vp);
        }

        return ret;
    }

};

udpsock::udpsock(int use_family) : _pp(new _impl)
{
	if (use_family == 1)
	{
		_pp->try_decide(_vp, AF_INET);
        myliblog("Protocol decided to %s in udpsock %p\n", get_family_name(_pp->protocol), this);
	}
	else if (use_family == 2)
	{
        _pp->try_decide(_vp, AF_INET6);
	}
	else
	{
		_pp->is_protocol_decided = false;
	}
}

udpsock::~udpsock()
{
	if (_pp)
	{
		delete _pp;
		_pp = nullptr;
	}
}

// Convert from IPStr to sockaddr
// Parameters:
// flag_ipv46: 
//		-1: Undecided 
//		0: IPv4 
//		1: IPv6
// Return:
// -1: inet_pton() call failed.
// 0: Success, IPv4
// 1: Success, IPv6
static int convert_ipv46(const std::string& IPStr, int Port,
	struct sockaddr*& _out_psockaddr, int& _out_szsockaddr,
	struct sockaddr_in* paddr, struct sockaddr_in6* paddr6, int flag_ipv46)
{
	if ( (flag_ipv46==1) ||
		 ( (flag_ipv46==-1) && (IPStr.find(":") != std::string::npos) ) 
		)
	{
		// Maybe IPv6
		memset(paddr6, 0, sizeof(sockaddr_in6));
		if (inet_pton(AF_INET6, IPStr.c_str(), &(paddr6->sin6_addr)) != 1)
		{
			return -1;
		}
		paddr6->sin6_port = htons(Port);
		paddr6->sin6_family = AF_INET6;

		_out_psockaddr = (sockaddr*)paddr6;
		_out_szsockaddr = sizeof(sockaddr_in6);
		return 1;
	}
	else // flag_ipv46==-1 && IPStr.find(":")==string::npos, flag_ipv46==0
	{
		// Maybe IPv4
		memset(paddr, 0, sizeof(sockaddr_in));
		if (inet_pton(AF_INET, IPStr.c_str(), &(paddr->sin_addr)) != 1)
		{
			return -1;
		}
		paddr->sin_port = htons(Port);
		paddr->sin_family = AF_INET;

		_out_psockaddr = (sockaddr*)paddr;
		_out_szsockaddr = sizeof(sockaddr_in);
		return 0;
	}
}

// Convert from sockaddr to IPStr
// Return:
// -1: inet_ntop() call failed.
// -2: Unsupported protocol
// 0: Success, IPv4
// 1: Success, IPv6
static int convertback_ipv46(const sockaddr* paddr, std::string& _out_IPStr)
{
	char buff[128] = { 0 };
	if (paddr->sa_family == AF_INET)
	{
		if (inet_ntop(AF_INET, &(((const sockaddr_in*)paddr)->sin_addr), buff, 128)!=NULL)
		{
			_out_IPStr = std::move(std::string(buff));
			return 0;
		}
		else return -1;
	}
	else if (paddr->sa_family == AF_INET6)
	{
		if (inet_ntop(AF_INET6, &(((const sockaddr_in6*)paddr)->sin6_addr), buff, 128) != NULL)
		{
			_out_IPStr = std::move(std::string(buff));
			return 1;
		}
		else return -1;
	}
	else return -2;
}

int udpsock::connect(const std::string& IPStr,int Port)
{
	sockaddr_in saddr;
	sockaddr_in6 saddr6;
	sockaddr* paddr;
	int addrsz;

	int ret = convert_ipv46(IPStr, Port, paddr, addrsz, &saddr, &saddr6,
		(_pp->is_protocol_decided) ? ((_pp->protocol == AF_INET) ? 0 : 1) : -1);

	if (ret < 0)
	{
		return GSOCK_INVALID_IP;
	}
	
    int cret = _pp->try_decide(_vp, (ret == 0) ? (AF_INET) : (AF_INET6));
    if (cret < 0)
    {
        return cret;
    }
	
	return ::connect(_vp->sfd, (const sockaddr*)paddr, addrsz);
}

int udpsock::broadcast_at(int Port)
{
	if (_pp->is_protocol_decided)
	{
		if (_pp->protocol == AF_INET)
		{
			sockaddr_in saddr;
			memset(&saddr, 0, sizeof(saddr));
			saddr.sin_family = AF_INET;
			saddr.sin_port = htons(Port);
			saddr.sin_addr.s_addr = INADDR_BROADCAST;

			return ::connect(_vp->sfd, (const sockaddr*)&saddr, sizeof(saddr));
		}
		else
		{
			myliblog("IPv6 does not support broadcast!\n");
            return GSOCK_BAD_PROTOCOL;
		}
	}
	else
	{
        int cret = _pp->try_decide(_vp, AF_INET);
		if (cret < 0)
		{
			return cret;
		}
        
        return broadcast_at(Port);
	}
}

int udpsock::set_broadcast()
{
	if (_pp->is_protocol_decided)
	{
		socklen_t opt = 1;
		return ::setsockopt(_vp->sfd, SOL_SOCKET, SO_BROADCAST, (const char*)&opt, sizeof(opt));
	}
	else
	{
        int cret = _pp->try_decide(_vp, AF_INET);
        if (cret < 0)
        {
            return cret;
        }

		return set_broadcast();
	}
}

int udpsock::bind(int Port)
{
	if (_pp->is_protocol_decided)
	{
		if (_pp->protocol == AF_INET)
		{
			sockaddr_in saddr;
			memset(&saddr, 0, sizeof(saddr));
			saddr.sin_family = AF_INET;
			saddr.sin_port = htons(Port);
			saddr.sin_addr.s_addr = INADDR_ANY;

			return ::bind(_vp->sfd, (const sockaddr*)&saddr, sizeof(saddr));
		}
		else
		{
			sockaddr_in6 saddr;
			memset(&saddr, 0, sizeof(saddr));
			saddr.sin6_family = AF_INET6;
			saddr.sin6_port = htons(Port);
			saddr.sin6_addr = in6addr_any;

			return ::bind(_vp->sfd, (const sockaddr*)&saddr, sizeof(saddr));
		}
	}
	else
	{
        int cret = _pp->try_decide(_vp, AF_INET);
        if (cret < 0)
        {
            return cret;
        }

		return bind(Port);
	}
}

int udpsock::sendto(const std::string& IPStr, int Port, const void* buffer, int length)
{
	sockaddr_in saddr;
	sockaddr_in6 saddr6;
	sockaddr* paddr;
	int addrsz;

	int ret = convert_ipv46(IPStr, Port, paddr, addrsz, &saddr, &saddr6,
		(_pp->is_protocol_decided) ? ((_pp->protocol == AF_INET) ? 0 : 1) : -1);
	if (ret < 0)
	{
		return GSOCK_INVALID_IP;
	}

    int cret = _pp->try_decide(_vp, AF_INET);
    if (cret < 0)
    {
        return cret;
    }

	return ::sendto(_vp->sfd, (const char*)buffer, length, 0, (const sockaddr*)paddr, addrsz);
}

int udpsock::broadcast(int Port,const void* buffer,int length)
{
	if (_pp->is_protocol_decided)
	{
		if (_pp->protocol == AF_INET)
		{
			sockaddr_in saddr;
			memset(&saddr, 0, sizeof(saddr));
			saddr.sin_family = AF_INET;
			saddr.sin_port = htons(Port);
			saddr.sin_addr.s_addr = INADDR_BROADCAST;
			return ::sendto(_vp->sfd, (const char*)buffer, length, 0, (const sockaddr*)&saddr, sizeof(saddr));
		}
		else
		{
			myliblog("IPv6 does not support broadcast!\n");
            return GSOCK_BAD_PROTOCOL;
		}
	}
	else
	{
        int cret = _pp->try_decide(_vp, AF_INET);
        if (cret < 0)
        {
            return cret;
        }

		return broadcast(Port, buffer, length);
	}
}

int udpsock::recvfrom(std::string& fromIP, int& fromPort, void* buffer, int bufferLength)
{
	if (_pp->is_protocol_decided)
	{
		if (_pp->protocol == AF_INET)
		{
			sockaddr_in saddr;
			socklen_t saddrlen = sizeof(saddr);
			int ret = ::recvfrom(_vp->sfd, (char*)buffer, bufferLength, 0, (sockaddr*)&saddr, &saddrlen);

			if (ret < 0)
			{
				return GSOCK_API_ERROR; /// don't bother errno.
			}

			int cret = convertback_ipv46((const sockaddr*)&saddr, fromIP);
			if (cret == -1)
			{
				return GSOCK_ERROR_NTOP;
			}
			else if (cret == -2)
			{
				return GSOCK_UNKNOWN_PROTOCOL;
			}
			fromPort = ntohs(saddr.sin_port);
			return ret;
		}
		else
		{
			sockaddr_in6 saddr;
			socklen_t saddrlen = sizeof(saddr);
			int ret = ::recvfrom(_vp->sfd, (char*)buffer, bufferLength, 0, (sockaddr*)&saddr, &saddrlen);

			if (ret < 0)
			{
				return ret; /// don't bother errno.
			}

			int cret = convertback_ipv46((const sockaddr*)&saddr, fromIP);
			if (cret == -1)
			{
				return GSOCK_ERROR_NTOP;
			}
			else if (cret == -2)
			{
				return GSOCK_UNKNOWN_PROTOCOL;
			}
			fromPort = ntohs(saddr.sin6_port);
			return ret;
		}
	}
	else
	{
        int cret = _pp->try_decide(_vp, AF_INET);
        if (cret < 0)
        {
            return cret;
        }

		return recvfrom(fromIP, fromPort, buffer, bufferLength);
	}
}

int udpsock::send(const void* buffer,int length)
{
	if (_pp->is_protocol_decided)
	{
		return ::send(_vp->sfd, (const char*)buffer, length, 0);
	}
	else
	{
		// if protocol is not decided, then socket is invalid. (Not Created)
		return GSOCK_INVALID_SOCKET;
	}
}

int udpsock::recv(void* buffer,int bufferLength)
{
	if (_pp->is_protocol_decided)
	{
		return ::recv(_vp->sfd, (char*)buffer, bufferLength, 0);
	}
	else
	{
		// same as udpsock::send
		return GSOCK_INVALID_SOCKET;
	}
}

// Select
struct selector::_impl
{
	fd_set readset, writeset, errorset;
	int readsz, writesz, errorsz;
};

selector::selector() : _pp(new _impl)
{
	clear();
}

selector::~selector()
{
	if (_pp)
	{
		delete _pp;
		_pp = nullptr;
	}
}

void selector::clear()
{
	FD_ZERO(&_pp->readset);
	FD_ZERO(&_pp->writeset);
	FD_ZERO(&_pp->errorset);
	_pp->readsz = _pp->writesz = _pp->errorsz = 0;
}

void selector::add_read(const vsock& v)
{
	if (v._vp->created)
	{
		FD_SET(v._vp->sfd, &_pp->readset);
		++_pp->readsz;
	}
}

void selector::add_write(const vsock& v)
{
	if (v._vp->created)
	{
		FD_SET(v._vp->sfd, &_pp->writeset);
		++_pp->writesz;
	}
}

void selector::add_error(const vsock& v)
{
	if (v._vp->created)
	{
		FD_SET(v._vp->sfd, &_pp->errorset);
		++_pp->errorsz;
	}
}

int selector::wait_for(int second, int ms)
{
	fd_set* pread = (_pp->readsz) ? (&_pp->readset) : NULL;
	fd_set* pwrite = (_pp->writesz) ? (&_pp->writeset) : NULL;
	fd_set* perr = (_pp->errorsz) ? (&_pp->errorset) : NULL;

	if (!(pread || pwrite || perr))
	{
		return 0;
	}

	struct timeval tval;
	tval.tv_sec = second;
	tval.tv_usec = ms;

	int ndfs = 0;
	return ::select(ndfs, pread, pwrite, perr, &tval);
}

int selector::wait()
{
	fd_set* pread = (_pp->readsz) ? (&_pp->readset) : NULL;
	fd_set* pwrite = (_pp->writesz) ? (&_pp->writeset) : NULL;
	fd_set* perr = (_pp->errorsz) ? (&_pp->errorset) : NULL;

	if (!(pread || pwrite || perr))
	{
		return 0;
	}

	int ndfs = 0;
	return ::select(ndfs, pread, pwrite, perr, NULL);
}

bool selector::can_read(const vsock& v)
{
	return FD_ISSET(v._vp->sfd, &_pp->readset);
}

bool selector::can_write(const vsock& v)
{
	return FD_ISSET(v._vp->sfd, &_pp->writeset);
}

bool selector::is_error(const vsock& v)
{
	return FD_ISSET(v._vp->sfd, &_pp->errorset);
}

#ifdef WIN32 // Windows: IOCP. Coming soon...

#else // Linux: epoll
#include <functional>

epoll::epoll(int MaxListen) : _evec(MaxListen)
{
	_fd = epoll_create(MaxListen); // this parameter is useless.
}
epoll::~epoll()
{
	close(_fd);
}
int epoll::add(vsock& v, int event)
{
	struct epoll_event ev;
	ev.events = event;
	ev.data.ptr = &v;
	return epoll_ctl(_fd, EPOLL_CTL_ADD, v._vp->sfd, &ev);
}
int epoll::mod(vsock& v, int event)
{
	struct epoll_event ev;
	ev.events = event;
	ev.data.ptr = &v;
	return epoll_ctl(_fd, EPOLL_CTL_MOD, v._vp->sfd, &ev);
}
int epoll::del(vsock& v)
{
	return epoll_ctl(_fd, EPOLL_CTL_DEL, v._vp->sfd, NULL);
}
int epoll::wait(int timeout)
{
	return _n = epoll_wait(_fd, _evec.data(), _evec.size(), timeout);
}
void epoll::handle(const std::function<void(vsock&, int)>& callback)
{
	if (_n > 0)
	{
		for (int i = 0; i < _n; i++)
		{
			callback(*((vsock*)(_evec[i].data.ptr)), (int)(_evec[i].events));
		}
	}
}
#endif

int DNSResolve(const std::string& HostName, std::vector<std::string>& _out_IPStrVec)
{
	std::vector<std::string> vec;

	/// Use getaddrinfo instead
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	struct addrinfo* result = nullptr;

	int ret = getaddrinfo(HostName.c_str(), NULL, &hints, &result);
	if (ret != 0)
	{
		return GSOCK_API_ERROR;/// API Call Failed.
	}

	int cnt = 0;
	for (struct addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next)
	{
		cnt++;
		switch (ptr->ai_family)
		{
			case AF_INET:
			{
				sockaddr_in * paddr = (struct sockaddr_in*) (ptr->ai_addr);
				char ip_buff[64] = { 0 };
				const char* ptr = inet_ntop(AF_INET, &(paddr->sin_addr), ip_buff, 64);
				if (ptr != NULL)
				{
					vec.push_back(ptr);
				}
				break;
			}
			case AF_INET6:
			{
				sockaddr_in6* paddr = (struct sockaddr_in6*) (ptr->ai_addr);
				char ip_buff[128] = { 0 };
				const char* ptr = inet_ntop(AF_INET6, &(paddr->sin6_addr), ip_buff, 128);
				if (ptr != NULL)
				{
					vec.push_back(ptr);
				}
				break;
			}
		}// End of switch
	}

	freeaddrinfo(result);

	_out_IPStrVec = std::move(vec);

	// if(cnt!=(int)_out_IPStrVec.size()),
	// then (cnt-(int)_out_IPStrVec.size()) errors happend while calling inet_ntop().
	return cnt; 
}

int DNSResolve(const std::string& HostName, std::string& _out_IPStr)
{
	std::vector<std::string> vec;
	int ret = DNSResolve(HostName, vec);
	if (ret < 0)
	{
		return -1;
	}
	if (vec.empty())
	{
		return -2;
	}
	_out_IPStr = vec[0];
	return 0;
}


/// Undefine marcos
#undef myliblog_ex
#undef myliblog