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

class _init_winsock2_2_class
{
public:
    _init_winsock2_2_class()
    {
		myliblog("sockaddr %d sockaddr_in %d sockaddr_in6 %d\n", sizeof(sockaddr), sizeof(sockaddr_in), sizeof(sockaddr_in6));
        /// Windows Platform need WinSock2.DLL initialization.
#ifdef _WIN32
        WORD wd;
        WSAData wdt;
        wd=MAKEWORD(2,2);
        int ret=WSAStartup(wd,&wdt);

        myliblog("WSAStartup() Returns: %d\n",ret);

        if(ret<0)
        {
            myliblog("WSAGetLastError: %d\n",WSAGetLastError());
            throw std::runtime_error("Unable to load winsock2.dll. ");
        }
#endif
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

struct vsock::_impl
{
	int sfd;
	bool created;
};

vsock::vsock() : _vp(new _impl)
{
	_vp->created=false;
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
	static int connect_ipv4(vsock::_impl* _vp,const std::string& IPStr, int Port);
	static int connect_ipv6(vsock::_impl* _vp,const std::string& IPStr, int Port);
};

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

	// Create socket
	_vp->sfd = socket(AF_INET, SOCK_STREAM, 0);
	if (_vp->sfd<0)
	{
		myliblog("socket() returns %d. WSAGetLastError: %d\n", _vp->sfd, WSAGetLastError());
		return GSOCK_ERROR_CREAT;
	}

	myliblog("Socket <IPv4> created: [%d] with _vp %p\n", _vp->sfd, _vp);
	_vp->created = true;

	// only returns -1 or 0
	return ::connect(_vp->sfd, (sockaddr*)&saddr, sizeof(saddr));
}

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

	// Create socket
	_vp->sfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (_vp->sfd<0)
	{
		myliblog("socket() returns %d. WSAGetLastError: %d\n", _vp->sfd, WSAGetLastError());
		return GSOCK_ERROR_CREAT;
	}

	myliblog("Socket <IPv6> created: [%d] with _vp %p\n", _vp->sfd, _vp);
	_vp->created = true;

	return ::connect(_vp->sfd, (sockaddr*)&saddr, sizeof(saddr));
}

int sock::connect(const std::string& IPStr,int Port)
{
    myliblog("sock::connect() %p\n",this);

    if(_vp->created)
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

int sock::send(const void* Buffer,int Length)
{
    return ::send(_vp->sfd,(const char*)Buffer,Length,0);
}

int sock::recv(void* Buffer,int MaxToRecv)
{
    return ::recv(_vp->sfd,(char*)Buffer,MaxToRecv,0);
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
epoll::epoll()
{
	_fd=epoll_create(1024); // this parameter is useless.
}
epoll::~epoll()
{
	close(_fd);
}
int epoll::add(const vsock& v,int event)
{
	struct epoll_event ev;
	ev.events=event;
	ev.data.fd=v._vp->sfd;
	return epoll_ctl(_fd,EPOLL_CTL_ADD,v._vp->sfd,&ev);
}
int epoll::mod(const vsock& v,int event)
{
	struct epoll_event ev;
	ev.events=event;
	ev.data.fd=v._vp->sfd;
	return epoll_ctl(_fd,EPOLL_CTL_MOD,v._vp->sfd,&ev);
}
int epoll::del(const vsock& v,int event)
{
	struct epoll_event ev;
	ev.events=event;
	ev.data.fd=v._vp->sfd;
	return epoll_ctl(_fd,EPOLL_CTL_DEL,v._vp->sfd,&ev);
}
int epoll::wait(epoll_event* events,int maxsize,int timeout)
{
	return epoll_wait(_fd,events,maxsize,timeout);
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