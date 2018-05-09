/** General Socket Wrapper
*   Created By Kiritow. (https://github.com/kiritow)
*   Licensed under MIT
*/

/** See VERSION for version information */

#include "gsock.h"

#ifdef GSOCK_DEBUG
#pragma message("GSock Debug mode compiled in")
#include <cstdio>
#define myliblog(fmt,...) printf("GSock: " fmt,__VA_ARGS__)
#else
#define myliblog(fmt,...)
#endif

#ifdef _WIN32
/// Using Win8.1
#define _WIN32_WINNT 0x0603

#include <winsock2.h>
#include <ws2tcpip.h>
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
#define closesocket close
using BYTE = unsigned char;
#endif

#include <cstring> /// memset
#include <string>
#include <stdexcept>

class _init_winsock2_2_class
{
public:
    _init_winsock2_2_class()
    {
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
        myliblog("WSACleanup() called.");
#endif
    }
} _init_winsock2_2_obj;

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
			myliblog("Socket closed: [%d] in %p\n",_vp->sfd,this);
			closesocket(_vp->sfd);
			
			_vp->created=false;
		}
		
		delete _vp;
		_vp=nullptr;
	}
}

int sock::connect(const std::string& IPStr,int Port)
{
    myliblog("sock::connect() %p\n",this);

    if(_vp->created)
    {
        return -2;
    }
    _vp->sfd=socket(AF_INET,SOCK_STREAM,0);
    if(_vp->sfd<0)
    {
        myliblog("socket() returns %d. WSAGetLastError: %d\n",_vp->sfd,WSAGetLastError());
        return -3;
    }
    myliblog("Socket created: [%d] in %p\n",_pp->sfd,this);
    _vp->created=true;
    
    struct sockaddr_in saddr;

    memset(&saddr,0,sizeof(saddr));
    saddr.sin_addr.s_addr=inet_addr(IPStr.c_str());
    saddr.sin_port=htons(Port);
    saddr.sin_family=AF_INET;

    return ::connect(_vp->sfd,(sockaddr*)&saddr,sizeof(saddr));
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
    struct timeval outtime;
    socklen_t _not_used_t;
    int ret=getsockopt(_vp->sfd,SOL_SOCKET,SO_SNDTIMEO,(char*)&outtime,&_not_used_t);
    if(ret<0) return ret;
    /// We don't know why, but on Windows, 1 Second means 1000.
#ifdef _WIN32
    _out_Second=outtime.tv_sec/1000;
    _out_uSecond=outtime.tv_usec;
#else
    _out_Second=outtime.tv_sec;
    _out_uSecond=outtime.tv_usec;
#endif

    return ret;
}

int sock::getrecvtime(int& _out_Second, int& _out_uSecond)
{
    struct timeval outtime;
    socklen_t _not_used_t;
    int ret=getsockopt(_vp->sfd,SOL_SOCKET,SO_RCVTIMEO,(char*)&outtime,&_not_used_t);
    if(ret<0) return ret;
    /// We don't know why, but on Windows, 1 Second means 1000.
#ifdef _WIN32
    _out_Second=outtime.tv_sec/1000;
    _out_uSecond=outtime.tv_usec;
#else
    _out_Second=outtime.tv_sec;
    _out_uSecond=outtime.tv_usec;
#endif

    return ret;
}

int sock::setsendtime(int Second)
{
    struct timeval outtime;
    /// We don't know why, but on Windows, 1 Second means 1000.
#ifdef _WIN32
    outtime.tv_sec=Second*1000;
    outtime.tv_usec=0;
#else
    outtime.tv_sec=Second;
    outtime.tv_usec=0;
#endif

    return setsockopt(_vp->sfd,SOL_SOCKET,SO_SNDTIMEO,(const char*)&outtime,sizeof(outtime));
}

int sock::setrecvtime(int Second)
{
    struct timeval outtime;
    /// We don't know why, but on Windows, 1 Second means 1000.
#ifdef _WIN32
    outtime.tv_sec=Second*1000;
    outtime.tv_usec=0;
#else
    outtime.tv_sec=Second;
    outtime.tv_usec=0;
#endif

    return setsockopt(_vp->sfd,SOL_SOCKET,SO_RCVTIMEO,(const char*)&outtime,sizeof(outtime));
}

//forgive me, but writing code in hospital is really not a good experience.
using _sock_getname_callback_t = decltype(getsockname);

static int _sock_getname_call(int sfd,std::string& ip,int& port,_sock_getname_callback_t fn)
{
	struct sockaddr_in saddr;
	socklen_t saddrlen=sizeof(saddr);
	memset(&saddr,0,saddrlen);
	int ret=fn(sfd,(sockaddr*)&saddr,&saddrlen);
	if(ret<0) return ret; //don't bother errno. stop here.
	ip=inet_ntoa(saddr.sin_addr);
	port=ntohs(saddr.sin_port);
	return ret;
}

int sock::getlocal(std::string& IPStr,int& Port)
{
	if(!(_vp->created))
	{
		return -2;
	}
	return _sock_getname_call(_vp->sfd,IPStr,Port,getsockname);
}

int sock::getpeer(std::string& IPStr,int& Port)
{
	if(!(_vp->created))
	{
		return -2;
	}
	return _sock_getname_call(_vp->sfd,IPStr,Port,getpeername);
}

int serversock::bind(int Port)
{
    myliblog("serversock::bind() %p\n",this);

    if(_vp->created)
    {
        return -2;
    }
    _vp->sfd=socket(AF_INET,SOCK_STREAM,0);
    if(_vp->sfd<0)
    {
        myliblog("socket() returns %d. WSAGetLastError: %d\n",_vp->sfd,WSAGetLastError());
        return -3;
    }
    myliblog("Socket created: [%d] in %p\n",_vp->sfd,this);
    _vp->created=true;
    
    sockaddr_in saddr;

    memset(&saddr,0,sizeof(saddr));
    saddr.sin_addr.s_addr=INADDR_ANY;
    saddr.sin_port=htons(Port);
    saddr.sin_family=AF_INET;
    return ::bind(_vp->sfd,(sockaddr*)&saddr,sizeof(saddr));
}

int serversock::set_reuse()
{
    socklen_t opt=1;
    return setsockopt(_vp->sfd,SOL_SOCKET,SO_REUSEADDR,(const char*)&opt,sizeof(opt));
}

int serversock::listen(int MaxCount)
{
    return ::listen(_vp->sfd,MaxCount);
}

int serversock::accept(sock& _out_s)
{
    if(_out_s._vp->created)
    {
        /// _out_s has been connected.
        return -2;
    }

    sock s; /// empty socket.
    sockaddr_in saddr;
    socklen_t saddrsz=sizeof(saddr);
    
    int ret=::accept(_vp->sfd,(sockaddr*)&(saddr),&saddrsz);
    if(ret<0)
    {
        /// accept() call failed.
        myliblog("accept() returns %d. WSAGetLastError: %d\n",ret,WSAGetLastError());
        return -1;
    }
    else
    {
        s._vp->sfd=ret;
        s._vp->created=true;

        myliblog("Socket opened: [%d] in %p by serversock %p\n",s._vp->sfd,&s,this);

        /// Move resource.
        _out_s=std::move(s);
        return 0;
    }
}

udpsock::udpsock()
{
	_vp->sfd = socket(AF_INET, SOCK_DGRAM, 0);
	_vp->created = true;
}

int udpsock::connect(const std::string& IPStr,int Port)
{
	sockaddr_in saddr;
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(Port);
	saddr.sin_addr.s_addr = inet_addr(IPStr.c_str());
	
	return ::connect(_vp->sfd,(const sockaddr*)&saddr,sizeof(saddr));
}

int udpsock::broadcast_at(int Port)
{
	sockaddr_in saddr;
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(Port);
	saddr.sin_addr.s_addr = INADDR_BROADCAST;
	
	return ::connect(_vp->sfd,(const sockaddr*)&saddr,sizeof(saddr));
}

int udpsock::set_broadcast()
{
	socklen_t opt=1;
	return ::setsockopt(_vp->sfd,SOL_SOCKET,SO_BROADCAST,(const char*)&opt,sizeof(opt));
}

int udpsock::bind(int Port)
{
	sockaddr_in saddr;
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(Port);
	saddr.sin_addr.s_addr = INADDR_ANY;
	return ::bind(_vp->sfd, (const sockaddr*)&saddr, sizeof(saddr));
}

int udpsock::sendto(const std::string& IPStr, int Port, const void* buffer, int length)
{
	sockaddr_in saddr;
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(Port);
	saddr.sin_addr.s_addr = inet_addr(IPStr.c_str());
	return ::sendto(_vp->sfd, (const char*)buffer, length, 0, (const sockaddr*)&saddr, sizeof(saddr));
}

int udpsock::broadcast(int Port,const void* buffer,int length)
{
	sockaddr_in saddr;
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(Port);
	saddr.sin_addr.s_addr = INADDR_BROADCAST;
	return ::sendto(_vp->sfd, (const char*)buffer, length, 0, (const sockaddr*)&saddr, sizeof(saddr));
}

int udpsock::recvfrom(std::string& fromIP, int& fromPort, void* buffer, int bufferLength)
{
	sockaddr_in saddr;
	socklen_t saddrlen = sizeof(saddr);
	int ret = ::recvfrom(_vp->sfd, (char*)buffer, bufferLength, 0, (sockaddr*)&saddr, &saddrlen);
	
	if (ret < 0)
	{
		return ret; /// don't bother errno.
	}

	fromIP = inet_ntoa(saddr.sin_addr);
	fromPort = ntohs(saddr.sin_port);
	return ret;
}

int udpsock::send(const void* buffer,int length)
{
	return ::send(_vp->sfd,(const char*)buffer,length,0);
}

int udpsock::recv(void* buffer,int bufferLength)
{
	return ::recv(_vp->sfd,(char*)buffer,bufferLength,0);
}

int DNSResolve(const std::string& HostName, std::string& _out_IPStr)
{
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
		return -1;/// API Call Failed.
	}
	for (struct addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next)
	{
		switch (ptr->ai_family)
		{
		case AF_INET:
			sockaddr_in * addr = (struct sockaddr_in*) (ptr->ai_addr);
			_out_IPStr = inet_ntoa(addr->sin_addr);
			freeaddrinfo(result);
			return 0;
			break;
		}
	}
	/// Unknown error.
	freeaddrinfo(result);
	return -2;
}


/// Undefine marcos
#undef myliblog