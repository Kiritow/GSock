/** General Socket Wrapper
*   Created By Kiritow. (https://github.com/kiritow)
*   Licensed under MIT
*/

/** Version: 2.1 */

#include "gsock.h"


#ifdef __WIN32__
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

#include <string>
#include <stdexcept>

class _init_winsock2_2_class
{
public:
    _init_winsock2_2_class()
    {
        /// Windows Platform need WinSock2.DLL initialization.
#ifdef __WIN32__
        WORD wd;
        WSAData wdt;
        wd=MAKEWORD(2,2);
        int ret=WSAStartup(wd,&wdt);
        if(ret<0)
        {
            throw std::runtime_error("Unable to load winsock2.dll. ");
        }
#endif
    }
    ~_init_winsock2_2_class()
    {
        /// Windows Platform need WinSock2.DLL clean up.
#ifdef __WIN32__
        WSACleanup();
#endif
    }
} _init_winsock2_2_obj;


class sock::_impl
{
public:
    int sfd;
    sockaddr_in saddr;
};

sock::sock() : _pp(new _impl)
{
    _pp->sfd=socket(AF_INET,SOCK_STREAM,0);
}

//private
sock::sock(int SocketValue) : _pp(new _impl)
{
    _pp->sfd=SocketValue;
}

sock::sock(sock&& tmp)
{
    _pp=std::move(tmp._pp);
}

sock& sock::operator = (sock&& tmp)
{
    if(_pp)
    {
        closesocket(_pp->sfd);
    }
    _pp=std::move(tmp._pp);
    return *this;
}

sock::~sock()
{
    if(_pp)
    {
        closesocket(_pp->sfd);
    }
}

int sock::connect(const std::string& IPStr,int Port)
{
    // refs
    int& sfd=_pp->sfd;
    sockaddr_in& saddr=_pp->saddr;

    memset(&saddr,0,sizeof(saddr));
    saddr.sin_addr.s_addr=inet_addr(IPStr.c_str());
    saddr.sin_port=htons(Port);
    saddr.sin_family=AF_INET;
    return ::connect(sfd,(sockaddr*)&saddr,sizeof(saddr));
}

int sock::send(const char* Buffer,int Length)
{
    return ::send(_pp->sfd,Buffer,Length,0);
}

int sock::recv(char* Buffer,int MaxToRecv)
{
    return ::recv(_pp->sfd,Buffer,MaxToRecv,0);
}

int sock::getsendtime(int& _out_Second, int& _out_uSecond)
{
    // refs
    int& sfd=_pp->sfd;

    struct timeval outtime;
    int _not_used_t;
    int ret=getsockopt(sfd,SOL_SOCKET,SO_SNDTIMEO,(char*)&outtime,&_not_used_t);
    if(ret<0) return ret;
    /// We don't know why, but on Windows, 1 Second means 1000.
#ifdef __WIN32__
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
    // refs
    int& sfd=_pp->sfd;

    struct timeval outtime;
    int _not_used_t;
    int ret=getsockopt(sfd,SOL_SOCKET,SO_RCVTIMEO,(char*)&outtime,&_not_used_t);
    if(ret<0) return ret;
    /// We don't know why, but on Windows, 1 Second means 1000.
#ifdef __WIN32__
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
    // refs
    int& sfd=_pp->sfd;

    struct timeval outtime;
    /// We don't know why, but on Windows, 1 Second means 1000.
#ifdef __WIN32__
    outtime.tv_sec=Second*1000;
    outtime.tv_usec=0;
#else
    outtime.tv_sec=Second;
    outtime.tv_usec=0;
#endif

    return setsockopt(sfd,SOL_SOCKET,SO_SNDTIMEO,(const char*)&outtime,sizeof(outtime));
}

int sock::setrecvtime(int Second)
{
    // refs
    int& sfd=_pp->sfd;

    struct timeval outtime;
    /// We don't know why, but on Windows, 1 Second means 1000.
#ifdef __WIN32__
    outtime.tv_sec=Second*1000;
    outtime.tv_usec=0;
#else
    outtime.tv_sec=Second;
    outtime.tv_usec=0;
#endif

    return setsockopt(sfd,SOL_SOCKET,SO_RCVTIMEO,(const char*)&outtime,sizeof(outtime));
}




class serversock::_impl
{
public:
    int sfd;
    sockaddr_in saddr;
};

serversock::serversock() : _pp(new _impl)
{
    _pp->sfd=socket(AF_INET,SOCK_STREAM,0);
}

serversock::~serversock()
{
    closesocket(_pp->sfd);
}

int serversock::bind(int Port)
{
    // refs
    int& sfd=_pp->sfd;
    sockaddr_in& saddr=_pp->saddr;

    memset(&saddr,0,sizeof(saddr));
    saddr.sin_addr.s_addr=INADDR_ANY;
    saddr.sin_port=htons(Port);
    saddr.sin_family=AF_INET;
    return ::bind(sfd,(sockaddr*)&saddr,sizeof(saddr));
}

int serversock::set_reuse()
{
    // refs
    int& sfd=_pp->sfd;

    int opt=1;
    return setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR,(const char*)&opt,sizeof(opt));
}

int serversock::listen(int MaxCount)
{
    // refs
    int& sfd=_pp->sfd;

    return ::listen(sfd,MaxCount);
}

sock&& serversock::accept()
{
    sock s;
    int tmp=sizeof(s._pp->saddr);
    int ret=::accept(_pp->sfd,(sockaddr*)&(s._pp->saddr),&tmp);
    if(ret<0)
    {
        s._pp->sfd=-1;/// Bad Socket
    }
    else
    {
        s._pp->sfd=ret;
    }
    return std::move(s);
}



int DNSResolve(const std::string& HostName, std::string& _out_IPStr)
{
    /// Use getaddrinfo instead
    struct addrinfo hints;
    memset(&hints,0,sizeof(hints));
    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=SOCK_STREAM;
    hints.ai_protocol=IPPROTO_TCP;

    struct addrinfo* result=nullptr;

    int ret=getaddrinfo(HostName.c_str(),NULL,&hints,&result);
    if(ret!=0)
    {
        return -1;/// API Call Failed.
    }
    for(struct addrinfo* ptr=result; ptr!=nullptr; ptr=ptr->ai_next)
    {
        switch(ptr->ai_family)
        {
        case AF_INET:
            sockaddr_in* addr=(struct sockaddr_in*) (ptr->ai_addr) ;
            _out_IPStr=inet_ntoa(addr->sin_addr);
            return 0;
            break;
        }
    }
    /// Unknown error.
    return -2;
}

