/** General Socket Wrapper
*   Created By Kiritow. (https://github.com/kiritow)
*   Licensed under MIT
*/

#include "gsock_helper.h"

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
#define WSAGetLastError() errno
#endif

sock_helper::sock_helper(sock& s) :_s(s)
{

}

int sock_helper::sendall(const void* ptr, int datasz, int& bytes_sent)
{
    int done = 0;
    while (done < datasz)
    {
        int ret = _s.send(((const char*)ptr) + done, datasz - done);
        if (ret <= 0)
        {
            bytes_sent = done;
            return ret;
        }
        done += ret;
    }
    bytes_sent = done;
    return done;
}

int sock_helper::sendall(const void* ptr, int datasz)
{
    int x;
    return sendall(ptr, datasz, x);
}

int sock_helper::recvuntil(void* buff, int max_length, 
    const std::function<bool()>& cond_fn, int& bytes_recv)
{
    int done = 0;
    while (done < max_length)
    {
        int ret = _s.recv(((char*)buff) + done, max_length - done);
        if (ret <= 0)
        {
            bytes_recv = done;
            return ret;
        }

        if (cond_fn())
        {
            return done;
        }
    }
    bytes_recv = done;
    return done;
}

int sock_helper::recvuntil(void* buff, int max_length,
    const std::function<bool(void*, int)>& cond_fn, int& bytes_recv)
{
    int done = 0;
    while (done < max_length)
    {
        int ret = _s.recv(((char*)buff) + done, max_length - done);
        if (ret <= 0)
        {
            bytes_recv = done;
            return ret;
        }

        if (cond_fn(buff, done))
        {
            return done;
        }
    }
    bytes_recv = done;
    return done;
}

int sock_helper::recvuntil(void* buff, int max_length,
    const std::function<bool()>& cond_fn)
{
    int x;
    return recvuntil(buff, max_length, cond_fn, x);
}

int sock_helper::recvuntil(void* buff, int max_length,
    const std::function<bool(void*, int)>& cond_fn)
{
    int x;
    return recvuntil(buff, max_length, cond_fn, x);
}

int sock_helper::sendpack(const void* ptr, int datasz)
{
    long net_size = htonl(datasz);
    int ret = sendall(&net_size, sizeof(net_size));
    if (ret <= 0) return ret;
    ret = sendall(ptr, datasz);
    if (ret <= 0) return ret;
    return datasz + sizeof(net_size);
}

int sock_helper::sendpack(const std::string& data)
{
    return sendpack(data.data(), data.size());
}

int sock_helper::recvpack(std::string& out_data)
{
    long net_size;
    int ret = recvuntil(&net_size, sizeof(long), []() {return false; });
    if (ret <= 0)
    {
        return ret;
    }
    std::string str;
    char c;
    long data_size = ntohl(net_size);
    if (data_size <= 0)
    {
        return -2;
    }
    long done = 0;
    while (done < data_size)
    {
        int ret = _s.recv(&c, 1);
        if (ret <= 0)
        {
            return ret;
        }
        str.push_back(c);
        done += ret;
    }

    out_data = str;
    return done;
}

int sock_helper::recvline(std::string& out_data, const std::string& separator, bool keep_sep)
{
    out_data.clear();

    char c;
    int done = 0;
    while (true)
    {
        int ret = _s.recv(&c, 1);
        if (ret <= 0)
        {
            return ret;
        }
        out_data.push_back(c);
        done += ret;
        if (out_data.find(separator) != std::string::npos)
        {
            break;
        }
    }
    return done;
}