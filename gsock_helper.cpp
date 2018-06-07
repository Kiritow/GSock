#include "gsock_helper.h"

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