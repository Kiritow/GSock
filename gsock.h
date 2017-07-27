/** General Socket Wrapper
*   Created By Kiritow. (https://github.com/kiritow)
*   Licensed under MIT
*/

/** Version: 2.1 */

#pragma once

#include <cstdint>
#include <memory>

class sock
{
public:
    sock();
    sock(const sock&)=delete;
    sock& operator = (const sock&)=delete;
    sock(sock&&);
    sock& operator = (sock&&);
    ~sock();

    int connect(const std::string& IPStr,int Port);

    template<typename T>
    int send(const T&);

    template<typename T>
    int recv(T&);

    int send(const char* Buffer,int Length);
    int recv(char* Buffer,int MaxToRecv);

    int getsendtime(int& _out_Second,int& _out_uSecond);
    int getrecvtime(int& _out_Second,int& _out_uSecond);

    int setsendtime(int Second);
    int setrecvtime(int Second);

private:
    sock(int);
    friend class serversock;

    class _impl;
    std::unique_ptr<_impl> _pp;
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

    int bind(int Port);
    int set_reuse();
    int listen(int MaxCount);

    sock&& accept();
private:
    class _impl;
    std::unique_ptr<_impl> _pp;
};

int DNSResolve(const std::string& HostName,std::string& _out_IPStr);
