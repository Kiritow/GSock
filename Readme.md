# General Socket Wrapper

GSOCK is a project created by [Kiritow](https://github.com/kiritow).

Licensed under MIT

# Example

## TCP Client Example

```cpp
#include "GSock/gsock.h"
#include "GSock/gsock_helper.h"

int main()
{
    int ret;
    std::string ip;

    // Initiate Socket Handler
    InitNativeSocket();

    if ((ret = DNSResolve("kiritow.com", ip)) < 0)
    {
        printf("Failed to resolve ip address. (%d)\n", ret);
        return 1;
    }
    
    sock s;
    if ((ret = s.connect(ip, 80)) < 0)
    {
        printf("Failed to connect. (%d)\n", ret);
        return 1;
    }

    std::string context("GET / HTTP/1.1\r\nHost: kiritow.com\r\nAccept: */*\r\n\r\n");
    sock_helper sh(s);
    if ((ret=sh.sendall(context.c_str(), context.size())) < 0)
    {
        printf("Failed to send request header. (%d)\n", ret);
        return 1;
    }

    char buff[1024];
    while (true)
    {
        memset(buff, 0, 1024);
        int ret = s.recv(buff, 1024);
        if (ret <= 0) break;
        printf("%s", buff);
    }

    return 0;
}
```

## TCP Echo Server Example

```cpp
#include "GSock/gsock.h"
#include "GSock/gsock_helper.h"

void service_main(sock& s)
{
    char buff[1024];
    sock_helper sh(s);

    while (true)
    {
        memset(buff, 0, 1024);
        int ret = s.recv(buff, 1024);
        if (ret <= 0) break;
        sh.sendall(buff, ret);
    }
}

int main()
{

    // Initiate Socket Handler
    InitNativeSocket();

    serversock t;
    if (t.bind(59123) < 0 || t.listen(10) < 0)
    {
        printf("Failed to start up server.\n");
        return 1;
    }
    
    while (true)
    {
        sock s;
        if (t.accept(s) < 0)
        {
            printf("Failed to accept.\n");
            break;
        }

        service_main(s);
    }

    return 0;
}
```
