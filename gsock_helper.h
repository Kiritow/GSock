/** General Socket Wrapper
*   Created By Kiritow. (https://github.com/kiritow)
*   Licensed under MIT
*/

// GSock Helper

#pragma once
#include "gsock.h"
#include <functional>

class sock_helper
{
public:
    sock_helper(sock&);
    
    int sendall(const void* ptr, int datasz);
    int sendall(const void* ptr, int datasz, int& bytes_sent);
    
    int recvuntil(void* buff, int max_length, const std::function<bool()>& cond_fn);
    int recvuntil(void* buff, int max_length, const std::function<bool()>& cond_fn, int& bytes_recv);
    int recvuntil(void* buff, int max_length, const std::function<bool(void*, int)>& cond_fn);
    int recvuntil(void* buff, int max_length, const std::function<bool(void*, int)>& cond_fn, int& bytes_recv);
private:
    sock & _s;
};