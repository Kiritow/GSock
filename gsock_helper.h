/** General Socket Wrapper
*   Created By Kiritow. (https://github.com/kiritow)
*   Licensed under MIT
*/

// GSock Helper

#pragma once
#include "gsock.h"
#include <functional>
#include <string>

class sock_helper
{
public:
    sock_helper(sock&);
    
	int sendall(const std::string& data);
    int sendall(const void* ptr, int datasz);
    int sendall(const void* ptr, int datasz, int& bytes_sent);
    
    int recvall(void* ptr, int length_to_recv);
    int recvall(void* ptr, int length_to_recv, int& bytes_recv);

    int recvuntil(void* buff, int max_length, const std::function<bool()>& cond_fn);
    int recvuntil(void* buff, int max_length, const std::function<bool()>& cond_fn, int& bytes_recv);
    int recvuntil(void* buff, int max_length, const std::function<bool(void*, int)>& cond_fn);
    int recvuntil(void* buff, int max_length, const std::function<bool(void*, int)>& cond_fn, int& bytes_recv);

    int sendpack(const void* ptr, int datasz);
    int sendpack(const std::string& data);
    int recvpack(std::string& out_data);

    int sendline(const std::string& data, const std::string& seperator="\r\n");
    int recvline(std::string& out_data, const std::string& separator="\r\n", bool keep_sep = false);
private:
    sock & _s;
};