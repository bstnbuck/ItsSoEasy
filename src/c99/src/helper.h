//
// Created by buckt on 15.09.2021.
//

#ifndef C_CODE_HELPER_H
#define C_CODE_HELPER_H

#include <stdbool.h>

#ifdef _WIN32
    // built self libz.a with Makefile on zlib 1.2.11
    #include "openssl/ssl.h"
#elif __linux__
    #include <openssl/ssl.h>
#endif

/***********************************************
Prints a string with new line character
@param str ASCII string print with new line
@return void
***********************************************/
void println(const char* str);

/***********************************************
Lists recursively all files in a directory and its subdirectories
@param path ASCII string which will be used to search for directories and files
@param buf buffer to save files in
@return int
***********************************************/
int walk(const char *path, char *buf[]);

/***********************************************
Checks if a file ends with an specific extension
@param path ASCII string file should analyzed
@return int
***********************************************/
bool hasExt(const char *path);

/***********************************************
Returns a TLS socket
@param hostname ASCII string hostname to connect with
@param port INT port number to connect with
@return SOCKET
***********************************************/
SSL* getTlsSocket(const char *hostname, int port);


#endif //C_CODE_HELPER_H
