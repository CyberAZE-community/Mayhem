#ifndef SYSCALL_H
#define SYSCALL_H

#include <windows.h>

BOOL  InitSyscalls(VOID);
DWORD GetSsn(const char *name);
PVOID SyscallStub(DWORD ssn);

#endif
