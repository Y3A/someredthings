#ifndef SRDI_H
#define SRDI_H

#define SRDI_CALLOFFSET 0x00000001

#define kill(...) return printf(__VA_ARGS__), 0

typedef struct
{

    DWORD   opt;
    char    filepath[MAX_PATH + 1];
    DWORD   offset;
    DWORD   passargs[4];
    DWORD   argc;

} BUILDER_ARGS, *PBUILDER_ARGS;


int build_shellcode(PBUILDER_ARGS args);
void _strncpy(char *dest, char *src, size_t len);

#endif