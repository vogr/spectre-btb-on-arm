#pragma once

int dummy(void);
int indirect_call(int (**f)(void));

extern char const libcall_data[32768];