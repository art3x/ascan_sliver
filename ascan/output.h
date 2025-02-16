#pragma once

typedef int (*goCallback)(char*, int);

struct Output {
	char* data;
	int len;
	goCallback callback;
};

Output* NewOutput(int bufferSize, goCallback callback);
void append(Output* output, const char* format, ...);
int failure(Output* output);
int success(Output* output);
