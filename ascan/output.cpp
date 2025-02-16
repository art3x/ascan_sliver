#include "pch.h"

#include <cstdint>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

#include "output.h"

Output* NewOutput(int bufferSize, goCallback callback)
{
	struct Output output;

	output.len = bufferSize;

	output.data = (char*)malloc(bufferSize);
	memset(output.data, 0, output.len);

	output.callback = callback;

	return &output;
}

void append(Output* output, const char* format, ...)
{
	// current output length
	int n = strlen((*output).data);

	// length of what we append
	va_list args;
	va_start(args, format);
	int l = vsnprintf(0, 0, format, args);
	va_end(args);

	// grow buffer if needed
	while ((n + l + 1) > (*output).len) {
		(*output).len = (*output).len * 2;
		(*output).data = (char*)realloc((*output).data, (*output).len);
	}

	// append to output
	va_start(args, format);
	vsnprintf((*output).data + strlen((*output).data), l + 1, format, args);
	va_end(args);
}

int success(Output* output)
{
	(*output).callback((*output).data, strlen((*output).data));
	free((*output).data);
	return 0;
}

int failure(Output* output)
{
	(*output).callback((*output).data, strlen((*output).data));
	free((*output).data);
	return 1;
}