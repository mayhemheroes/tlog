#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" bool tlog_utf8_buf_is_valid(const char *ptr, size_t len);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);

    std::string str = provider.ConsumeRandomLengthString(1000);
    const char* cstr = str.c_str();
    tlog_utf8_buf_is_valid(cstr, strlen(cstr));
    return 0;
}
