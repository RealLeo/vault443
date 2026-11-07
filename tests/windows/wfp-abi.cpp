// SDK ABI evidence only: no WFP handle, administrative action or network mutation.
// Build in the existing MSVC x64 developer environment: cl /nologo /W4 /EHsc wfp-abi.cpp
#include <windows.h>
#include <fwpmu.h>
#include <cstddef>
#include <cstdio>

int main() {
    std::printf("{\"pointerBytes\":%zu,\"sizeof\":%zu,\"action\":%zu,\"rawContext\":%zu,\"providerContextKey\":%zu,\"reserved\":%zu,\"filterId\":%zu,\"effectiveWeight\":%zu}\n",
        sizeof(void*), sizeof(FWPM_FILTER0), offsetof(FWPM_FILTER0, action),
        offsetof(FWPM_FILTER0, rawContext), offsetof(FWPM_FILTER0, providerContextKey),
        offsetof(FWPM_FILTER0, reserved), offsetof(FWPM_FILTER0, filterId),
        offsetof(FWPM_FILTER0, effectiveWeight));
    return sizeof(void*) == 8 && sizeof(FWPM_FILTER0) == 200 &&
        offsetof(FWPM_FILTER0, action) == 128 && offsetof(FWPM_FILTER0, rawContext) == 152 &&
        offsetof(FWPM_FILTER0, providerContextKey) == 152 && offsetof(FWPM_FILTER0, reserved) == 168 &&
        offsetof(FWPM_FILTER0, filterId) == 176 && offsetof(FWPM_FILTER0, effectiveWeight) == 184 ? 0 : 1;
}
