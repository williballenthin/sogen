#include <windows.h>
#include <stdio.h>

__declspec(noinline) int compute(int x) { return x * 3 + 1; }

int main(void)
{
    OutputDebugStringA("probe32 start");
    HMODULE h = LoadLibraryA("version.dll");
    printf("version.dll=%p compute=%d\n", (void*)h, compute(41));
    Sleep(1);
    OutputDebugStringA("probe32 end");
    return 7;
}
