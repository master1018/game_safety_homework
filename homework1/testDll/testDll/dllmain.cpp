// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <stdio.h>
#include <Windows.h>

extern "C" __declspec(dllexport) void testApi()
{
    MessageBoxA(0, "注入成功", "testDll", MB_OK);
}

extern "C" __declspec(dllexport) int NextHook(int code, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, code, wParam, lParam);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    //testApi();
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        testApi();
        break;
    case DLL_THREAD_ATTACH:
        //testApi();
        break;
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}