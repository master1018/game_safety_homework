#include <cstdio>
#include <iostream>
#include <vector>
#include <Windows.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <ShellAPI.h>
//#include "dllmain.cpp"
#pragma comment(lib, "Psapi.lib")
//#pragma comment(lib, "testDll.lib")
using namespace std;

// 32λע��
#define TEST_DLL_PATH               "E:\\Github\\game_safety_homework\\homework1\\testDll\\Debug\\testDll.dll"
#define LSTR_TEST_DLL_PATH          L"E:\\Github\\game_safety_homework\\homework1\\testDll\\Debug\\testDll.dll"
// 64λע��
#define TEST_DLL_PATH_X64           "E:\\Github\\game_safety_homework\\homework1\\testDll\\x64\\Debug\\testDll.dll"
#define LSTR_TEST_DLL_PATH_X64      L"E:\\Github\\game_safety_homework\\homework1\\testDll\\x64\\Debug\\testDll.dll"

#define printf_error(X)             printf("********************\n�������: %ld\n%s\n********************\n\n", GetLastError(), X)


/*
*   @brief ������Ȩ
*/
VOID EnableDebugPriv(VOID)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
    CloseHandle(hToken);
}

/*
*   @brief ����ָ���Ľ��̣�������̴����򷵻�true������false
*   @param dwTid ���ҵĽ�������
*/
bool FindProcess(char *strProcessName, DWORD& dwPID, vector<DWORD>& dwTID)
{
    TCHAR processName[64] = { 0 };
    TCHAR tszProcess[64] = { 0 };
    MultiByteToWideChar(CP_ACP, 0, strProcessName, strlen(strProcessName) + 1, processName, sizeof(processName) / sizeof(processName[0]));
    lstrcpy(tszProcess, processName);
    //���ҽ���
    STARTUPINFO st;
    PROCESS_INFORMATION pi;
    PROCESSENTRY32 ps;
    HANDLE hSnapshot;
    memset(&st, 0, sizeof(STARTUPINFO));
    st.cb = sizeof(STARTUPINFO);
    memset(&ps, 0, sizeof(PROCESSENTRY32));
    ps.dwSize = sizeof(PROCESSENTRY32);
    memset(&pi, 0, sizeof(PROCESS_INFORMATION));
    // �������� 
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return false;
    if (!Process32First(hSnapshot, &ps))
        return false;
    do {
        if (lstrcmp(ps.szExeFile, tszProcess) == 0)
        {
            //�ҵ�ָ���ĳ���
            dwPID = ps.th32ProcessID;
            // ��ý��̵������߳�ID
            DWORD* pThreadId = NULL;
            BOOL bRet = TRUE;
            DWORD dwThreadIdLength = 0;
            DWORD dwBufferLength = 1000;
            THREADENTRY32 te32 = { 0 };
            do {
                // �����ڴ�
                pThreadId = new DWORD[dwBufferLength];
                if (NULL == pThreadId)
                {
                    std::cout << "new Error" << std::endl;
                    bRet = FALSE;
                    break;
                }
                ::RtlZeroMemory(pThreadId, (dwBufferLength * sizeof(DWORD)));
                ::RtlZeroMemory(&te32, sizeof(te32));
                te32.dwSize = sizeof(te32);

                //�����߳̿���
                hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                bRet = ::Thread32First(hSnapshot, &te32);

                while (bRet)
                {
                    if (te32.th32OwnerProcessID == dwPID) {// ��ȡ���̶�Ӧ���߳�ID
                        pThreadId[dwThreadIdLength] = te32.th32ThreadID;
                        dwTID.push_back(pThreadId[dwThreadIdLength]);
                        dwThreadIdLength++;
                    }
                    // ������һ���߳̿�����Ϣ
                    bRet = ::Thread32Next(hSnapshot, &te32);
                }
            } while (FALSE);

            CloseHandle(hSnapshot);
            return true;
            //getchar();
            //return dwPid;
        }
    } while (Process32Next(hSnapshot, &ps));
    CloseHandle(hSnapshot);
    return false;
}


/*
*	@brief ����CreateRemoteThread������testDll.dllע�뵽Ŀ��exe������
*	@param targetExe ע��Ŀ��exe����
*/
BOOL CreateRemoteThread_Inject(char* targetExe)
{
	//DWORD dwProcess = 0;
	char myDll[] = TEST_DLL_PATH_X64;
	DWORD dwProcessId;
    vector<DWORD> dwThreadId;
    if (FindProcess(targetExe, dwProcessId, dwThreadId))
    {
        printf_s("����Ŀ����� /%s/, pid /%ld/, num of tids /%ld/\n", targetExe, dwProcessId, dwThreadId.size());
        HANDLE hProcess = 0;
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
        if (!hProcess)
        {
            printf_error("�޷���Ŀ�����!");
            return false;
        }
        LPVOID allocateMem = VirtualAllocEx(hProcess, NULL, sizeof(myDll), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!allocateMem)
        {
            printf_error("�����ڴ����ʧ��!");
        }
        if (!WriteProcessMemory(hProcess, allocateMem, myDll, sizeof(myDll), NULL))
        {
            printf_error("�޷�д������ڴ�!");
            return false;
        }
        HANDLE hRet = 0;
        hRet = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocateMem, 0, 0);
        if (!hRet)
        {
            printf_error("�޷�����Զ���߳�!");
            return false;
        }
        CloseHandle(hProcess);
        return true;
    }
    else
    {
        printf_error("δ�ҵ�Ŀ����� /%s/!\n", targetExe);
    }
    return false;
}

/*
*   @brief ��Ϣ����ע��
*/
BOOL SetWindowHookEx_Inject(char* targetExe)
{
    // Ŀ�����Ĵ��ڱ���
    HWND hwnd = FindWindow(NULL, L"FlappyBird Configuration");
    if (!hwnd)
    {
        printf_error("�޷��ҵ����� \"FlappyBird Configuration\" !");
        return false;
    }

    DWORD pid = NULL;
    DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
    if (!tid)
    {
        printf_error("�޷��ҵ�����\"FlappyBird Configuration\"��Ӧ���߳�ID!");
        return false;
    }

    HMODULE dll = LoadLibraryEx(LSTR_TEST_DLL_PATH_X64, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!dll)
    {
        printf_error("�޷�����dll!");
        return false;
    }

    HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "NextHook");
    if (!addr)
    {
        printf_error("NextHook��ַ���ʧ��!");
        return false;
    }

    HHOOK handle = SetWindowsHookEx(WH_GETMESSAGE, addr, dll, tid);
    if (!handle)
    {
        printf_error("���ô�����Ϣ����ʧ��!");
        return false;
    }
    PostThreadMessage(tid, WM_NULL, NULL, NULL);

    printf_s("���ӳɹ�����!\n");
    printf_s("���������ַ�ȡ������:\n");

    getchar();
    char c;
    c = getchar();
    // �������
    BOOL unhook = UnhookWindowsHookEx(handle);
    if (!unhook)
    {
        printf_error("��Ϣ���ӽ���ʧ��!");
        return false;
    }

    return true;
}

BOOL APC_Inject(char* targetExe)
{
    wchar_t myDll[] = LSTR_TEST_DLL_PATH_X64;
    DWORD dwProcessId;
    vector<DWORD> dwThreadId;
    if (FindProcess(targetExe, dwProcessId, dwThreadId))
    {
        printf_s("����Ŀ����� /%s/, tid /%ld/\n", targetExe, dwProcessId);
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
        LPVOID allocateMem = VirtualAllocEx(hProcess, nullptr, 1 << 12, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!allocateMem)
        {
            printf_error("�����ڴ����ʧ��!");
        }
        if (!WriteProcessMemory(hProcess, allocateMem, myDll, sizeof(myDll), nullptr))
        {
            printf_error("�޷�д������ڴ�!");
            return false;
        }
        for (const auto& tid : dwThreadId)
        {
            HANDLE hThread = ::OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
            if (hThread)
            {
                QueueUserAPC((PAPCFUNC)GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryW"), hThread, (ULONG_PTR)allocateMem);
            }
        }
        VirtualFreeEx(hProcess, allocateMem, 0, MEM_RELEASE | MEM_DECOMMIT);
    }
    return true;
}

/*
*   @brief ע���dllע�룬Ϊ��̬ע��dll��һ�ַ�ʽ����Ҫ�Ƚ���ע�룬������Ŀ�����
*/
BOOL RegSetValue_Inject()
{
    HKEY hkey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hkey) != ERROR_SUCCESS)
    {
        printf_error("ע��� HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows ��ʧ��!");
        return false;
    }
    TCHAR setValue1[254];
    int setValue2 = 1;
    memset(setValue1, 0, sizeof(setValue1));
    wcsncpy_s(setValue1, TEXT(TEST_DLL_PATH_X64), 254);
    RegSetValueEx(hkey, L"AppInit_DLLs", 0, REG_SZ, (const BYTE *)setValue1, sizeof(TCHAR) * wcslen(setValue1));
    RegSetValueEx(hkey, L"LoadAppInit_DLLs", 0, REG_DWORD, (const BYTE *)&setValue2, sizeof(setValue2));

    printf_s("���������ַ���ԭע���:\n");
    getchar();
    char c;
    c = getchar();
    RegSetValueEx(hkey, L"AppInit_DLLs", 0, REG_SZ, NULL, 0);
    setValue2 = 0;
    RegSetValueEx(hkey, L"LoadAppInit_DLLs", 0, REG_DWORD, (const BYTE*)&setValue2, sizeof(setValue2));
    return true;
}

int main()
{
    EnableDebugPriv();
    char input[] = "FlappyBird.exe";
    int chose = 0;
    printf_s("����ע��ѡ��:\n");
    printf_s("1.CreateRemoteThread_Inject\n2.SetWindowHookEx_Inject\n3.APC_Inject\n4.RegSetValue_Inject\n");
    cin >> chose;
    //cout << "����Ŀ�����:" << endl;
    //cin >> input;
    switch (chose)
    {
    case 1:
        if (CreateRemoteThread_Inject(input))
        {
            cout << "CreateRemoteThread inject success!" << endl;
        }
        else
        {
            cout << "CreateRemoteThread inject failed!" << endl;
        }
        break;
    case 2:
        if (SetWindowHookEx_Inject(input))
        {
            cout << "SetWindowHookEx inject successs!" << endl;
        }
        else
        {
            cout << "SetWindowHookEx inject failed!" << endl;
        }
        break;
    case 3:
        if (APC_Inject(input))
        {
            cout << "APC inject success!" << endl;
        }
        else
        {
            cout << "APC inject failed!" << endl;
        }
        break;
    case 4:
        if (RegSetValue_Inject())
        {
            cout << "RegSetValuet inject success!" << endl;
        }
        else
        {
            cout << "RegSetValue inject failed!" << endl;
        }
    default:
        break;
    }
    

    system("pause");
    return 0;
}