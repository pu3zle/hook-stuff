#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <memoryapi.h>
#include <iostream>
#include <Psapi.h>


#include <disasmtypes.h>
#include <bddisasm.h>


//#include <gdiplus.h>
//#pragma comment (lib, "Gdiplus.lib")

typedef uint64_t ui64, *pui64;

//Gdiplus::ARGB AddColors(Gdiplus::ARGB left, Gdiplus::ARGB right)
//{
//    uint32_t a = min(0xFF000000, (left & 0xFF000000) + (right & 0xFF000000));
//    uint32_t r = min(0x00FF0000, (left & 0x00FF0000) + (right & 0x00FF0000));
//    uint32_t g = min(0x0000FF00, (left & 0x0000FF00) + (right & 0x0000FF00));
//    uint32_t b = min(0x000000FF, (left & 0x000000FF) + (right & 0x000000FF));
//
//    return a | r | g | b;
//}
//
//Gdiplus::ARGB ReturnRed(Gdiplus::ARGB left, Gdiplus::ARGB right)
//{
//    return 0xffff0000;
//}

void* AllocatePageNearAddress(void* TargetAddress)
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    const uint64_t PAGE_SIZE = sysInfo.dwPageSize;
    std::cout << " page size: " << std::hex << PAGE_SIZE << '\n';

    const uint64_t startAddr = (uint64_t)TargetAddress & ~(PAGE_SIZE - 1);
    std::cout << " startAddr:" << std::hex << startAddr << '\n';
    const ui64 minAddr = min(startAddr - 0x7FFFFF00, (ui64)sysInfo.lpMinimumApplicationAddress);
    const ui64 maxAddr = max(startAddr + 0x7FFFFF00, (ui64)sysInfo.lpMaximumApplicationAddress);
    ui64 startPage = startAddr - (startAddr % PAGE_SIZE);

    std::cout << " minAddr:" << std::hex << minAddr << '\n' << " maxAddr:" << std::hex << maxAddr << '\n' << " startPage:" << std::hex << startPage << '\n';
    std::cout << " minAppAddr:" << std::hex << sysInfo.lpMinimumApplicationAddress << '\n' << " maxAppAddr:" << std::hex << sysInfo.lpMaximumApplicationAddress << '\n';

    USHORT pageOffset = 1;

    while (1)
    {
        ui64 byteOffset = pageOffset * PAGE_SIZE;
        ui64 lowAddress = (startPage > byteOffset) ? startPage - byteOffset : 0;
        ui64 highAddress = startPage + byteOffset;

        bool needsBreak = (lowAddress < minAddr && highAddress > maxAddr);

        if (highAddress < maxAddr)
        {
            void* outAddr = VirtualAlloc((void*)highAddress, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if(outAddr)
            {
                return outAddr;
            }
        }
        if (lowAddress > minAddr)
        {
            void* outAddr = VirtualAlloc((void*)lowAddress, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (outAddr)
            {
                return outAddr;
            }
        }

        pageOffset++;

        if (needsBreak)
        {
            break;
        }
    }
    return nullptr;

}

void WriteAbsoluteJump64(void* relayAddress, void* addressToJumpTo)
{
    uint8_t absJumpInstructions[] =
    {
      0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov r10, addr
      0x41, 0xFF, 0xE2 //jmp r10
    };
    ui64 addrToWrite = (ui64)addressToJumpTo;
    memcpy(absJumpInstructions+2, &addrToWrite, sizeof(ui64));
    memcpy(relayAddress, absJumpInstructions, sizeof(absJumpInstructions));
}

void InstallHook(void* HookedFunction, void* PayloadFunction)
{
    void* relayAddr = AllocatePageNearAddress(HookedFunction);
    if (relayAddr == nullptr)
    {
        std::cout << "Failed to allocate relay address!\n";
        return;
    }
    WriteAbsoluteJump64(relayAddr, PayloadFunction);

    //32 bit relative jump opcode is E9, takes 1 32 bit operand for jump offset
    uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

    DWORD oldProtect = 0;
    VirtualProtect(HookedFunction, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);

    const ui64 relAddr = (ui64)relayAddr - ((ui64)HookedFunction + sizeof(jmpInstruction));
    memcpy(jmpInstruction + 1, &relAddr, 4);
    memcpy(HookedFunction, &jmpInstruction, sizeof(jmpInstruction));
}

uint64_t GetBaseModuleForProcess()
{
    HANDLE process = GetCurrentProcess();
    HMODULE processModules[1024];
    DWORD numBytesWrittenInModuleArray = 0;
    EnumProcessModules(process, processModules, sizeof(HMODULE) * 1024, &numBytesWrittenInModuleArray);

    DWORD numRemoteModules = numBytesWrittenInModuleArray / sizeof(HMODULE);
    CHAR processName[256];
    GetModuleFileNameExA(process, NULL, processName, 256); //a null module handle gets the process name
    _strlwr_s(processName, 256);

    HMODULE module = 0; //An HMODULE is the DLL's base address 

    for (DWORD i = 0; i < numRemoteModules; ++i)
    {
        CHAR moduleName[256];
        CHAR absoluteModuleName[256];
        GetModuleFileNameExA(process, processModules[i], moduleName, 256);

        _fullpath(absoluteModuleName, moduleName, 256);
        _strlwr_s(absoluteModuleName, 256);

        if (strcmp(processName, absoluteModuleName) == 0)
        {
            module = processModules[i];
            break;
        }
    }

    return (uint64_t)module; // The HMODULE is actually a pointer to the module
}

void* GetFunc2HookAddr()
{
    uint64_t functionRVA = 0x44C44;
    uint64_t func2HookAddr = GetBaseModuleForProcess() + functionRVA;
    return (void*)func2HookAddr;
}

int Open3DPaintButtonHandler()
{
    return 0;
}

void GetFirstBytes(void* address)
{

}

int main()
{
    /* InstallHook(AddColors, ReturnRed);

     Gdiplus::ARGB col = AddColors(0x00000000, 0x000000FF);
     std::cout << "Final color:" << std::hex << col;
     return 0;*/
    uint8_t instructions[] = { 0x48, 0x89, 0x4c, 0x24, 0x08, // mov
        0x55, // push
        0x57, // push
        0x48, 0x81, 0xec, 0x08, 0x01, 0x00, 0x00, // sub
        0x48, 0x8d, 0x6c, 0x24, 0x20 }; // lea

    uint8_t instructions_dis[] = {
        0x85, 0xc9,
        0x74, 0x26,
        0x83, 0xf9, 0x01,
        0x74, 0x0c
    };

    INSTRUX instrux = { 0 };
    for (int offset = 0; offset < 5; offset += instrux.Length)
    {
        // decode instruction
        RtlSecureZeroMemory(&instrux, sizeof(instrux));
        NDSTATUS status = NdDecodeEx(&instrux, instructions_dis + offset, 0x10, ND_CODE_64, ND_DATA_64);
        if (!ND_SUCCESS(status))
        {
            // on fail, go to next byte
            instrux.Length = 1;
            continue;
        }

        for (int i = 0; i < instrux.Length; i++)
        {
            printf("0x%X ", instrux.InstructionBytes[i]);
        }
        std::cout << '\n';
    }

    //if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    //{
    //    InstallHook(GetFunc2HookAddr(), Open3DPaintButtonHandler); //we'll fill this in later
    //}
    return true;
}

//BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD ul_reason_for_call, LPVOID lpvReserved)
//{
//    
//}

