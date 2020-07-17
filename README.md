# Process Herpaderping 
Process herpaderping is a method of obscuring the intentions of a process by 
modifying the content on disk after the image has been mapped. This results 
in curious behavior by security products and the OS itself.

![][gif.SurivDemo]

## Summary
Generally, a security product takes action on process creation by registering a 
callback in the Windows Kernel 
([PsSetCreateProcessNotifyRoutineEx][msdn.PsSetCreateProcessNotifyRoutineEx]). 
At this point, a security product may inspect the file that was used to map 
the executable and determine if this process should be allowed to execute. This 
kernel callback is invoked when the initial thread is inserted, not when the 
process object is created. 

![][pic.PspCallProcessNotifyRoutinesXrefs]

Because of this, an actor can create and map a process, modify the content of 
the file, then create the initial thread. A product that does inspection at the 
creation callback would see the modified content. Additionally, some products 
use an on-write scanning approach which consists of monitoring for file writes. 
A familiar optimization here is recording the file has been written to and 
defer the actual inspection until [IRP_MJ_CLEANUP][msdn.IRP_MJ_CLEANUP] 
occurs (e.g. the file handle is closed). An actor taking these steps: 
`write -> map -> modify -> execute -> close`. Will subvert on-write scanning 
that solely relies on inspection at [IRP_MJ_CLEANUP][msdn.IRP_MJ_CLEANUP].

To abuse this convention. We first write a binary to a target file on disk. 
Then, map then image of the target file and provide this to the OS to use for 
process creation. The OS kindly maps the original binary for us. Then, using 
the existing file handle and before creating the initial thread, we modify the 
target file content to obscure or fake the file backing the image. After this, 
we create the initial thread to begin execution of the original binary. Then 
later, close the target file handle. Let walk through this step-by-step:
1. Write target binary to disk, keeping the handle open. This is what will 
   execute in memory.
2. Map the file as an image section ([NtCreateSection][msdn.NtCreateSection], 
   [SEC_IMAGE][msdn.SEC_IMAGE]).
3. Create the process object using the section handle (`NtCreateProcessEx`).
4. Using the same target file handle. Obscure the file on disk.
5. Create the initial thread in the process (`NtCreateThreadEx`).
    - At this point the process creation callback in the kernel will fire. The 
      contents on disk do not match what was mapped. Inspection of the file at 
      this point will result in incorrect attribution.
6. Close the handle. [IRP_MJ_CLEANUP][msdn.IRP_MJ_CLEANUP] will occur here.
    - Since we've hidden the contents of what is executing, inspection at this 
      point will result in incorrect attribution.

## Behavior
You'll see in the demo below, `CMD.exe` is used as the execution target. The 
first run overwrites the bytes on disk with a pattern. The second run `CMD.exe` 
is overwritten with `ProcessHacker.exe`, the tool fixes up the binary to look 
as close to `ProcessHacker.exe` as possible, even retaining the original 
signature. Note the multiple executions of the same binary and how the process 
looks to the user compared to what is in the file on disk.

![][gif.ProcessHerpaderp]

### Diving Deeper

We've observed the behavior and some of this may be surprising. Let's try to 
explain this behavior.

#### Repeated executions despite the bits on disk changing

Let's try to understand why the process successfully executes multiple times 
despite the bits on disk not being `CMD.exe`. Below is some `WinDbg` output. 
I've executed the tool as in the demo above, the first herpaderped process was 
created, then I started another, let's compare:

```
PROCESS ffff998aab671080
    SessionId: 1  Cid: 0230    Peb: 3783820000  ParentCid: 28d4
    DirBase: 12a49a000  ObjectTable: ffff8201fd4cba40  HandleCount:  79.
    Image: lol.exe

0: kd> dt nt!_EPROCESS ffff998aab671080
...
   +0x3c0 SectionObject    : 0xffff8201`ff93db70 Void
...
   +0x448 ImageFilePointer : (null) 
...

0: kd> !object 0xffff8201`ff93db70
Object: ffff8201ff93db70  Type: (ffff998aa54d2e80) Section
    ObjectHeader: ffff8201ff93db40 (new version)
    HandleCount: 0  PointerCount: 1
    Directory Object: 00000000  Name: \Users\jxy\Desktop\lol.exe
```
```
PROCESS ffff998aab971080
    SessionId: 1  Cid: 20a8    Peb: 4d492ca000  ParentCid: 12dc
    DirBase: 199f9e000  ObjectTable: ffff8201ffc3d200  HandleCount:  71.
    Image: lol.exe

0: kd> dt nt!_EPROCESS ffff998aab971080
...
   +0x3c0 SectionObject    : 0xffff8201`fc004a10 Void
...
   +0x448 ImageFilePointer : 0xffff998a`adf2dde0 _FILE_OBJECT
...

0: kd> !object 0xffff8201`ff93db70
Object: ffff8201ff93db70  Type: (ffff998aa54d2e80) Section
    ObjectHeader: ffff8201ff93db40 (new version)
    HandleCount: 0  PointerCount: 1
    Directory Object: 00000000  Name: \Users\jxy\Desktop\lol.exe

0: kd> !object 0xffff998a`adf2dde0
Object: ffff998aadf2dde0  Type: (ffff998aa54d3820) File
    ObjectHeader: ffff998aadf2ddb0 (new version)
    HandleCount: 0  PointerCount: 1
    Directory Object: 00000000  Name: \Users\jxy\Desktop\lol.exe {HarddiskVolume3}
```

Note the two processes. I've dumped the relevant parts of the `EPROCESS` for 
each. They have different section object, as expected, they need their own 
sections since they are independent processes.

The first process' `ImageFilePointer` is null since the tool calls 
`NtCreateProcessEx` and explicitly hands the OS a section to use. We'll circle 
back around to this later. For now, let's take a closer look at the 
[FILE_OBJECT][msdn.FILE_OBJECT]: 

```
0: kd> dt nt!_FILE_OBJECT 0xffff998a`adf2dde0
   +0x000 Type             : 0n5
   +0x002 Size             : 0n216
   +0x008 DeviceObject     : 0xffff998a`a73c8930 _DEVICE_OBJECT
   +0x010 Vpb              : 0xffff998a`a75ec2a0 _VPB
   +0x018 FsContext        : 0xffff8201`fa92a170 Void
   +0x020 FsContext2       : 0xffff8202`0514a2e0 Void
   +0x028 SectionObjectPointer : 0xffff998a`ae08aae8 _SECTION_OBJECT_POINTERS
   +0x030 PrivateCacheMap  : (null) 
   +0x038 FinalStatus      : 0n0
   +0x040 RelatedFileObject : (null) 
   +0x048 LockOperation    : 0 ''
   +0x049 DeletePending    : 0 ''
   +0x04a ReadAccess       : 0x1 ''
   +0x04b WriteAccess      : 0 ''
   +0x04c DeleteAccess     : 0 ''
   +0x04d SharedRead       : 0x1 ''
   +0x04e SharedWrite      : 0 ''
   +0x04f SharedDelete     : 0x1 ''
   +0x050 Flags            : 0x44042
   +0x058 FileName         : _UNICODE_STRING "\Users\jxy\Desktop\lol.exe"
   +0x068 CurrentByteOffset : _LARGE_INTEGER 0x0
   +0x070 Waiters          : 0
   +0x074 Busy             : 0
   +0x078 LastLock         : (null) 
   +0x080 Lock             : _KEVENT
   +0x098 Event            : _KEVENT
   +0x0b0 CompletionContext : (null) 
   +0x0b8 IrpListLock      : 0
   +0x0c0 IrpList          : _LIST_ENTRY [ 0xffff998a`adf2dea0 - 0xffff998a`adf2dea0 ]
   +0x0d0 FileObjectExtension : (null) 
```

First, that file object looks different than what we had originally opened with. 
This is expected since executing the process normally (as the user would, by 
double clicking it) will result `explorer.exe` calling `NtCreateUserProcess`. 
This kind of helps explain the behavior we see. But if it were using the file 
why did it execute `CMD.exe`? We've overwritten it.

Its behavior seems like the section is being reused. Let's verify this 
assumption.

The file object stores [SECTION_OBJECT_POINTERS][msdn.SECTION_OBJECT_POINTERS] 
at `SectionObjectPointer`. Let's look there. 

```
0: kd> dx -id 0,0,ffff998aa547b2c0 -r1 ((ntkrnlmp!_SECTION_OBJECT_POINTERS *)0xffff998aae08aae8)
((ntkrnlmp!_SECTION_OBJECT_POINTERS *)0xffff998aae08aae8)                 : 0xffff998aae08aae8 [Type: _SECTION_OBJECT_POINTERS *]
    [+0x000] DataSectionObject : 0xffff998aae04c6d0 [Type: void *]
    [+0x008] SharedCacheMap   : 0x0 [Type: void *]
    [+0x010] ImageSectionObject : 0xffff998aa7c2d660 [Type: void *]
```

According to the documentation the 
`DataSectionObject` and `ImageSectionObject` are `CONTROL_AREA` structures. And 
`SharedCacheMap` is `SHARED_CACHE_MAP`. Let's set a breakpoint and see where 
`ImageSectionObject` is accessed. I'll run another instance of `lol.exe`. 

```
ba r8 0xffff998aae08aae8+0x108

Breakpoint 0 hit
nt!MiReferenceControlArea+0x59:
fffff802`2f4955e1 408af8          mov     dil,al
2: kd> k
 # Child-SP          RetAddr           Call Site
00 fffffd89`f2772640 fffff802`2f9f8111 nt!MiReferenceControlArea+0x59
01 fffffd89`f27726d0 fffff802`2f9f8574 nt!MiCreateImageOrDataSection+0x171
02 fffffd89`f27727c0 fffff802`2f9f7bcf nt!MiCreateSection+0xf4
03 fffffd89`f2772940 fffff802`2f9f7960 nt!MiCreateSectionCommon+0x1ff
04 fffffd89`f2772a20 fffff802`2f5d3c15 nt!NtCreateSection+0x60
05 fffffd89`f2772a90 00007ffb`de0fc9b4 nt!KiSystemServiceCopyEnd+0x25
06 00000000`0496d848 00007ffb`db8a1a47 ntdll!NtCreateSection+0x14
07 00000000`0496d850 00007ffb`db8a55a0 KERNELBASE!BasepLoadLibraryAsDataFileInternal+0x2e7
08 00000000`0496da80 00007ffb`db88c41d KERNELBASE!LoadLibraryExW+0xe0
09 00000000`0496daf0 00007ffb`dd39c9c1 KERNELBASE!GetFileVersionInfoSizeExW+0x3d
0a 00000000`0496db50 00007ffb`dd39c94c SHELL32!_LoadVersionInfo+0x39
0b 00000000`0496dbc0 00007ffb`db1c43c1 SHELL32!CVersionPropertyStore::Initialize+0x2c5
...
2d 00000000`0496f3c0 00007ffb`dd376a4a SHELL32!CRegistryVerbsContextMenu::_Execute+0xcb
2e 00000000`0496f430 00007ffb`dd362df3 SHELL32!CRegistryVerbsContextMenu::InvokeCommand+0xaa
2f 00000000`0496f730 00007ffb`dd391069 SHELL32!HDXA_LetHandlerProcessCommandEx+0x117
30 00000000`0496f840 00007ffb`dd54857d SHELL32!CDefFolderMenu::InvokeCommand+0x139
31 00000000`0496fba0 00007ffb`dd7faf49 SHELL32!SHInvokeCommandOnContextMenu2+0x1f5
32 00000000`0496fde0 00007ffb`dc13dd25 SHELL32!s_DoInvokeVerb+0xc9
33 00000000`0496fe50 00007ffb`dc5c7bd4 shcore!_WrapperThreadProc+0xf5
34 00000000`0496ff30 00007ffb`de0cce51 KERNEL32!BaseThreadInitThunk+0x14
35 00000000`0496ff60 00000000`00000000 ntdll!RtlUserThreadStart+0x21

3: kd> g
Breakpoint 0 hit
nt!MiReferenceControlArea+0x59:
fffff802`2f4955e1 408af8          mov     dil,al
3: kd> k
 # Child-SP          RetAddr           Call Site
00 fffffd89`f2771f30 fffff802`2f9f8111 nt!MiReferenceControlArea+0x59
01 fffffd89`f2771fc0 fffff802`2f9f8574 nt!MiCreateImageOrDataSection+0x171
02 fffffd89`f27720b0 fffff802`2fa52b83 nt!MiCreateSection+0xf4
03 fffffd89`f2772230 fffff802`2fa500ee nt!MmCreateSpecialImageSection+0xbb
04 fffffd89`f27722e0 fffff802`2f5d3c15 nt!NtCreateUserProcess+0x54e
05 fffffd89`f2772a90 00007ffb`de0fd8e4 nt!KiSystemServiceCopyEnd+0x25
06 00000000`0496d858 00007ffb`db8df36a ntdll!NtCreateUserProcess+0x14
07 00000000`0496d860 00007ffb`db8dbd06 KERNELBASE!CreateProcessInternalW+0x1f7a
08 00000000`0496e9b0 00007ffb`dc5cbe93 KERNELBASE!CreateProcessW+0x66
09 00000000`0496ea20 00007ffb`db17cf36 KERNEL32!CreateProcessWStub+0x53
...
14 00000000`0496f3c0 00007ffb`dd376a4a SHELL32!CRegistryVerbsContextMenu::_Execute+0xcb
15 00000000`0496f430 00007ffb`dd362df3 SHELL32!CRegistryVerbsContextMenu::InvokeCommand+0xaa
16 00000000`0496f730 00007ffb`dd391069 SHELL32!HDXA_LetHandlerProcessCommandEx+0x117
17 00000000`0496f840 00007ffb`dd54857d SHELL32!CDefFolderMenu::InvokeCommand+0x139
18 00000000`0496fba0 00007ffb`dd7faf49 SHELL32!SHInvokeCommandOnContextMenu2+0x1f5
19 00000000`0496fde0 00007ffb`dc13dd25 SHELL32!s_DoInvokeVerb+0xc9
1a 00000000`0496fe50 00007ffb`dc5c7bd4 shcore!_WrapperThreadProc+0xf5
1b 00000000`0496ff30 00007ffb`de0cce51 KERNEL32!BaseThreadInitThunk+0x14
1c 00000000`0496ff60 00000000`00000000 ntdll!RtlUserThreadStart+0x21

3: kd> g
Breakpoint 0 hit
nt!MiReferenceControlArea+0x59:
fffff802`2f4955e1 408af8          mov     dil,al
0: kd> k
 # Child-SP          RetAddr           Call Site
00 fffffd89`f28b5640 fffff802`2f9f8111 nt!MiReferenceControlArea+0x59
01 fffffd89`f28b56d0 fffff802`2f9f8574 nt!MiCreateImageOrDataSection+0x171
02 fffffd89`f28b57c0 fffff802`2f9f7bcf nt!MiCreateSection+0xf4
03 fffffd89`f28b5940 fffff802`2f9f7960 nt!MiCreateSectionCommon+0x1ff
04 fffffd89`f28b5a20 fffff802`2f5d3c15 nt!NtCreateSection+0x60
05 fffffd89`f28b5a90 00007ffb`de0fc9b4 nt!KiSystemServiceCopyEnd+0x25
06 000000a1`98f7dd78 00007ffb`db8a1a47 ntdll!NtCreateSection+0x14
07 000000a1`98f7dd80 00007ffb`db8a55a0 KERNELBASE!BasepLoadLibraryAsDataFileInternal+0x2e7
08 000000a1`98f7dfb0 00007ffb`dcfab65b KERNELBASE!LoadLibraryExW+0xe0
09 000000a1`98f7e020 00007ffb`dd34bcfc USER32!PrivateExtractIconsW+0x15b
0a 000000a1`98f7e530 00007ffb`dd34ba78 SHELL32!SHPrivateExtractIcons+0x1ec
0b 000000a1`98f7ea30 00007ff7`70a856ee SHELL32!ExtractIconExW+0xe8
```

As we see, after I double click to start `lol.exe` again, the 
`ImageSectionObject` is accessed from 
[SECTION_OBJECT_POINTERS][msdn.SECTION_OBJECT_POINTERS] of the 
[FILE_OBJECT][msdn.FILE_OBJECT] a number of times. The section data appears to 
be reused. This would ignore the data on disk and helps explain the behavior 
we're seeing with multiple executions. This is a smart optimization, if you've 
already done the work to parse and map the image, why duplicate that work?

With a bit of reverse engineering of `MiReferenceControlArea` we can see this:

```cpp
struct CREATE_SECTION_PACKET
{
    ULONG Flags;
    DWORD Unknown04;
    POBJECT_ATTRIBUTES InputObjectAttributes;
    ULONG AllocateAttributes;
    ULONG InputAllocationAttributes;
    UCHAR InputSectionSignatureLevel;
    BYTE Unknown19;
    WORD Unknown1A;
    ULONG InputSectionPageProtection;
    ULONG PageProtectionMask;
    DWORD Unknown24;
    HANDLE InputFileHandle;
    PFILE_OBJECT InputFileObject;
    PFILE_OBJECT FileObject;
    CONTROL_AREA* SectionControlArea;
    KPROCESSOR_MODE InputPreviousMode;
    BYTE Unknown49[67];
    DWORD Unknown8C;
    SECTION* SectionObject;
    PLARGE_INTEGER MaximumSize;
    PACCESS_TOKEN InputToken;
    DWORD InputSessionId;
    DWORD UnknownAC;
    MI_PARTITION* Partition;
    PIRP TopLevelIrp;
    BYTE UnknownC0;
    BYTE UnknownC1[3];
    DWORD UnknownC4;
};

NTSTATUS __fastcall MiReferenceControlArea(
    CREATE_SECTION_PACKET* CreateSectionPacket,
    CONTROL_AREA* ControlArea,
    CONTROL_AREA** ControlAreaOut)
{
    CONTROL_AREA* controlArea;
//...
    fileObject = CreateSectionPacket->FileObject;
    //  
    // Retrieve section object pointers. If SEC_IMAGE use ImageSectionObject 
    // otherwise use DataSectionObject
    //  
    controlArea = fileObject->SectionObjectPointer->DataSectionObject;
    if ((CreateSectionPacket->AllocateAttributes & SEC_IMAGE) != 0)
    {
        controlArea = fileObject->SectionObjectPointer->ImageSectionObject;
    }
//...
//
// Some exceptionally ugly lock loops and validation.
//
//...
            *ControlAreaOut = controlArea;
            return STATUS_SUCCESS;
//...
}

NTSTATUS __fastcall MiCreateImageOrDataSection(
    CREATE_SECTION_PACKET* CreateSectionPacket)
{
    NTSTATUS status;
    PFILE_OBJECT fileObject;
    CONTROL_AREA controlArea;
    CONTROL_AREA* newControlArea;
//...
    fileObject = CreateSectionPacket->InputFileObject;
    if (fileObject)
    {
        //
        // A file object was provided already, use it.
        //
        goto HaveFileObject;
    }
    if ((allocationAttributes & SEC_LARGE_PAGES) == 0)
    {
        //
        // Get the file object form the input file handle.
        //
        status = ObReferenceObjectByHandle(
                     CreateSectionPacket->InputFileHandle,
                     MmMakeFileAccess[CreateSectionPacket->PageProtectionMask & 7],
                     IoFileObjectType,
                     CreateSectionPacket->InputPreviousMode,
                     &fileObject,
                     NULL);
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }
        if (!fileObject->SectionObjectPointer)
        {
            //
            // If the file handle was used and there was not section crated for 
            // it already, this is a failure condition. 
            //
            status = STATUS_INVALID_FILE_FOR_SECTION;
            goto Exit;
        }

:HaveFileObject
//...
        //
        // Sore some information in the packet and the local CONTROL_AREA to 
        // maintain state for further calls.
        //
        ObfReferenceObject(fileObject);
        CreateSectionPacket->FileObject = fileObject;
        controlArea.u.LongFlags = 2;
        controlArea.FilePointer.Value = fileObject;
        newControlArea = NULL;
//...
        while (1)
        {
//...
            //
            // Go reference the correct control area.
            //
            status = MiReferenceControlArea(CreateSectionPacket, 
                                            &controlArea, 
                                            &sectionControlArea);
            if (NT_SUCCESS(status))
            {
                break;
            }
            if ((status == 0xC000060B) || (status == 0xC0000476))
            {
                //
                // The control area is not charged or is invalid.
                //
                goto Exit;
            }
        }
        CreateSectionPacket->SectionControlArea = sectionControlArea;
        if ((sectionControlArea->u.LongFlags & 2) != 0)
        {
            //
            // We have the section control area which will have the reference 
            // section. Now, go create the new one.
            //
            status = MiCreateNewSection(CreateSectionPacket,
                                        &newControlArea);
            if (NT_SUCCESS(status)))
            {
//...
                CreateSectionPacket->SectionControlArea = newControlArea;
                goto Exit;
//...
Exit:
//...
    return status;
}
```

The above shows that this path will reference the input file object. And 
attempt to re-use the section from the control area to create a new section 
based on it. In our example, this returns to `MiCreateSection` which does some 
finalization.

Let's go back to the debugger now and identify that file object. From my 
reverse engineering I know that `CREATE_SECTION_PACKET` is stored on the 
stack from a higher call. I'll go identify that.

This is the structure `CREATE_SECTION_PACKET` in the stack starting at 
`InputFileHandle` and ending at `FileObject` between these fields there exists 
`InputFileObject`:
```
0: kd> dq fffffd89`f016b868 L3
fffffd89`f016b868  00000000`0000255c 00000000`00000000
fffffd89`f016b878  ffff998a`ae91ea20
```

The input file object is null. This is expected in this path. And the 
`InputFileHandle` is a handle to an almost identical  
[FILE_OBJECT][msdn.FILE_OBJECT] from the `EPROCESS` of the previous process. 
But it isn't the same. However, the `SectionObjectPointer` is the same for both 
objects.

```
0: kd> !handle 00000000`0000255c

PROCESS ffff998aab1b2480
    SessionId: 1  Cid: 12dc    Peb: 0099d000  ParentCid: 12b8
    DirBase: 1ab742000  ObjectTable: ffff8201fa4fa6c0  HandleCount: 2041.
    Image: explorer.exe

Handle table at ffff8201fa4fa6c0 with 2041 entries in use

255c: Object: ffff998aae91ea20  GrantedAccess: 00120089 (Protected) (Inherit) (Audit) Entry: ffff8201fbdf9570
Object: ffff998aae91ea20  Type: (ffff998aa54d3820) File
    ObjectHeader: ffff998aae91e9f0 (new version)
        HandleCount: 1  PointerCount: 32770
        Directory Object: 00000000  Name: \Users\jxy\Desktop\lol.exe {HarddiskVolume3}

0: kd> !object ffff998a`ae91ea20
Object: ffff998aae91ea20  Type: (ffff998aa54d3820) File
    ObjectHeader: ffff998aae91e9f0 (new version)
    HandleCount: 1  PointerCount: 32770
    Directory Object: 00000000  Name: \Users\jxy\Desktop\lol.exe {HarddiskVolume3}
0: kd> dt nt!_FILE_OBJECT ffff998a`ae91ea20
   +0x000 Type             : 0n5
   +0x002 Size             : 0n216
   +0x008 DeviceObject     : 0xffff998a`a73c8930 _DEVICE_OBJECT
   +0x010 Vpb              : 0xffff998a`a75ec2a0 _VPB
   +0x018 FsContext        : 0xffff8201`fa92a170 Void
   +0x020 FsContext2       : 0xffff8201`ff956940 Void
   +0x028 SectionObjectPointer : 0xffff998a`ae08aae8 _SECTION_OBJECT_POINTERS
   +0x030 PrivateCacheMap  : (null) 
   +0x038 FinalStatus      : 0n0
   +0x040 RelatedFileObject : (null) 
   +0x048 LockOperation    : 0 ''
   +0x049 DeletePending    : 0 ''
   +0x04a ReadAccess       : 0x1 ''
   +0x04b WriteAccess      : 0 ''
   +0x04c DeleteAccess     : 0 ''
   +0x04d SharedRead       : 0x1 ''
   +0x04e SharedWrite      : 0 ''
   +0x04f SharedDelete     : 0x1 ''
   +0x050 Flags            : 0xc0042
   +0x058 FileName         : _UNICODE_STRING "\Users\jxy\Desktop\lol.exe"
   +0x068 CurrentByteOffset : _LARGE_INTEGER 0x0
   +0x070 Waiters          : 0
   +0x074 Busy             : 0
   +0x078 LastLock         : (null) 
   +0x080 Lock             : _KEVENT
   +0x098 Event            : _KEVENT
   +0x0b0 CompletionContext : (null) 
   +0x0b8 IrpListLock      : 0
   +0x0c0 IrpList          : _LIST_ENTRY [ 0xffff998a`ae91eae0 - 0xffff998a`ae91eae0 ]
   +0x0d0 FileObjectExtension : (null) 
```

We now see how the [SECTION_OBJECT_POINTERS][msdn.SECTION_OBJECT_POINTERS] are 
shared between each [FILE_OBJECT][msdn.FILE_OBJECT].

The new bits from the file don't ever become mapped for a new process until 
all the [FILE_OBJECT][msdn.FILE_OBJECT] are reclaimed with the shared 
`SectionObjectPointer` and `ImageSectionObject`.

```
Breakpoint 0 hit
nt!MiClearFilePointer+0x5d:
fffff802`2f4f9385 ebe2            jmp     nt!MiClearFilePointer+0x41 (fffff802`2f4f9369)
3: kd> k
 # Child-SP          RetAddr           Call Site
00 fffffd89`f254f690 fffff802`2f56f501 nt!MiClearFilePointer+0x5d
01 fffffd89`f254f6c0 fffff802`2f56f4a9 nt!MiDestroySection+0x29
02 fffffd89`f254f6f0 fffff802`2f5eaca0 nt!MiCleanSection+0x6d
03 fffffd89`f254f790 fffff802`2f42324e nt!MiCheckControlArea+0x1c7a40
04 fffffd89`f254f800 fffff802`2f9da4c3 nt!MiDereferenceControlAreaBySection+0x2a
05 fffffd89`f254f830 fffff802`2fa189e0 nt!MiSectionDelete+0x83
06 fffffd89`f254f860 fffff802`2f4a1004 nt!ObpRemoveObjectRoutine+0x80
07 fffffd89`f254f8c0 fffff802`2fa6d64c nt!ObfDereferenceObject+0xa4
08 fffffd89`f254f900 fffff802`2fa26743 nt!PspRundownSingleProcess+0x16c
09 fffffd89`f254f980 fffff802`2fa5c4fb nt!PspExitThread+0x60b
0a fffffd89`f254fa90 fffff802`2f5d3c15 nt!NtTerminateProcess+0xeb
0b fffffd89`f254fb00 00007ffb`de0fc5f4 nt!KiSystemServiceCopyEnd+0x25
0c 00000025`020ff718 00000000`00000000 ntdll!NtTerminateProcess+0x14
```

#### What this means for the process creation callback 

[PS_CREATE_NOTIFY_INFO][msdn.PS_CREATE_NOTIFY_INFO] contains a `FileObject`, 
which according to the documentation, is the file object of the process being 
created. How does [PS_CREATE_NOTIFY_INFO][msdn.PS_CREATE_NOTIFY_INFO] in the 
process creation callback get populated? Well `PspCallProcessNotifyRoutines` 
calls `PsReferenceProcessFilePointer` of course:

```cpp
NTSTATUS __fastcall PsReferenceProcessFilePointer(
    PEPROCESS Process, 
    PFILE_OBJECT* FileObject)
{
    NTSTATUS status;
    CONTROL_AREA* controlArea;

    status = STATUS_UNSUCCESSFUL;

    if (ExAcquireRundownProtection(&Process->RundownProtect))
    {
       if (Process->SectionObject)
       {
           controlArea = MiSectionControlArea(Process->SectionObject);
           *FileObject = MiReferenceControlAreaFile(controlArea);
           status = STATUS_SUCCESS;
       }

       ExReleaseRundownProtection(&Process->RundownProtect);
    }

    return status;
}
```

We see here it gets the `FileObject` from the `SectionObject` field in the 
`EPROCESS`.

What does this mean for the callback? I wrote a simple test driver that 
registers for the callback and prints some debug info.

```
Process:    FFFF998AAC8DF080
ProcessId:  00000000000008C0
CreateInfo: FFFFFD89F16F8E20
  Flags:           0x00000000
  ParentProcessId: 0000000000001B90
  FileObject:      FFFF998AB534DAA0
  ImageFileName:   "\Users\jxy\Desktop\lol.exe"
  CommandLine:     ""
```
```
0: kd> dt nt!_FILE_OBJECT FFFF998AB534DAA0
   +0x000 Type             : 0n5
   +0x002 Size             : 0n216
   +0x008 DeviceObject     : 0xffff998a`a73c8930 _DEVICE_OBJECT
   +0x010 Vpb              : 0xffff998a`a75ec2a0 _VPB
   +0x018 FsContext        : 0xffff8202`23a8a170 Void
   +0x020 FsContext2       : 0xffff8202`23a8a3d0 Void
   +0x028 SectionObjectPointer : 0xffff998a`b5aa1118 _SECTION_OBJECT_POINTERS
   +0x030 PrivateCacheMap  : (null) 
   +0x038 FinalStatus      : 0n0
   +0x040 RelatedFileObject : 0xffff998a`b239c560 _FILE_OBJECT
   +0x048 LockOperation    : 0 ''
   +0x049 DeletePending    : 0 ''
   +0x04a ReadAccess       : 0x1 ''
   +0x04b WriteAccess      : 0x1 ''
   +0x04c DeleteAccess     : 0 ''
   +0x04d SharedRead       : 0x1 ''
   +0x04e SharedWrite      : 0x1 ''
   +0x04f SharedDelete     : 0x1 ''
   +0x050 Flags            : 0x44042
   +0x058 FileName         : _UNICODE_STRING "\Users\jxy\Desktop\lol.exe"
   +0x068 CurrentByteOffset : _LARGE_INTEGER 0x44600
   +0x070 Waiters          : 0
   +0x074 Busy             : 0
   +0x078 LastLock         : (null) 
   +0x080 Lock             : _KEVENT
   +0x098 Event            : _KEVENT
   +0x0b0 CompletionContext : (null) 
   +0x0b8 IrpListLock      : 0
   +0x0c0 IrpList          : _LIST_ENTRY [ 0xffff998a`b534db60 - 0xffff998a`b534db60 ]
   +0x0d0 FileObjectExtension : (null) 
```

That's the same access that I opened the file with to create the section. Let's 
try something. Let's run `ProcessHerpaderping` with the `--exclusive` option. 
This will hold the initial file handle open with exclusive rights.

```
Process:    FFFF998AB2BD5080
ProcessId:  0000000000001C10
CreateInfo: FFFFFD89F1B1DE20
  Flags:           0x00000000
  ParentProcessId: 000000000000255C
  FileObject:      FFFF998AB21A6330
  ImageFileName:   "\Users\jxy\Desktop\lol.exe"
  CommandLine:     ""

0: kd> dt nt!_FILE_OBJECT FFFF998AB21A6330
   +0x000 Type             : 0n5
   +0x002 Size             : 0n216
   +0x008 DeviceObject     : 0xffff998a`a73c8930 _DEVICE_OBJECT
   +0x010 Vpb              : 0xffff998a`a75ec2a0 _VPB
   +0x018 FsContext        : 0xffff8202`23a8a170 Void
   +0x020 FsContext2       : 0xffff8202`21292760 Void
   +0x028 SectionObjectPointer : 0xffff998a`b5aa1118 _SECTION_OBJECT_POINTERS
   +0x030 PrivateCacheMap  : 0xffff998a`ab2d3a68 Void
   +0x038 FinalStatus      : 0n0
   +0x040 RelatedFileObject : 0xffff998a`b239dcd0 _FILE_OBJECT
   +0x048 LockOperation    : 0 ''
   +0x049 DeletePending    : 0 ''
   +0x04a ReadAccess       : 0x1 ''
   +0x04b WriteAccess      : 0x1 ''
   +0x04c DeleteAccess     : 0 ''
   +0x04d SharedRead       : 0 ''
   +0x04e SharedWrite      : 0 ''
   +0x04f SharedDelete     : 0 ''
   +0x050 Flags            : 0x40042
   +0x058 FileName         : _UNICODE_STRING "\Users\jxy\Desktop\lol.exe"
   +0x068 CurrentByteOffset : _LARGE_INTEGER 0x44600
   +0x070 Waiters          : 0
   +0x074 Busy             : 0
   +0x078 LastLock         : (null) 
   +0x080 Lock             : _KEVENT
   +0x098 Event            : _KEVENT
   +0x0b0 CompletionContext : (null) 
   +0x0b8 IrpListLock      : 0
   +0x0c0 IrpList          : _LIST_ENTRY [ 0xffff998a`b21a63f0 - 0xffff998a`b21a63f0 ]
   +0x0d0 FileObjectExtension : (null) 
```

I control this file access now. Meaning, I may hold this handle open and 
prevent others from accessing the file. While this isn't horrible for the 
kernel callback. It means any downstream logic that that makes the assumption 
they can open the file with read access, will be broken. Well, it would have 
already been given I've overwritten the file content. And the kernel callback 
is boned too, since reading directly from the file using that 
[FILE_OBJECT][msdn.FILE_OBJECT] will just read up the wrong data.

##### But wait, there's more...
This also means if I try to execute that process again. It does not work; I get 
a sharing violation. From user mode, without access to that original target 
file handle, no one may conventionally execute the process.

## Background and Motivation
When designing products for securing Windows platforms. Many engineers in 
this field (myself included) have fallen on preconceived notions with respect 
to how the OS will handle data. In this scenario, some might expect the file on 
disk to remain "locked" when the process is created. You can't delete the file. 
You can't write to it. But you can rename it. Seen here, under the right 
conditions, you can in fact write to it. Remain vigilant on your assumptions, 
always question them, and do you research.

The motivation for this research came about when discovering how to do analysis 
when a file is written. With prior background researching process hollowing and 
doppelganing. I had theorized this might be possible. The goal is to provide 
better security. You cannot create a better lock without first understanding 
how to break the old one.

## Known Affected Platforms
Below is a list of products and Windows OSes that have been tested as of 
(7/14/2020). Tests were preformed with a known malicious binary.



| Operating System                    | Version         | Vulnerable |
| :---------------------------------- | :-------------- | :--------: |
| Windows 7 Enterprise x86            | 6.1.7601        | Yes        |
| Windows 10 Pro x64                  | 10.0.18363.900  | Yes        |
| Windows 10 Pro Insider Preview x64  | 10.0.20170.1000 | Yes        |

| Security Product                    | Version       | Vulnerable |
| :---------------------------------- | :------------ | :--------: |
| Windows Defender AntiMalware Client | 4.18.2006.10  | Yes        |
| Windows Defender Engine             | 1.1.17200.2   | Yes        |
| Windows Defender Antivirus          | 1.319.1127.0  | Yes        |
| Windows Defender Antispyware        | 1.319.1127.0  | Yes        |
| Windows Defender AntiMalware Client | 4.18.2007.6   | Yes        |
| Windows Defender Engine             | 1.1.17300.2   | Yes        |
| Windows Defender Antivirus          | 1.319.1676.0  | Yes        |
| Windows Defender Antispyware        | 1.319.1676.0  | Yes        |

# Source 
This repo contains a tool for exercising the herpaderping method of process 
obfuscation. Usage is as follows:
```
Process Herpaderping Tool - Copyright (c) Johnny Shaw
ProcessHerpaderping.exe TargetBinary FileName [ReplacedWith] [Options...]
Usage:
  TargetBinary             Target binary to execute.
  FileName                 File name to execute the binary from.
  ReplacedWith             File to replace the binary with. Optional,
                           defaults overwrites the binary with a pattern.
  -h,--help                Prints tool usage.
  -d,--do-not-wait         Does not wait for spawned process to exit,
                           default waits.
  -l,--logging-mask number Specifies the logging mask, defaults to full
                           logging.
                               0x1   Successes
                               0x2   Informational
                               0x4   Warnings
                               0x8   Errors
                               0x10  Contextual
  -q,--quiet               Runs quietly, overrides logging mask, no title.
  -r,--random-obfuscation  Uses random bytes rather than a pattern for
                           file obfuscation.
  -e,--exclusive           Target file is created with exclusive access and
                           the handle is held open as long as possible.
                           Without this option the handle has full share
                           access and is closed as soon as possible.
```

## Cloning and Building
The repo uses submouldes, after cloning be sure to init and update the 
submobules. Projects files are targeted to Visual Studio 2019.
```
git clone https://github.com/jxy-s/herpaderping.git
cd .\herpaderping\
git submodule update --init --recursive
MSBuild .\herpaderping.sln
```

## Credits
The following are used without modification. Credits to their authors.
- [Windows Implementation Libraries (WIL)][github.wil]  
A header-only C++ library created to make life easier for developers on Windows 
through readable type-safe C++ interfaces for common Windows coding patterns.  
- [Process Hacker Native API Headers][github.phnt]   
Collection of Native API header files. Gathered from Microsoft header files and 
symbol files, as well as a lot of reverse engineering and guessing.

[//]: # (Hyperlink IDs)
[github.wil]: https://github.com/microsoft/wil
[github.phnt]: https://github.com/processhacker/phnt
[msdn.PsSetCreateProcessNotifyRoutineEx]: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
[msdn.IRP_MJ_CLEANUP]: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-cleanup
[msdn.NtCreateSection]: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection
[msdn.SEC_IMAGE]: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga
[msdn.IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION]: https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization
[msdn.IRP_MJ_WRITE]: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write 
[msdn.FILE_OBJECT]: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_object
[msdn.SECTION_OBJECT_POINTERS]: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_section_object_pointers
[msdn.PS_CREATE_NOTIFY_INFO]: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info

[//]: # (Relative Path IDs)
[gif.ProcessHerpaderp]: res/ProcessHerpaderp.gif
[pic.PspCallProcessNotifyRoutinesXrefs]: res/PspCallProcessNotifyRoutinesXrefs.png
[gif.SurivDemo]: res/SurivDemo.gif