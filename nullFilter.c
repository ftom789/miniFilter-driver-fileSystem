#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Ntddvol.h>
#include <bcrypt.h>


//read - https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt

#ifndef ROUND_TO_SIZE
#define ROUND_TO_SIZE(_length, _alignment)    \
            (((_length) + ((_alignment)-1)) & ~((_alignment) - 1))
#endif

#ifndef FlagOn
#define FlagOn(_F,_SF)        ((_F) & (_SF))
#endif


#define USB_NAME L"USBSTOR\\DiskSanDisk_Cruzer_Blade____1.00"
//#define IOCTL_VOLUME_BASE   ((DWORD32) 'V')

//#define IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS    CTL_CODE(IOCTL_VOLUME_BASE, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define DFDBG_TRACE_ERRORS              0x00000001
#define DFDBG_TRACE_ROUTINES            0x00000002
#define DFDBG_TRACE_OPERATION_STATUS    0x00000004

#define DF_VOLUME_GUID_NAME_SIZE        48

#define DF_INSTANCE_CONTEXT_POOL_TAG    'nIfD'
#define DF_STREAM_CONTEXT_POOL_TAG      'xSfD'
#define DF_TRANSACTION_CONTEXT_POOL_TAG 'xTfD'
#define DF_ERESOURCE_POOL_TAG           'sRfD'
#define DF_DELETE_NOTIFY_POOL_TAG       'nDfD'
#define DF_STRING_POOL_TAG              'rSfD'

#define DF_CONTEXT_POOL_TYPE            PagedPool

#define DF_NOTIFICATION_MASK            (TRANSACTION_NOTIFY_COMMIT_FINALIZE | \
                                         TRANSACTION_NOTIFY_ROLLBACK)

#define DEVICE_SEND CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_WRITE_DATA)
#define DEVICE_REC CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_READ_DATA)


UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\UsbDiskOnKeyDriver");
UNICODE_STRING SymlinkName = RTL_CONSTANT_STRING(L"\\??\\UsbDiskOnKeySymName");


PDEVICE_OBJECT DeviceObject = NULL;


typedef struct {
    BCRYPT_ALG_HANDLE phAlgorithm;
    BCRYPT_KEY_HANDLE phKey;
    PUCHAR pbKeyObject;
    PUCHAR pbIV;
    UINT32 cbBlockLen;
} BcryptHandles,*PBcryptHandles;



BcryptHandles bHandles;

NTSTATUS CopyUnicodeStrings(UNICODE_STRING dest, UNICODE_STRING source)
{
    dest.Length = source.Length;
    dest.MaximumLength = source.MaximumLength;
    dest.Buffer=(PWCHAR)ExAllocatePool(NonPagedPool, source.MaximumLength);
    if (dest.Buffer != NULL)
    {
        RtlZeroMemory(dest.Buffer, source.MaximumLength);
        RtlCopyMemory(dest.Buffer, source.Buffer, dest.MaximumLength);
        return STATUS_BUFFER_ALL_ZEROS;
    }
    return STATUS_SUCCESS;

}

NTSTATUS
DfAllocateUnicodeString(
    _Inout_ PUNICODE_STRING String
)
/*++
Routine Description:
    This helper routine simply allocates a buffer for a UNICODE_STRING and
    initializes its Length to zero.
    It uses whatever value is present in the MaximumLength field as the size
    for the allocation.
Arguments:
    String - Pointer to UNICODE_STRING.
Return Value:
    STATUS_INSUFFICIENT_RESOURCES if it was not possible to allocate the
    buffer from pool.
    STATUS_SUCCESS otherwise.
--*/
{
    PAGED_CODE();

    ASSERT(NULL != String);
    ASSERT(0 != String->MaximumLength);

    String->Length = 0;

    String->Buffer = ExAllocatePoolWithTag(DF_CONTEXT_POOL_TYPE,
        String->MaximumLength,
        DF_STRING_POOL_TAG);

    if (NULL == String->Buffer) {

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

VOID
DfFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
)
/*++
Routine Description:
    This helper routine frees the buffer of a UNICODE_STRING and resets its
    Length to zero.
Arguments:
    String - Pointer to UNICODE_STRING.
--*/
{
    PAGED_CODE();

    ASSERT(NULL != String);
    ASSERT(0 != String->MaximumLength);

    String->Length = 0;

    if (NULL != String->Buffer) {

        String->MaximumLength = 0;
        ExFreePool(String->Buffer);
        String->Buffer = NULL;
    }
}

//https://github.com/microsoft/Windows-driver-samples/tree/master/filesys/miniFilter/nullFilter
//https://community.osr.com/discussion/237575/minifilter-directly-changing-irp-mj-write-buffers



PFLT_FILTER FilterHandle = NULL;
NTSTATUS AddDevice(__in struct _DRIVER_OBJECT* DriverObject, __in struct _DEVICE_OBJECT* PhysicalDeviceObject);
NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_POSTOP_CALLBACK_STATUS MiniPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS MiniPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS MiniPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS MiniPreRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
NTSTATUS PfltInstanceSetupCallback(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
);
NTSTATUS Decrypt(PVOID EncryptedData, ULONG size, PVOID* Data, PULONG SizeOfBuffer);
NTSTATUS Encrypt(PVOID Data, ULONG size, PVOID* EncryptedData, PULONG SizeOfBuffer);
VOID PrintBuffer(PVOID buffer, ULONG size);

const FLT_OPERATION_REGISTRATION Callbacks[] = {
 {IRP_MJ_CREATE, 0, MiniPreCreate, MiniPostCreate},
 {IRP_MJ_WRITE, 0, MiniPreWrite, NULL},
 {IRP_MJ_READ, 0, MiniPreRead, NULL},
 {IRP_MJ_OPERATION_END}
};

const FLT_REGISTRATION FilterRegistration = {
 sizeof(FLT_REGISTRATION),
 FLT_REGISTRATION_VERSION,
 0,
 NULL,
 Callbacks,
 MiniUnload,
 PfltInstanceSetupCallback,
 NULL,
 NULL,
 NULL,
 NULL,
 NULL,
 NULL,
 NULL
};



typedef struct {
    PFLT_VOLUME Volume;
    UNICODE_STRING GUID;
    PFLT_VOLUME_PROPERTIES VolumeProperties;
} Volume,*PVolume;

PVolume v = NULL;

_Use_decl_annotations_
NTSTATUS
MyAddDevice(
    struct _DRIVER_OBJECT* DriverObject,
    struct _DEVICE_OBJECT* PhysicalDeviceObject
)
{
    KdPrint(("adddevice call"));
    return STATUS_SUCCESS;
}




NTSTATUS PfltInstanceSetupCallback(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    

    NTSTATUS status;
    //KdPrint(("Volume"));
    
    KdPrint(("-------------\n"));
    //v->Volume = FltObjects->Volume;
    
    KdPrint(("Print Volume\n"));
    
    ULONG BufferSize;
    status = FltGetVolumeGuidName(FltObjects->Volume, NULL, &BufferSize);
    
    UNICODE_STRING tempString;
    tempString.MaximumLength = BufferSize *
        sizeof(WCHAR) +
        sizeof(WCHAR);

    
    
    
    status = DfAllocateUnicodeString(&tempString);
    

    status = FltGetVolumeGuidName(FltObjects->Volume, &tempString, &BufferSize);

    if (status == STATUS_BUFFER_TOO_SMALL)
    {
        KdPrint(("Buffer too small\n"));
    }
    else if (status == STATUS_INSUFFICIENT_RESOURCES)
    {
        KdPrint(("STATUS_INSUFFICIENT_RESOURCES\n"));
    }
    else if (status == STATUS_INVALID_DEVICE_REQUEST)
    {
        KdPrint(("STATUS_INVALID_DEVICE_REQUEST\n"));
    }
    else if (status == STATUS_FLT_VOLUME_NOT_FOUND)
    {
        KdPrint(("STATUS_FLT_VOLUME_NOT_FOUND\n"));
    }
    //CopyUnicodeStrings(v->GUID, tempString);
    KdPrint(("guid: %wZ\n", tempString));
    DfFreeUnicodeString(&tempString);
    



    PFLT_VOLUME_PROPERTIES volumeProperties=(PFLT_VOLUME_PROPERTIES)ExAllocatePool(NonPagedPool, (sizeof(FLT_VOLUME_PROPERTIES) + 512));
    ULONG volumePropertiesLength;
    
    status = FltGetVolumeProperties(FltObjects->Volume,
        volumeProperties,
        (sizeof(FLT_VOLUME_PROPERTIES) + 512) ,
        &volumePropertiesLength);
    if (status== STATUS_BUFFER_OVERFLOW)
    {
        KdPrint(("STATUS_BUFFER_OVERFLOW\n"));
    }
    else if (status == STATUS_BUFFER_TOO_SMALL)
    {
        KdPrint(("STATUS_BUFFER_TOO_SMALL\n"));
    }
    else {
        KdPrint(("Success DeviceName Properties %wZ\n", volumeProperties->FileSystemDeviceName));
        KdPrint(("Success RealDeviceName Properties %wZ\n",volumeProperties->RealDeviceName));
        KdPrint(("Success DriverName Properties %wZ\n", volumeProperties->FileSystemDriverName));
        
    }
    KdPrint(("->->->->->\n"));
    
    PDEVICE_OBJECT deviceObj = NULL;
    status = FltGetDiskDeviceObject(FltObjects->Volume, &deviceObj);


    if (!NT_SUCCESS(status)||deviceObj==NULL)
    {
        KdPrint(("failed deviceObj\n"));
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    /*
    PDEVICE_OBJECT DeviceObj=NULL;
    PFILE_OBJECT fileObj = NULL;
    
    
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\??\\PhysicalDrive1");
    status=IoGetDeviceObjectPointer(&DeviceName,FILE_ALL_ACCESS,&fileObj,&DeviceObj);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("failed get deviceObj"));
        return STATUS_SUCCESS;
    }
    PDEVICE_OBJECT PhyDeviceObj = NULL;
    PhyDeviceObj = IoGetDeviceAttachmentBaseRef(DeviceObj);
    if (PhyDeviceObj == NULL)
    {
        KdPrint(("failed get PhysicDeviceObj"));
    }
    
    int size = 32;
    PWCHAR deviceID = (PWCHAR)ExAllocatePool(NonPagedPool, size);
    ULONG dataLen;
    RtlZeroMemory(deviceID, size);
    status = IoGetDeviceProperty(PhyDeviceObj, DevicePropertyHardwareID, size, deviceID, &dataLen);
    
    while (status == STATUS_BUFFER_TOO_SMALL)
    {
       
            
        ExFreePool(deviceID);
        size *= 2;
        deviceID = (PWCHAR)ExAllocatePool(NonPagedPool, size);
        RtlZeroMemory(deviceID, size);
        status = IoGetDeviceProperty(PhyDeviceObj, DevicePropertyHardwareID, size, deviceID, &dataLen);
        if (status == STATUS_BUFFER_TOO_SMALL)
        {
            KdPrint(("STATUS_BUFFER_TOO_SMALL\n"));
        }
        else if (status == STATUS_INVALID_PARAMETER_2)
        {
            KdPrint(("STATUS_INVALID_PARAMETER_2\n"));
        }
        else if (status == STATUS_INVALID_DEVICE_REQUEST)
        {
            KdPrint(("STATUS_INVALID_DEVICE_REQUEST\n"));
        }
        
        
        
    }
    
    if (status == STATUS_BUFFER_TOO_SMALL)
    {
        KdPrint(("STATUS_BUFFER_TOO_SMALL\n"));
    }
    else if (status == STATUS_INVALID_PARAMETER_2)
    {
        KdPrint(("STATUS_INVALID_PARAMETER_2\n"));
    }
    else if (status == STATUS_INVALID_DEVICE_REQUEST)
    {
        KdPrint(("STATUS_INVALID_DEVICE_REQUEST\n"));
    }
    else if (status==STATUS_SUCCESS) {
        KdPrint(("STATUS_SUCCESS\n"));
        size = wcslen(deviceID);
        KdPrint(("deviceId: %d\n", size));
    }
    else
    {
        KdPrint(("error code %x", status));
    }
    
    ExFreePool(deviceID);
    //v->VolumeProperties = &volumeProperties;
    
    */
    /**/

    //https://community.osr.com/discussion/comment/178370#Comment_178370



    KEVENT WaitEvent;
    PIRP NewIrp;
    NTSTATUS status1;
    PDEVICE_OBJECT ndevice;
    PDEVICE_OBJECT device;
    PFILE_OBJECT file;
    ULONG lenght;
    WCHAR hwId[512];
    PVOLUME_DISK_EXTENTS volumeextents;
    PUNICODE_STRING devicename;
    wchar_t data[25];
    IO_STATUS_BLOCK IoStatus = { 0 };
    
    KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);

    volumeextents = (PVOLUME_DISK_EXTENTS)ExAllocatePool(NonPagedPool, sizeof(VOLUME_DISK_EXTENTS));


    //PDEVICE_OBJECT lowerDeviceObj = IoGetLowerDeviceObject(deviceObj);
    NewIrp = IoBuildDeviceIoControlRequest(IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        deviceObj,
        NULL, 0,
        (PVOID)volumeextents, sizeof(VOLUME_DISK_EXTENTS),
        FALSE, &WaitEvent, &IoStatus);
    KdPrint(("status 0x%x \n", IoStatus.Status));

    if (!NewIrp) {
        DbgPrint("Failed to create new IRP,IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS");
        ExFreePool(volumeextents);
        return;
    }

    // send this irp to the storage device
    PIO_STACK_LOCATION irpnext = NULL;
    irpnext = IoGetNextIrpStackLocation(NewIrp);
    DbgPrint("Setze jetz IoCall ab!\n");
    
    status = IoCallDriver(deviceObj, NewIrp);
    
    if (status == STATUS_PENDING) {
        status = KeWaitForSingleObject(&WaitEvent, Executive, KernelMode, FALSE,
            NULL);
        status = IoStatus.Status;
    }

    if (!NT_SUCCESS(status)) {
        DbgPrint("IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS failed, status =0x%x\n", status);
        //Flt
        return STATUS_FLT_DO_NOT_ATTACH;
    }
    
    wcscpy(data, L"\\GLOBAL??\\PhysicalDrive");
    KdPrint(("copy string to data2\n"));
    KdPrint(("status 0x%x \n", IoStatus.Status));
    KdPrint(("exte %d \n", volumeextents->NumberOfDiskExtents));
    data[23] = volumeextents->Extents[0].DiskNumber + 0x30;
    data[24] = 0;

    RtlInitUnicodeString(&devicename, data);
    KdPrint(("Init string\n"));
    IoGetDeviceObjectPointer(&devicename, FILE_READ_ATTRIBUTES, &file, &device);
    ndevice = IoGetDeviceAttachmentBaseRef(device);
    KdPrint(("GotDevice obj\n"));
    status1 = IoGetDeviceProperty(ndevice, DevicePropertyHardwareID, sizeof(hwId), hwId, &lenght);
    KdPrint(("GotDevice Prop\n"));

    if (!NT_SUCCESS(status1)) {
        DbgPrint(" failed, status =0x%x\n", status1);
        
    }
    else
    {
        KdPrint(("the hwid is: %ls", hwId));
        if (wcscmp(USB_NAME, hwId) == 0)
        {
            KdPrint(("identical\n"));
            KdPrint(("-----------------\n"));
            return STATUS_SUCCESS;
        }
    }
    KdPrint(("-----------------\n"));
    /**/
    return STATUS_FLT_DO_NOT_ATTACH;
}


NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    KdPrint(("Driver unloaded2 \r\n"));
    //ExFreePool(v);
    FltUnregisterFilter(FilterHandle);

    return STATUS_SUCCESS;
}

FLT_POSTOP_CALLBACK_STATUS MiniPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    //KdPrint(("Post create is running \r\n"));
    
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS MiniPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION FileNameInfo;
    NTSTATUS status;
    WCHAR Name[200] = { 0 };

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);

    if (NT_SUCCESS(status))
    {
        status = FltParseFileNameInformation(FileNameInfo);

        if (NT_SUCCESS(status))
        {

            if (FileNameInfo->Name.MaximumLength < 200)
            {
                RtlCopyMemory(Name, FileNameInfo->Name.Buffer, FileNameInfo->Name.MaximumLength);
                //KdPrint(("Create file: %ws \r\n", Name));
            }
        }

        FltReleaseFileNameInformation(FileNameInfo);
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS MiniPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION FileNameInfo;
    NTSTATUS status;
    WCHAR Name[200] = { 0 };
    

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);

    if (NT_SUCCESS(status))
    {
        status = FltParseFileNameInformation(FileNameInfo);

        if (NT_SUCCESS(status))
        {

            if (FileNameInfo->Name.MaximumLength < 200)
            {
                RtlCopyMemory(Name, FileNameInfo->Name.Buffer, FileNameInfo->Name.MaximumLength);
                _wcsupr(Name);
                if (wcsstr(Name, L"DFG") != NULL)
                {
                    char* ioBuffer = NULL;
                    PMDL MdlAddress = Data->Iopb->Parameters.Write.MdlAddress;
                    ULONG Length = (ULONG)Data->Iopb->Parameters.Write.Length;

                    if (NULL != MdlAddress)
                    {
                        // Don't expect chained MDLs this high up the stack
                        ASSERT(MdlAddress->Next == NULL);
                        ioBuffer = (char*)MmGetSystemAddressForMdlSafe(MdlAddress, NormalPagePriority);
                    }
                    else
                    {
                        ioBuffer = (char*)Data->Iopb->Parameters.Write.WriteBuffer;
                    }
                    //KdPrint(("Write file: %ws blocked \r\n", Name));

                    if (ioBuffer != NULL)
                    {
                        PVOID EncryptedBuffer;
                        ULONG SizeOfBuffer;
                        
                        
                        PrintBuffer(Data->Iopb->Parameters.Write.WriteBuffer, Length);
                        

                        KdPrint(("buffer SIZE - %lu\n", Length));

                        
                        
                        Encrypt(Data->Iopb->Parameters.Write.WriteBuffer, Data->Iopb->Parameters.Write.Length, &EncryptedBuffer, &SizeOfBuffer);
                        KdPrint(("SizeOfBuffer - %lu\n", SizeOfBuffer));
                        //KdPrint(("buffer - %s\n", EncryptedBuffer));
                       
                        
                        if (EncryptedBuffer != NULL)
                        {
                            KdPrint(("Encrypted buffer is not null\n"));
                            KdPrint(("Size of buffer - %lu\n",SizeOfBuffer));
                            //RtlZeroMemory(Data->Iopb->Parameters.Write.WriteBuffer, Data->Iopb->Parameters.Write.Length);
                            Data->Iopb->Parameters.Write.Length = SizeOfBuffer;
                            Data->Iopb->Parameters.Write.ByteOffset.QuadPart=0;
                               //Data->Iopb->Parameters.Write.WriteBuffer = "abc\0";
                            /*PVOID newBuf = FltAllocatePoolAlignedWithTag(FltObjects->Instance,
                                NonPagedPool,
                                (SIZE_T)SizeOfBuffer,
                                NULL);*/
                            //Data->Iopb->Parameters.Write.WriteBuffer = ExAllocatePool(NonPagedPool, 3);
                            //RtlCopyMemory(newBuf, EncryptedBuffer, SizeOfBuffer);
                            Data->Iopb->Parameters.Write.WriteBuffer = EncryptedBuffer;
                            Data->Iopb->Parameters.Write.MdlAddress = NULL;
                            //RtlCopyMemory(Data->Iopb->Parameters.Write.WriteBuffer, EncryptedBuffer, SizeOfBuffer);
                            Data->IoStatus.Status = STATUS_SUCCESS;
                            Data->IoStatus.Information = SizeOfBuffer;
                            FltSetCallbackDataDirty(Data);//A minifilter driver's preoperation or postoperation callback routine calls FltSetCallbackDataDirty to indicate that it has modified the contents of the callback data structure.

                            //ExFreePool(EncryptedBuffer);
                        }
                        //((char*)Data->Iopb->Parameters.Write.WriteBuffer)[SizeOfBuffer] = 0;
                        KdPrint(("write buffer is - \n"));
                        PrintBuffer(Data->Iopb->Parameters.Write.WriteBuffer, Data->Iopb->Parameters.Write.Length);

                        //KdPrint(("decrypt buffer WriteBuffer - %s\n", Data->Iopb->Parameters.Write.WriteBuffer));
                        PVOID DecryptedBuffer;
                        ULONG SizeOfBufferDecrypt;
                        //((char*)Data->Iopb->Parameters.Write.WriteBuffer)[Data->Iopb->Parameters.Write.Length] = 0;
                        Decrypt(Data->Iopb->Parameters.Write.WriteBuffer, Data->Iopb->Parameters.Write.Length, &DecryptedBuffer, &SizeOfBufferDecrypt);
                        Decrypt(Data->Iopb->Parameters.Write.WriteBuffer, 32, &DecryptedBuffer, &SizeOfBufferDecrypt);
                        KdPrint(("finished\n"));
                        //KdPrint(("the write buffer is: %s\n", ioBuffer));
                    }
                    else {
                        KdPrint(("the write buffer is null\n"));
                    }
                    

                    //Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
                   // Data->IoStatus.Information = 0;
                    //FltReleaseFileNameInformation(FileNameInfo);


                    //return FLT_PREOP_COMPLETE; //this return status will make the Io manager to not move the irp to the lower drivers
                }
                KdPrint(("Write file: %ws \r\n", Name));
                FltReleaseFileNameInformation(FileNameInfo);

                
                //WCHAR str = { 0 };
                
                //wcsncpy(str, (WCHAR)Buffer, 10);
                

                /*status=FltAllocateContext(FilterHandle, FLT_FILE_CONTEXT, MAXUSHORT, NonPagedPool, &context);
                if (!NT_SUCCESS(status))
                {
                    KdPrint(("failed alloc context \r\n"));
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                }

                RtlZeroMemory(context, MAXUSHORT);
                

                
                
                if (!NT_SUCCESS(status))
                {
                    KdPrint(("failed get file context \r\n"));
                    FltReleaseContext(context);
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                }*/


                
            }
        }

        
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_PREOP_CALLBACK_STATUS MiniPreRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{

    
    PFLT_FILE_NAME_INFORMATION FileNameInfo;
    NTSTATUS status;
    WCHAR Name[200] = { 0 };
    PFLT_CONTEXT context;
    

    KdPrint(("read call\n"));

    status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &context);

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
    
    ULONG readLen = Data->Iopb->Parameters.Read.Length;
    if (readLen == 0)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (NT_SUCCESS(status))
    {
       
        
        
        
        status = FltParseFileNameInformation(FileNameInfo);

        if (NT_SUCCESS(status))
        {
            
            if (FileNameInfo->Name.MaximumLength < 200)
            {
                

                RtlCopyMemory(Name, FileNameInfo->Name.Buffer, FileNameInfo->Name.MaximumLength);
                _wcsupr(Name);
                //KdPrint(("read file %ws\n", Name));
                if (wcsstr(Name, L"DFG") != NULL)
                {
                    KdPrint(("read file %ws\n", Name));
                    PVOID ioBuffer = NULL;
                    PMDL MdlAddress = Data->Iopb->Parameters.Read.MdlAddress;
                    ULONG Length = (ULONG)Data->Iopb->Parameters.Read.Length;
                    LARGE_INTEGER FileSize;
                    FsRtlGetFileSize(FltObjects->FileObject, &FileSize);
                    KdPrint(("Size Of File is %lu\n", FileSize.QuadPart));
                    

                    if (NULL != MdlAddress)
                    {
                        // Don't expect chained MDLs this high up the stack
                        ASSERT(MdlAddress->Next == NULL);
                        ioBuffer = MmGetSystemAddressForMdlSafe(MdlAddress, NormalPagePriority);
                        //KdPrint(("read file Mdl: %s\n", ioBuffer));
                    }
                    else
                    {
                        ioBuffer = Data->Iopb->Parameters.Read.ReadBuffer;

                        //KdPrint(("readBuffer file: %s\n", ioBuffer));
                        //KdPrint(("readBuffer length: %lu\n", Data->Iopb->Parameters.Read.Length));
                        PrintBuffer(Data->Iopb->Parameters.Read.ReadBuffer, (ULONG) FileSize.QuadPart);
                    }

                    if (ioBuffer != NULL)
                    {
                        PVOID DecryptedBuffer;
                        ULONG SizeOfBuffer;
                        //KdPrint(("SizeOfText %lu\n", Data->Iopb->Parameters.Read.Length));
                        Decrypt(Data->Iopb->Parameters.Read.ReadBuffer, 32, &DecryptedBuffer, &SizeOfBuffer);
                        //KdPrint(("decrypt buffer - %s\n", DecryptedBuffer));
                        //KdPrint(("SizeOfBuffer - %lu\n", SizeOfBuffer));
                        
                       
                        /*
                        if (DecryptedBuffer != NULL)
                        {
                            Data->Iopb->Parameters.Read.Length = SizeOfBuffer;
                            Data->Iopb->Parameters.Read.ReadBuffer = DecryptedBuffer;
                            Data->IoStatus.Information = SizeOfBuffer;
                            Data->IoStatus.Status = STATUS_SUCCESS;
                            
                            
                        }
                        */
                        //KdPrint(("decrypt buffer ReadBuffer - %s\n", Data->Iopb->Parameters.Read.ReadBuffer));
                        KdPrint(("finished\n"));
                        FltSetCallbackDataDirty(Data);
                        
                    }
                    else {
                        KdPrint(("read buffer is null\n"));
                    }
                    
                    /*char* str = "234";
                    RtlCopyMemory(Data->Iopb->Parameters.Read.ReadBuffer, str, 4);
                    Data->Iopb->Parameters.Read.Length = 4;*/
                }
            }
        }
        else
        {
            KdPrint(("cant parse file info 0x%x\n"));
        
        }
    }
    else
    {
        KdPrint(("not success read get file info 0x%x\n"));
    }
    
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


ULONG AdaptDataSizeToAesBlockSize(ULONG size)
{
    ULONG start = 16;
    ULONG mul= 1;
    while (start < size)
    {
        start = 16 * mul;
        mul++;
    }
    return start;
}

VOID PrintBuffer(PVOID buffer, ULONG size)
{
    ULONG i;
    char* bufferSTR = (char*)buffer;
    for (i = 0; i < size; i++)
    {
        
        KdPrint(("%02X ", bufferSTR[i]));
    }
    KdPrint(("\n"));
}

NTSTATUS Encrypt(PVOID Data,ULONG size,PVOID *EncryptedData, PULONG SizeOfBuffer)
{
    NTSTATUS status;
    ULONG SizeOfCipherText;
    ULONG newSize = AdaptDataSizeToAesBlockSize(size);
    PVOID newData = ExAllocatePool(NonPagedPool, newSize);
    RtlZeroMemory(newData, newSize);
    RtlCopyMemory(newData, Data, size);
    status = BCryptEncrypt(bHandles.phKey, newData, newSize, NULL, bHandles.pbIV, bHandles.cbBlockLen, NULL, 0, &SizeOfCipherText, BCRYPT_BLOCK_PADDING);
    KdPrint(("NTSTATUS is - 0x%x\n", status));
    *EncryptedData = ExAllocatePool(NonPagedPool, SizeOfCipherText);
    status = BCryptEncrypt(bHandles.phKey, newData, newSize, NULL, bHandles.pbIV, bHandles.cbBlockLen, *EncryptedData, SizeOfCipherText, &SizeOfCipherText, BCRYPT_BLOCK_PADDING);
    KdPrint(("NTSTATUS is - 0x%x\n", status));
    KdPrint(("Encrypt buffer in function - \n"));
    PrintBuffer(*EncryptedData, SizeOfCipherText);
    *SizeOfBuffer = SizeOfCipherText;
    //KdPrint(("Size of buffer - %lu\n", *SizeOfBuffer));
    //KdPrint(("Size of buffer - %lu\n", SizeOfCipherText));
    
    
    //PVOID DecryptBuffer;
    //ULONG SizeOfDecryptBuffer;
    //Decrypt(*EncryptedData, SizeOfBuffer, &DecryptBuffer, &SizeOfDecryptBuffer);
    /*
    ULONG SizeOfPlainText;
    PVOID Data2;
    status = BCryptDecrypt(bHandles.phKey, *EncryptedData, SizeOfCipherText, NULL, NULL, 0, NULL, 0, &SizeOfPlainText, BCRYPT_BLOCK_PADDING);
    KdPrint(("Size of plain text - %lu\n", SizeOfPlainText));
    KdPrint(("NTSTATUS is - 0x%x\n", status));
    Data2 = ExAllocatePool(NonPagedPool, SizeOfPlainText);
    status = BCryptDecrypt(bHandles.phKey, *EncryptedData, SizeOfCipherText, NULL, NULL, 0, Data2, SizeOfPlainText, &SizeOfPlainText, BCRYPT_BLOCK_PADDING);
    KdPrint(("decrypt buffer in function - %s\n", Data2));
    KdPrint(("NTSTATUS is - 0x%x\n", status));
    */
    //*SizeOfBuffer = SizeOfPlainText;
    return STATUS_SUCCESS;
}

NTSTATUS Decrypt(PVOID EncryptedData, ULONG size, PVOID *Data, PULONG SizeOfBuffer)
{
    NTSTATUS status;
    ULONG SizeOfPlainText;
    //PVOID Data2;
    //ULONG newSize = AdaptDataSizeToAesBlockSize(size);
    KdPrint(("Size OFFFF Encrypt buffer in function - %lu\n",size));
    KdPrint(("Encrypt buffer in function - \n"));
    PrintBuffer(EncryptedData, size);
    
    status = BCryptDecrypt(bHandles.phKey, EncryptedData, size, NULL, bHandles.pbIV, bHandles.cbBlockLen, NULL, 0, &SizeOfPlainText, BCRYPT_BLOCK_PADDING);
    KdPrint(("Size of plain text - %lu\n", SizeOfPlainText));
    KdPrint(("NTSTATUS is - 0x%x\n", status));
    *Data = ExAllocatePool(NonPagedPool, SizeOfPlainText);
    //*Data = "sdfsdf";
    PrintBuffer(*Data, SizeOfPlainText);
    status = BCryptDecrypt(bHandles.phKey, EncryptedData, size, NULL, bHandles.pbIV, bHandles.cbBlockLen, *Data, SizeOfPlainText, &SizeOfPlainText, BCRYPT_BLOCK_PADDING);
    KdPrint(("decrypt buffer in function - \n"));
    PrintBuffer(*Data, SizeOfPlainText);
    KdPrint(("NTSTATUS is - 0x%x\n", status));
    *SizeOfBuffer = SizeOfPlainText;
    /*
    NTSTATUS status;
    ULONG SizeOfPlainText;
    ULONG newSize = AdaptDataSizeToAesBlockSize(size);

    status = BCryptDecrypt(bHandles.phKey, EncryptedData, newSize, NULL, NULL, 0, NULL, 0, &SizeOfPlainText, BCRYPT_BLOCK_PADDING);
    KdPrint(("Size of plain text - %lu\n", SizeOfPlainText));
    KdPrint(("NTSTATUS is - 0x%x\n", status));
    *Data = ExAllocatePool(NonPagedPool, SizeOfPlainText);
    status = BCryptDecrypt(bHandles.phKey, EncryptedData, newSize, NULL, NULL, 0, *Data, SizeOfPlainText, &SizeOfPlainText, BCRYPT_BLOCK_PADDING);
    KdPrint(("decrypt buffer in function - %s\n", Data));
    KdPrint(("NTSTATUS is - 0x%x\n", status));
    *SizeOfBuffer = SizeOfPlainText;
    */
    return STATUS_SUCCESS;
}

NTSTATUS ReadIOCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(Irp);
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLength = irpsp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLength = irpsp->Parameters.DeviceIoControl.OutputBufferLength;
    KdPrint(("ReadIOCTLLL"));
    switch (irpsp->Parameters.DeviceIoControl.IoControlCode) {
    case DEVICE_SEND:
        break;
    case DEVICE_REC:
        break;
    }


    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    
    NTSTATUS status;
    KdPrint(("HEELL\n"));
    
    //DRIVER_ADD_DEVICE MyAddDevice;
    //DriverObject->DriverExtension->AddDevice = MyAddDevice;


    /*status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

    if (!NT_STATUS(status))
    {
        return status;
    }*/

    BCRYPT_ALG_HANDLE phAlgorithm;

    
    status = BCryptOpenAlgorithmProvider(
        &phAlgorithm,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0
    );
    KdPrint(("NTSTATUS is - 0x%x\n", status));

    UINT32 cbKeyObject;
    ULONG cbData;
    status = BCryptGetProperty(
        phAlgorithm,
        BCRYPT_OBJECT_LENGTH,
        &cbKeyObject,
        sizeof(UINT32),
        &cbData,
        0
    );
    KdPrint(("NTSTATUS is - 0x%x\n", status));
    BCRYPT_KEY_HANDLE keyHandle = { 0 };

    //int size = 1024;
    PUCHAR key = (PUCHAR)ExAllocatePool(NonPagedPool, cbKeyObject);


    UINT32 cbBlockLen;
    status = BCryptGetProperty(
        phAlgorithm,
        BCRYPT_OBJECT_LENGTH,
        &cbBlockLen,
        sizeof(UINT32),
        &cbData,
        0
    );
    KdPrint(("NTSTATUS is - 0x%x\n", status));
    PUCHAR pbIV=(PUCHAR)ExAllocatePool(NonPagedPool, cbBlockLen);
    const UCHAR rgbPlaintext[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    static const UCHAR rgbIV[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    static const UCHAR rgbAES128Key[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    
    RtlCopyMemory(pbIV, rgbIV, cbBlockLen);

    status = BCryptSetProperty(
        phAlgorithm,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0);
    KdPrint(("NTSTATUS is - 0x%x\n", status));

    //PUCHAR secret = (PUCHAR)ExAllocatePool(NonPagedPool, 12);
    
    
    //strcpy((char*)secret, "tomhapro123");
    //KdPrint(("secret - %s\n", secret));
    status = BCryptGenerateSymmetricKey(phAlgorithm, &keyHandle, key, cbKeyObject, rgbAES128Key, sizeof(rgbAES128Key), 0);




    KdPrint(("NTSTATUS is - 0x%x\n", status));
    bHandles.phKey = keyHandle;
    bHandles.pbKeyObject = key;
    bHandles.phAlgorithm = phAlgorithm;
    bHandles.pbIV = pbIV;
    bHandles.cbBlockLen = cbBlockLen;


    status = IoCreateSymbolicLink(&SymlinkName, &DeviceName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(DeviceObject);
        return status;

    }


    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ReadIOCTL;
    


    //DriverObject->MajorFunction[IRP_MJ_READ] = ReturnPassTrue;
    //DriverObject->MajorFunction[IRP_MJ_WRITE] = GetPass;




    status = FltRegisterFilter(DriverObject, &FilterRegistration, &FilterHandle);

    if (NT_SUCCESS(status))
    {
       
        //v = (PVolume)ExAllocatePool(NonPagedPool, sizeof(Volume)); //allocate memory for Volume struct
        //IoGetDeviceObjectPointer
        //IoGetDeviceAttachmentBaseRef

        status = FltStartFiltering(FilterHandle);
        if (!NT_SUCCESS(status))
        {
            FltUnregisterFilter(FilterHandle);
        }

        
        //char VolumeName[30] = "\\Device\\HarddiskVolume";
        
        
        
        /*
        BOOLEAN Found = FALSE;
        int i = 1;

        while (!Found&&i!=2)
        {
            if (v != NULL)
            {
                strcpy(VolumeName, "\\Device\\HarddiskVolume");
                RtlZeroMemory(v, sizeof(Volume));

                char num[4];

                itoa(i, &num, 10);

                strcat(VolumeName, num);
                wchar_t  ws[100];
                mbstowcs(ws, VolumeName, 100);

                UNICODE_STRING str = RTL_CONSTANT_STRING(ws);

                KdPrint(("%wZ \n", str));

                CopyUnicodeStrings(v->VolumeName, str);
                
                //KdPrint(("%wZ \n", v->VolumeName));
                v->Volume = NULL;
                UNICODE_STRING str2 = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume2");
                str.Length = str2.Length;
                status=FltGetVolumeFromName(FilterHandle, &str2,&(v->Volume));
                
                if (!NT_SUCCESS(status))
                {
                    KdPrint(("failed get Pflt Volume\n"));
                    return status;
                }
                
                

                ULONG BufferSize;
                status = FltGetVolumeGuidName(v->Volume, NULL, &BufferSize);

                UNICODE_STRING tempString;
                tempString.MaximumLength = BufferSize *
                    sizeof(WCHAR) +
                    sizeof(WCHAR);

                status = DfAllocateUnicodeString(&tempString);


                status = FltGetVolumeGuidName(v->Volume, &tempString, &BufferSize);

                if (!NT_SUCCESS(status))
                {
                    KdPrint(("failed get GUID\n"));
                    return status;
                }
                KdPrint(("guid: %wZ", tempString));
                DfFreeUnicodeString(&tempString);
                
                */
                /*
                
                UNICODE_STRING guidNeed = RTL_CONSTANT_STRING(L"\\??\\Volume{4d36e967-e325-11ce-bfc1-08002be10318}");
                KdPrint(("guid - %wZ", &v->GUID));
                if ((RtlCompareUnicodeString(&guidNeed,&v->GUID,TRUE)))
                {
                    break;
                }

                
            }
            i++;
        }*/
        

        
    }

    return STATUS_SUCCESS;
}


