/*++

Copyright (c) 1999 - 2002  Microsoft Corporation

Module Name:

passThrough.c

Abstract:

This is the main module of the passThrough miniFilter driver.
This filter hooks all IO operations for both pre and post operation
callbacks.  The filter passes through the operations.

Environment:

Kernel mode

--*/
#include "X70FsdStruct.h"
#include "X70FsdFileInfo.h"
#include "X70FsdCreate.h"
#include "X70FsdData.h" 
#include "X70FsdRead.h"
#include "X70FsdWrite.h"
#include "X70FsdCloseCleanup.h"
#include "X70FsdSupport.h"
#include "X70FsdInterface.h"
#include "X70FsdDirCtrl.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


#define X70FSD_PORT_NAME	L"\\PortXiao70"

PFLT_FILTER gFilterHandle = NULL;
extern COMMAND gCommand;

PFLT_PORT 	gServerPort = NULL;
PFLT_PORT 	gClientPort = NULL;

ULONG_PTR OperationStatusCtx = 1;

#define CONTEXT_TAG 'x70'
#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
	(FlagOn(gTraceFlags,(_dbgLevel)) ?              \
	DbgPrint _string :                          \
	((int)0))

/*************************************************************************
Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
			 __in PDRIVER_OBJECT DriverObject,
			 __in PUNICODE_STRING RegistryPath
			 );

NTSTATUS
PtInstanceSetup (
				 __in PCFLT_RELATED_OBJECTS FltObjects,
				 __in FLT_INSTANCE_SETUP_FLAGS Flags,
				 __in DEVICE_TYPE VolumeDeviceType,
				 __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
				 );

VOID
PtInstanceTeardownStart (
						 __in PCFLT_RELATED_OBJECTS FltObjects,
						 __in FLT_INSTANCE_TEARDOWN_FLAGS Flags
						 );

VOID
PtInstanceTeardownComplete (
							__in PCFLT_RELATED_OBJECTS FltObjects,
							__in FLT_INSTANCE_TEARDOWN_FLAGS Flags
							);

NTSTATUS
PtUnload (
		  __in FLT_FILTER_UNLOAD_FLAGS Flags
		  );

NTSTATUS
PtInstanceQueryTeardown (
						 __in PCFLT_RELATED_OBJECTS FltObjects,
						 __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
						 );

FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough (
						   __inout PFLT_CALLBACK_DATA Data,
						   __in PCFLT_RELATED_OBJECTS FltObjects,
						   __deref_out_opt PVOID *CompletionContext
						   );

VOID
PtOperationStatusCallback (
						   __in PCFLT_RELATED_OBJECTS FltObjects,
						   __in PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
						   __in NTSTATUS OperationStatus,
						   __in PVOID RequesterContext
						   );

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough (
							__inout PFLT_CALLBACK_DATA Data,
							__in PCFLT_RELATED_OBJECTS FltObjects,
							__in_opt PVOID CompletionContext,
							__in FLT_POST_OPERATION_FLAGS Flags
							);

FLT_PREOP_CALLBACK_STATUS
PtPreOperationNoPostOperationPassThrough (
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	);

BOOLEAN
PtDoRequestOperationStatus(
						   __in PFLT_CALLBACK_DATA Data
						   );

VOID
CleanupVolumeContext(
					 __in PFLT_CONTEXT Context,
					 __in FLT_CONTEXT_TYPE ContextType
					 );

NTSTATUS GenerateFileName(IN PFLT_INSTANCE  Instance,
    IN PFILE_OBJECT  FileObject,
    IN PFLT_CALLBACK_DATA  CallbackData,
    IN FLT_FILE_NAME_OPTIONS  NameOptions,
    OUT PBOOLEAN  CacheFileNameInformation,
    OUT PFLT_NAME_CONTROL  FileName
);

NTSTATUS NormalizeContextCleanupCallback(IN PVOID  *NormalizationContext);

NTSTATUS NormalizeNameComponentCallback ( IN PFLT_INSTANCE  Instance,
										IN PCUNICODE_STRING  ParentDirectory,
										IN USHORT  VolumeNameLength,
										IN PCUNICODE_STRING  Component,
										IN OUT PFILE_NAMES_INFORMATION  ExpandComponentName,
										IN ULONG  ExpandComponentNameLength,
										IN FLT_NORMALIZE_NAME_FLAGS  Flags,
										IN OUT PVOID  *NormalizationContext
);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, PtUnload)
#pragma alloc_text(PAGE, PtInstanceQueryTeardown)
#pragma alloc_text(PAGE, PtInstanceSetup)
#pragma alloc_text(PAGE, PtInstanceTeardownStart)
#pragma alloc_text(PAGE, PtInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE,
	0,
	PtPreOperationCreate,
	PtPostOperationCreate },

	{ IRP_MJ_CREATE_NAMED_PIPE,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_CLOSE,
	0,
	PtPreOperationClose,
	PtPostOperationClose },

	{ IRP_MJ_READ,
	0,
	PtPreOperationRead,
	PtPostOperationRead },

	{ IRP_MJ_WRITE,
	0,
	PtPreOperationWrite,
	PtPostOperationWrite},

	{ IRP_MJ_QUERY_INFORMATION,
	0,
	PtPreOperationQueryInformation,
	PtPostOperationQueryInformation },

	{ IRP_MJ_SET_INFORMATION,
	0,
	PtPreOperationSetInformation,
	PtPostOperationSetInformation },

	{ IRP_MJ_QUERY_EA,
	0,
	PtPreOperationQueryEa,
	PtPostOperationPassThrough },

	{ IRP_MJ_SET_EA,
	0,
	PtPreOperationSetEa,
	PtPostOperationPassThrough },

	{ IRP_MJ_FLUSH_BUFFERS,
	0,
	PtPreOperationFlushBuffers,
	PtPostOperationFlushBuffers },

	{ IRP_MJ_QUERY_VOLUME_INFORMATION,
	0,
	PtPreOperationQueryVolumeInformation,
	PtPostOperationQueryVolumeInformation },

	{ IRP_MJ_SET_VOLUME_INFORMATION,
	0,
	PtPreOperationSetVolumeInformation,
	PtPostOperationSetVolumeInformation },

	{ IRP_MJ_DIRECTORY_CONTROL,
	0,
	PtPreOperationDirCtrl,
	PtPostOperationDirCtrl },

	{ IRP_MJ_FILE_SYSTEM_CONTROL,
	0,
	PtPreOperationFileSystemControl,
	PtPostOperationFileSystemControl },

	{ IRP_MJ_DEVICE_CONTROL,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_INTERNAL_DEVICE_CONTROL,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_SHUTDOWN,
	0,
	PtPreOperationNoPostOperationPassThrough,
	NULL },                              

	{ IRP_MJ_LOCK_CONTROL,
	0,
	PtPreOperationLockControl,
	PtPostOperationLockControl },

	{ IRP_MJ_CLEANUP,
	0,
	PtPreOperationCleanup,
	PtPostOperationCleanup },

	{ IRP_MJ_CREATE_MAILSLOT,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_QUERY_SECURITY,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_SET_SECURITY,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_QUERY_QUOTA,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_SET_QUOTA,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_PNP,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
	0,
	PtPreOperationAcquireForCreateSection ,
	PtPostOperationAcquireForCreateSection },

	{ IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
	0,
	PtPreOperationReleaseForCreateSection,
	PtPostOperationReleaseForCreateSection },

	{ IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
	0,
	PtPreOperationAcquireForModWrite,
	PtPostOperationAcquireForModWrite },

	{ IRP_MJ_RELEASE_FOR_MOD_WRITE,
	0,
	PtPreOperationReleaseForModWrite,
	PtPostOperationReleaseForModWrite },

	{ IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
	0,
	PtPreOperationAcquireForCcFlush,
	PtPostOperationAcquireForCcFlush },

	{ IRP_MJ_RELEASE_FOR_CC_FLUSH,
	0,
	PtPreOperationReleaseForCcFlush,
	PtPostOperationReleaseForCcFlush },

	{ IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
	0,
	PtPreOperationCheckIfPossible,
	PtPostOperationCheckIfPossible },

	{ IRP_MJ_NETWORK_QUERY_OPEN,
	0,
	PtPreOperationNetworkQueryOpen,
	PtPostOperationNetworkQueryOpen },

	{ IRP_MJ_MDL_READ,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_MDL_READ_COMPLETE,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_PREPARE_MDL_WRITE,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_MDL_WRITE_COMPLETE,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_VOLUME_MOUNT,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_VOLUME_DISMOUNT,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_OPERATION_END }
};


CONST FLT_CONTEXT_REGISTRATION ContextNotifications[] = {

	{ FLT_VOLUME_CONTEXT,
	0,
	CleanupVolumeContext,
	sizeof(VOLUME_CONTEXT),
	CONTEXT_TAG },

	{ FLT_CONTEXT_END }
};

//
//  This defines what we want to filter with FltMgr
//

//

CONST FLT_REGISTRATION FilterRegistration = {

	sizeof( FLT_REGISTRATION ),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,      //0                            //  Flags

	ContextNotifications,                               //  Context
	Callbacks,                          //  Operation callbacks

	PtUnload,                           //  MiniFilterUnload

	PtInstanceSetup,                    //  InstanceSetup
	PtInstanceQueryTeardown,            //  InstanceQueryTeardown
	PtInstanceTeardownStart,            //  InstanceTeardownStart
	PtInstanceTeardownComplete,         //  InstanceTeardownComplete

	GenerateFileName,     //NULL                         //  GenerateFileName
	NormalizeNameComponentCallback,                               //  GenerateDestinationFileName
	NULL,//NormalizeContextCleanupCallback,                                //  NormalizeNameComponent

};

NTSTATUS NormalizeContextCleanupCallback(IN PVOID  *NormalizationContext)
{
	
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	return Status;
}

NTSTATUS GenerateFileName(IN PFLT_INSTANCE  Instance,
    IN PFILE_OBJECT  FileObject,
    IN PFLT_CALLBACK_DATA  CallbackData,
    IN FLT_FILE_NAME_OPTIONS  NameOptions,
    OUT PBOOLEAN  CacheFileNameInformation,
    OUT PFLT_NAME_CONTROL  FileName
) //上层的minifilter过滤驱动的名字请求进行处理
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PFILE_OBJECT StreamObject = FileObject;
	PFLT_FILE_NAME_INFORMATION FileNameInformation = NULL;
	BOOLEAN bEncryptResource = FALSE;
	PFCB Fcb = FileObject->FsContext;
	PCCB Ccb = FileObject->FsContext2;

	FsRtlEnterFileSystem();

	try
	{
		if(IsMyFakeFcb(FileObject))
		{
			

			ExAcquireResourceSharedLite(Fcb->EncryptResource,TRUE);
			bEncryptResource = TRUE;

			if(BooleanFlagOn(Fcb->FcbState,SCB_STATE_SHADOW_CLOSE) || Ccb->StreamFileInfo.StreamObject == NULL)
			{
				try_return (Status = STATUS_FILE_DELETED);
			}
			else
			{			
				StreamObject = Ccb->StreamFileInfo.StreamObject;
			}
		}

		ClearFlag(NameOptions,FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER);

		if(FlagOn(NameOptions,FLT_FILE_NAME_NORMALIZED))
		{
			ClearFlag(NameOptions,FLT_FILE_NAME_NORMALIZED);
			SetFlag(NameOptions,FLT_FILE_NAME_OPENED);
		}
		
		if (CallbackData) 
		{
			PFILE_OBJECT TemFileObject = CallbackData->Iopb->TargetFileObject;
			CallbackData->Iopb->TargetFileObject = StreamObject;

			FltSetCallbackDataDirty(CallbackData);

			Status = FltGetFileNameInformation(CallbackData,NameOptions, &FileNameInformation);
			
			CallbackData->Iopb->TargetFileObject = TemFileObject;
			FltClearCallbackDataDirty(CallbackData);
		} 
		else 
		{
			Status = FltGetFileNameInformationUnsafe(StreamObject,Instance, NameOptions, &FileNameInformation);
		}
		if(!NT_SUCCESS(Status))
		{
			try_return (Status);
		}
		Status = FltCheckAndGrowNameControl(FileName, FileNameInformation->Name.Length);

		if(!NT_SUCCESS(Status))
		{
			try_return (Status);
		}

		RtlCopyUnicodeString(&FileName->Name, &FileNameInformation->Name);

		if(FileNameInformation != NULL)
		{
			FltReleaseFileNameInformation(FileNameInformation);
		}
		Status = STATUS_SUCCESS;
try_exit: NOTHING;
	}
	finally
	{
		if(bEncryptResource)
		{
			ExReleaseResourceLite( Fcb->EncryptResource );
		}
	}
	FsRtlExitFileSystem();
	return Status;
}

NTSTATUS NormalizeNameComponentCallback ( IN PFLT_INSTANCE  Instance,
										IN PCUNICODE_STRING  ParentDirectory,
										IN USHORT  VolumeNameLength,
										IN PCUNICODE_STRING  Component,
										IN OUT PFILE_NAMES_INFORMATION  ExpandComponentName,
										IN ULONG  ExpandComponentNameLength,
										IN FLT_NORMALIZE_NAME_FLAGS  Flags,
										IN OUT PVOID  *NormalizationContext
)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	return Status;
}

VOID
CleanupVolumeContext(
					 __in PFLT_CONTEXT Context,
					 __in FLT_CONTEXT_TYPE ContextType
					 )
{
	PVOLUME_CONTEXT ctx = Context;

	PAGED_CODE();

	UNREFERENCED_PARAMETER( ContextType );

	ASSERT(ContextType == FLT_VOLUME_CONTEXT);

	FltDeleteContext(Context);
}

NTSTATUS
PtInstanceSetup (
				 __in PCFLT_RELATED_OBJECTS FltObjects,
				 __in FLT_INSTANCE_SETUP_FLAGS Flags,
				 __in DEVICE_TYPE VolumeDeviceType,
				 __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
				 )
{
	PDEVICE_OBJECT devObj = NULL;
	PVOLUME_CONTEXT ctx = NULL;
	PFILE_FS_SIZE_INFORMATION VolumeBuffer = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG retLen;
	PUNICODE_STRING workingName;
	USHORT size;
	IO_STATUS_BLOCK IoStatus;

	UCHAR volPropBuffer[sizeof(FLT_VOLUME_PROPERTIES)+512];
	PFLT_VOLUME_PROPERTIES volProp = (PFLT_VOLUME_PROPERTIES)volPropBuffer;

	PAGED_CODE();

	UNREFERENCED_PARAMETER( Flags );
	UNREFERENCED_PARAMETER( VolumeDeviceType );
	UNREFERENCED_PARAMETER( VolumeFilesystemType );

	try {

		//我们在卷上下文中保存扇区大小跟一个资源，用卷上下文完成vcb的工作
		status = FltAllocateContext( FltObjects->Filter,
			FLT_VOLUME_CONTEXT,
			sizeof(VOLUME_CONTEXT),
			NonPagedPool,
			&ctx );

		if (!NT_SUCCESS(status)) 
		{
			leave;
		}

		status = FltGetVolumeProperties( FltObjects->Volume,
			volProp,
			sizeof(volPropBuffer),
			&retLen );

		if (!NT_SUCCESS(status)) 
		{

			leave;
		}

		ASSERT((volProp->SectorSize  == 0) || (volProp->SectorSize  >= MIN_SECTOR_SIZE));

		if(volProp->SectorSize  > MAX_SECTOR_SIZE)
		{
			DbgPrint("不支持这么大的扇区的磁盘 %d \n",volProp->SectorSize );
			status = STATUS_UNSUCCESSFUL;
			leave;
		}

		ctx->SectorSize = max(volProp->SectorSize ,MIN_SECTOR_SIZE);

		ctx->VolResource = X70FsdAllocateResource();

		ctx->DeviceType = volProp->DeviceType;

		VolumeBuffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance,NonPagedPool,sizeof(FILE_FS_SIZE_INFORMATION),'clu');

		if(VolumeBuffer == NULL)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			leave;
		}

		status = FltQueryVolumeInformation(
			FltObjects->Instance,
			&IoStatus,
			VolumeBuffer,
			sizeof(FILE_FS_SIZE_INFORMATION),
			FileFsSizeInformation
			); 

		if (NT_SUCCESS(status)) 
		{

			ctx->SectorsPerAllocationUnit = VolumeBuffer->SectorsPerAllocationUnit;
		}
		else
		{
			ctx->SectorsPerAllocationUnit = 1; //网络设备会返回失败。
		}

		FltIsVolumeWritable(FltObjects->Volume,&ctx->IsWritable );

		status = FltSetVolumeContext( FltObjects->Volume,
			FLT_SET_CONTEXT_KEEP_IF_EXISTS,
			ctx,
			NULL );

		if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) 
		{
			status = STATUS_SUCCESS;
		}

	} 
	finally 
	{

		if (ctx != NULL)
		{

			FltReleaseContext( ctx );
		}
		if(VolumeBuffer != NULL)
		{
			FltFreePoolAlignedWithTag(FltObjects->Instance,VolumeBuffer,'clu');
		}
	}

	return status;
}


NTSTATUS
PtInstanceQueryTeardown (
						 __in PCFLT_RELATED_OBJECTS FltObjects,
						 __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
						 )
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( Flags );

	return STATUS_SUCCESS;
}


VOID
PtInstanceTeardownStart (
						 __in PCFLT_RELATED_OBJECTS FltObjects,
						 __in FLT_INSTANCE_TEARDOWN_FLAGS Flags
						 )
						 /*++

						 Routine Description:

						 This routine is called at the start of instance teardown.

						 Arguments:

						 FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
						 opaque handles to this filter, instance and its associated volume.

						 Flags - Reason why this instance is been deleted.

						 Return Value:

						 None.

						 --*/
{
	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( Flags );

	PAGED_CODE();

	PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
		("PassThrough!PtInstanceTeardownStart: Entered\n") );
}


VOID
PtInstanceTeardownComplete (
							__in PCFLT_RELATED_OBJECTS FltObjects,
							__in FLT_INSTANCE_TEARDOWN_FLAGS Flags
							)
							/*++

							Routine Description:

							This routine is called at the end of instance teardown.

							Arguments:

							FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
							opaque handles to this filter, instance and its associated volume.

							Flags - Reason why this instance is been deleted.

							Return Value:

							None.

							--*/
{
	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( Flags );

	PAGED_CODE();

	PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
		("PassThrough!PtInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
			 __in PDRIVER_OBJECT DriverObject,
			 __in PUNICODE_STRING RegistryPath
			 )
			 /*++

			 Routine Description:

			 This is the initialization routine for this miniFilter driver.  This
			 registers with FltMgr and initializes all global data structures.

			 Arguments:

			 DriverObject - Pointer to driver object created by the system to
			 represent this driver.

			 RegistryPath - Unicode string identifying where the parameters for this
			 driver are located in the registry.

			 Return Value:

			 Returns STATUS_SUCCESS.

			 --*/
{
	NTSTATUS status;
	BOOLEAN bInit = FALSE;

	PSECURITY_DESCRIPTOR sd;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;

	UNREFERENCED_PARAMETER( RegistryPath );

	PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
		("PassThrough!DriverEntry: Entered\n") );
	try
	{
		status = FltRegisterFilter( DriverObject,
			&FilterRegistration,
			&gFilterHandle );

		if (!NT_SUCCESS( status ))
		{
			leave;
		}

#ifdef CV
		VirtualizerStart();
#endif
		status = InitDriverEntry( DriverObject,RegistryPath);
#ifdef CV
		VirtualizerEnd();
#endif
		if (!NT_SUCCESS( status ))
		{
			bInit = FALSE;
			leave;
		}
		
		bInit = TRUE;

		status  = FltBuildDefaultSecurityDescriptor( &sd,
			FLT_PORT_ALL_ACCESS );

		if (!NT_SUCCESS( status )) 
		{
			leave;
		}

		RtlInitUnicodeString( &uniString, X70FSD_PORT_NAME );

		InitializeObjectAttributes( &oa,
			&uniString,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL,
			sd );

		status = FltCreateCommunicationPort( gFilterHandle,
			&gServerPort,
			&oa,
			NULL,
			PtMiniConnect,
			PtMiniDisconnect,
			PtMiniMessage,
			1 );

		FltFreeSecurityDescriptor( sd );

		if (!NT_SUCCESS( status )) 
		{
			leave;
		}

		status = FltStartFiltering( gFilterHandle );

	}
	finally
	{
		if (!NT_SUCCESS( status ) ) 
		{

			if (NULL != gServerPort) 
			{
				FltCloseCommunicationPort( gServerPort);
			}

			if (NULL != gFilterHandle) 
			{
				FltUnregisterFilter( gFilterHandle );
			}
			if(bInit)
			{
				UnloadDriver();
			}
		}
	}
	DbgPrint("status = %x ",status);
	return status;
}

NTSTATUS
PtUnload (
		  __in FLT_FILTER_UNLOAD_FLAGS Flags
		  )
		  /*++

		  Routine Description:

		  This is the unload routine for this miniFilter driver. This is called
		  when the minifilter is about to be unloaded. We can fail this unload
		  request if this is not a mandatory unloaded indicated by the Flags
		  parameter.

		  Arguments:

		  Flags - Indicating if this is a mandatory unload.

		  Return Value:

		  Returns the final status of this operation.

		  --*/
{
	UNREFERENCED_PARAMETER( Flags );

	PAGED_CODE();

	UnloadDriver();

	PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
		("PassThrough!PtUnload: Entered\n") );

	FltUnregisterFilter( gFilterHandle );

	return STATUS_SUCCESS;
}


/*************************************************************************
MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough (
						   __inout PFLT_CALLBACK_DATA Data,
						   __in PCFLT_RELATED_OBJECTS FltObjects,
						   __deref_out_opt PVOID *CompletionContext
						   )
						   /*++

						   Routine Description:

						   This routine is the main pre-operation dispatch routine for this
						   miniFilter. Since this is just a simple passThrough miniFilter it
						   does not do anything with the callbackData but rather return
						   FLT_PREOP_SUCCESS_WITH_CALLBACK thereby passing it down to the next
						   miniFilter in the chain.

						   This is non-pageable because it could be called on the paging path

						   Arguments:

						   Data - Pointer to the filter callbackData that is passed to us.

						   FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
						   opaque handles to this filter, instance, its associated volume and
						   file object.

						   CompletionContext - The context for the completion routine for this
						   operation.

						   Return Value:

						   The return value is the status of the operation.

						   --*/
{
	NTSTATUS status;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;

	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( CompletionContext );

	PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
		("PassThrough!PtPreOperationPassThrough: Entered\n") );

	if(IsMyFakeFcb(FltObjects->FileObject))
	{

		if(FLT_IS_FASTIO_OPERATION(Data)) 
		{
			/*DbgPrint("收到我们自己的fcb请求MajorFunction %x \n",Data->Iopb->MajorFunction );
			DbgPrint("收到我们自己的fcb请求MinorFunction  %x \n",Data->Iopb->MinorFunction  );
			DbgPrint("FastIo Passthru \n");*/
			FltStatus = FLT_PREOP_DISALLOW_FASTIO ;
			return FltStatus;
		}
		if(FLT_IS_IRP_OPERATION(Data))
		{
			DbgPrint("收到我们自己的fcb请求MajorFunction %x \n",Data->Iopb->MajorFunction );
			DbgPrint("收到我们自己的fcb请求MinorFunction  %x \n",Data->Iopb->MinorFunction  );
			DbgPrint("Irp Passthru \n");

			FltStatus = X70FsdPrePassThroughIrp(Data,FltObjects,CompletionContext);		
			return FltStatus;
		}
		if(FLT_IS_FS_FILTER_OPERATION(Data))
		{
			Data->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
			return FltStatus;
		}
	}

	//
	//  See if this is an operation we would like the operation status
	//  for.  If so request it.
	//
	//  NOTE: most filters do NOT need to do this.  You only need to make
	//        this call if, for example, you need to know if the oplock was
	//        actually granted.
	//

	if (PtDoRequestOperationStatus( Data )) {

		status = FltRequestOperationStatusCallback( Data,
			PtOperationStatusCallback,
			(PVOID)(++OperationStatusCtx) );
		if (!NT_SUCCESS(status)) {

			PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
				("PassThrough!PtPreOperationPassThrough: FltRequestOperationStatusCallback Failed, status=%08x\n",
				status) );
		}
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
PtOperationStatusCallback (
						   __in PCFLT_RELATED_OBJECTS FltObjects,
						   __in PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
						   __in NTSTATUS OperationStatus,
						   __in PVOID RequesterContext
						   )
						   /*++

						   Routine Description:

						   This routine is called when the given operation returns from the call
						   to IoCallDriver.  This is useful for operations where STATUS_PENDING
						   means the operation was successfully queued.  This is useful for OpLocks
						   and directory change notification operations.

						   This callback is called in the context of the originating thread and will
						   never be called at DPC level.  The file object has been correctly
						   referenced so that you can access it.  It will be automatically
						   dereferenced upon return.

						   This is non-pageable because it could be called on the paging path

						   Arguments:

						   FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
						   opaque handles to this filter, instance, its associated volume and
						   file object.

						   RequesterContext - The context for the completion routine for this
						   operation.

						   OperationStatus -

						   Return Value:

						   The return value is the status of the operation.

						   --*/
{
	UNREFERENCED_PARAMETER( FltObjects );

	PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
		("PassThrough!PtOperationStatusCallback: Entered\n") );

	PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
		("PassThrough!PtOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
		OperationStatus,
		RequesterContext,
		ParameterSnapshot->MajorFunction,
		ParameterSnapshot->MinorFunction,
		FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough (
							__inout PFLT_CALLBACK_DATA Data,
							__in PCFLT_RELATED_OBJECTS FltObjects,
							__in_opt PVOID CompletionContext,
							__in FLT_POST_OPERATION_FLAGS Flags
							)

{

	UNREFERENCED_PARAMETER( Data );
	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( CompletionContext );
	UNREFERENCED_PARAMETER( Flags );

	if(CompletionContext != NULL)
	{

		X70PostFsdPassThroughIrp(CompletionContext);

	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
PtPreOperationNoPostOperationPassThrough (
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	)
	/*++

	Routine Description:

	This routine is the main pre-operation dispatch routine for this
	miniFilter. Since this is just a simple passThrough miniFilter it
	does not do anything with the callbackData but rather return
	FLT_PREOP_SUCCESS_WITH_CALLBACK thereby passing it down to the next
	miniFilter in the chain.

	This is non-pageable because it could be called on the paging path

	Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
	opaque handles to this filter, instance, its associated volume and
	file object.

	CompletionContext - The context for the completion routine for this
	operation.

	Return Value:

	The return value is the status of the operation.

	--*/
{
	UNREFERENCED_PARAMETER( Data );
	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( CompletionContext );

	PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
		("PassThrough!PtPreOperationNoPostOperationPassThrough: Entered\n") );

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
PtDoRequestOperationStatus(
						   __in PFLT_CALLBACK_DATA Data
						   )
						   /*++

						   Routine Description:

						   This identifies those operations we want the operation status for.  These
						   are typically operations that return STATUS_PENDING as a normal completion
						   status.

						   Arguments:

						   Return Value:

						   TRUE - If we want the operation status
						   FALSE - If we don't

						   --*/
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

	//
	//  return boolean state based on which operations we are interested in
	//

	return (BOOLEAN)

		//
		//  Check for oplock operations
		//

		(((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
		((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
		(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
		(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
		(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

		||

		//
		//    Check for directy change notification
		//

		((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
		(iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
		);
}


//user application Conect
