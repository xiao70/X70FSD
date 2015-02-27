#ifndef __X70FSDDATA_H__
#define __X70FSDDATA_H__

#include "X70FsdStruct.h"

VOID GetFltRoutineAddress();

NTSTATUS InitDriverEntry(__in PDRIVER_OBJECT DriverObject,
						 __in PUNICODE_STRING RegistryPath);

NTSTATUS MyGetFileStandardInfo(
	__in  PFLT_CALLBACK_DATA Data,
	__in  PCFLT_RELATED_OBJECTS FltObjects,
	__in	PFILE_OBJECT FileObject,
	__in PLARGE_INTEGER FileAllocationSize,
	__in PLARGE_INTEGER FileSize,
	__in PBOOLEAN bDirectory
	);

BOOLEAN HashFilePath(PUNICODE_STRING pFileFullPath,PUCHAR HashValue);

BOOLEAN FindExistFcb(PUCHAR HashValue,PFCB * pFcb);

BOOLEAN IsMyFakeFcb(PFILE_OBJECT FileObject);

FLT_PREOP_CALLBACK_STATUS
X70FsdCompleteMdl (
					 __inout PFLT_CALLBACK_DATA Data,
					 __in PCFLT_RELATED_OBJECTS FltObjects,
					 __in PIRP_CONTEXT IrpContext
					 );

BOOLEAN
X70FsdCMCAcquireForLazyWrite (
    IN PVOID Context,
    IN BOOLEAN Wait
    );

VOID
X70FsdCMCReleaseFromLazyWrite (
    IN PVOID Context
    );

BOOLEAN
X70FsdCMCAcquireForReadAhead (
    IN PVOID Context,
    IN BOOLEAN Wait
    );
VOID
X70FsdCMCReleaseFromReadAhead (
    IN PVOID Context
    );


PVOID
X70FsdMapUserBuffer (
					   __inout PFLT_CALLBACK_DATA Data
					   );

PIRP_CONTEXT
X70FsdCreateIrpContext (
						  IN PFLT_CALLBACK_DATA Data,
						  IN PCFLT_RELATED_OBJECTS FltObjects,
						  IN BOOLEAN Wait
						  );
PTOP_LEVEL_CONTEXT
X70FsdSetTopLevelIrp (
						IN PTOP_LEVEL_CONTEXT TopLevelContext,
						IN BOOLEAN ForceTopLevel,   //read Ê±ºòÎªtrue true
						IN BOOLEAN SetTopLevel
						);

VOID
X70FsdFinishIoAtEof (
					   IN PFSRTL_ADVANCED_FCB_HEADER Header
					   );

BOOLEAN
X70FsdWaitForIoAtEof (
						IN PFSRTL_ADVANCED_FCB_HEADER Header,
						IN OUT PLARGE_INTEGER FileOffset,
						IN ULONG Length,
						IN PEOF_WAIT_BLOCK EofWaitBlock
						);

VOID
X70FsdDeleteIrpContext (
						  IN OUT PIRP_CONTEXT *IrpContext
						  );

VOID
X70FsdCompleteRequest (
						 IN OUT PIRP_CONTEXT *IrpContext OPTIONAL,
						 IN OUT PFLT_CALLBACK_DATA *Data  OPTIONAL,
						 IN NTSTATUS Status,
						 IN BOOLEAN Pending
						 );

VOID
X70FsdLockUserBuffer (
						IN PIRP_CONTEXT IrpContext,
						IN OUT PFLT_CALLBACK_DATA Data,
						IN LOCK_OPERATION Operation,
						IN ULONG BufferLength
						);
BOOLEAN X70FsdAcquireExclusiveFcb (
    IN PIRP_CONTEXT IrpContext,
    IN PFCB Fcb
    );


BOOLEAN X70FsdAcquireSharedFcbWaitForEx (
    IN PIRP_CONTEXT IrpContext,
    IN PFCB Fcb
	);

VOID
X70FsdPopUpFileCorrupt (
    IN PIRP_CONTEXT IrpContext,
    IN PFCB Fcb
    );

VOID
X70FsdLookupFileAllocationSize (
    IN PIRP_CONTEXT IrpContext,
    IN PFCB Fcb,
	IN PCCB Ccb
    );

BOOLEAN X70FsdAcquireSharedFcb (
    IN PIRP_CONTEXT IrpContext,
    IN PFCB Fcb
    );

VOID X70FsdFspDispatchWorkItem (
								  IN PDEVICE_OBJECT  DeviceObject,
								  IN PVOID  Context 
								  );

VOID
X70FsdProcessException (
						 IN OUT PIRP_CONTEXT *IrpContext OPTIONAL,
						 IN OUT PFLT_CALLBACK_DATA *Data  OPTIONAL,
						 IN NTSTATUS Status				 
						 );

VOID X70FsdFspDispatch (
						   PVOID  Context 
						  );

VOID
X70FsdPrePostIrp (
					IN PFLT_CALLBACK_DATA Data,
					IN PVOID Context
					
					);

VOID
X70FsdAddToWorkque (					  
					  IN PFLT_CALLBACK_DATA Data,
					  IN PIRP_CONTEXT IrpContext
					  );

VOID
X70FsdOplockComplete (
						IN PFLT_CALLBACK_DATA Data,
						IN PVOID Context
					);

BOOLEAN
X70FsdZeroData (
			  IN PIRP_CONTEXT IrpContext,
			  IN PFCB Fcb,
			  IN PFILE_OBJECT FileObject,
			  IN LONGLONG StartingZero,
			  IN LONGLONG ByteCount,
			  IN ULONG SectorSize
			  );


NTSTATUS
X70FsdPostRequest(
					__inout PFLT_CALLBACK_DATA Data,
					__in	  PIRP_CONTEXT IrpContext
					);

PCCB X70FsdCreateCcb();

NTSTATUS WriteFileHeader(PCFLT_RELATED_OBJECTS FltObjects,PFILE_OBJECT FileObject,PLARGE_INTEGER RealFileSize,PUCHAR ProcessGuid,PUNICODE_STRING FileFullName);

NTSTATUS X70FsdOverWriteFile(
							   PFILE_OBJECT FileObject,
							   PFCB Fcb,
							   LARGE_INTEGER AllocationSize
							   );

NTSTATUS OpenFileAndFcb(__inout PFLT_CALLBACK_DATA Data,
						  __in PCFLT_RELATED_OBJECTS FltObjects,
						  __in PUNICODE_STRING FileName,
						  __in PLARGE_INTEGER FileAllocationSize,
						  __in PLARGE_INTEGER FileSize,
						  __in PUCHAR HashValue,
						  __in PACCESS_MASK DesiredAccess,
						  __in PULONG	ShareAccess);

NTSTATUS CreateFileAndFcb(__inout PFLT_CALLBACK_DATA Data,
						  __in PCFLT_RELATED_OBJECTS FltObjects,
						  __in PUNICODE_STRING FileName,
						  __in PLARGE_INTEGER FileAllocationSize,
						  __in PLARGE_INTEGER FileSize,
						  __in PUCHAR HashValue,
						  __in PACCESS_MASK DesiredAccess,
						  __in PULONG	ShareAccess);

NTSTATUS CreateFcbAndCcb(__inout PFLT_CALLBACK_DATA Data,
						  __in PCFLT_RELATED_OBJECTS FltObjects,
						  __in PIRP_CONTEXT IrpContext,
						  __in PUCHAR HashValue
						  );

BOOLEAN RemoveFcbList(PUCHAR HashValue,PFCB *Fcb);

//ÊÍ·ÅFCB
BOOLEAN X70FsdFreeFcb(PFCB Fcb,PIRP_CONTEXT IrpContext);

PERESOURCE
X70FsdAllocateResource ( );

NTSTATUS X70FsdSyncMoreProcessingCompRoutine(
					IN PDEVICE_OBJECT  DeviceObject,
					IN PIRP  Irp,
					IN PVOID  Context
					);


BOOLEAN UpdateHashValue(PUCHAR OldHashValue,PUCHAR NewHashValue,PFCB * pFcb);

VOID X70FsdRaiseStatus(PIRP_CONTEXT IrpContext,NTSTATUS Status);

FLT_PREOP_CALLBACK_STATUS
MyFltProcessFileLock (
    __in PFILE_LOCK FileLock,
    __in PFLT_CALLBACK_DATA  CallbackData,
    __in_opt PVOID Context
    );

BOOLEAN
MyFltCheckLockForReadAccess (
    __in PFILE_LOCK FileLock,
    __in PFLT_CALLBACK_DATA  CallbackData
    );

BOOLEAN
MyFltCheckLockForWriteAccess (
    __in PFILE_LOCK FileLock,
    __in PFLT_CALLBACK_DATA  CallbackData
    );

NTSTATUS ModifyFileHeader(PCFLT_RELATED_OBJECTS FltObjects,PFILE_OBJECT FileObject,PLARGE_INTEGER pRealFileSize,PUCHAR ProcessGuid,PUNICODE_STRING pFileFullName,MODIFY_TYPE ModType);

NTSTATUS CleanupSetFile(PCFLT_RELATED_OBJECTS FltObjects,PFCB Fcb,PCCB Ccb);

NTSTATUS GetFileStreamRealSize(PIRP_CONTEXT IrpContext,PCFLT_RELATED_OBJECTS FltObjects,PWCHAR StreamName ,ULONG StreamNameLength,PBOOLEAN IsEnFile);

NTSTATUS TransformFileToEncrypted(PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS FltObjects,PFCB Fcb,PCCB Ccb);

NTSTATUS TransformFileToDisEncrypt( PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS FltObjects,PFCB Fcb,PCCB Ccb);

NTSTATUS GetCurrentProcessFullPath(PEPROCESS pEprocess,PUNICODE_STRING ProcessFullPath);

NTSTATUS
GetCurrentProcessFullName(PEPROCESS Eprocess,PUNICODE_STRING ProcessFullPath);

NTSTATUS ExtendingSetFile(PCFLT_RELATED_OBJECTS FltObjects,PFCB Fcb,PCCB Ccb);

VOID UnloadDriver();

BOOLEAN IsLicenseProcess(HANDLE ProId,PEPROCESS Eprocess,PULONG ProType,PBOOLEAN pbParentProcessLicense,PUCHAR ProcessGuid);

BOOLEAN RemoveTrustProcess(PPROCESS_HASH pProcHash);

BOOLEAN InsertTrustProcess(PPROCESS_HASH pProcHash);

BOOLEAN FreeTrustProcess();

BOOLEAN
X70FsdIsIrpTopLevel (
    IN PFLT_CALLBACK_DATA Data
    );

NTSTATUS ExtendingValidDataSetFile(PCFLT_RELATED_OBJECTS FltObjects,PFCB Fcb,PCCB Ccb);

BOOLEAN InSameVACB(IN ULONGLONG LowAddress, IN ULONGLONG HighAddress);

BOOLEAN OS_VISTA_LATER();

VOID NetFileSetCacheProperty(PFILE_OBJECT FileObject,ACCESS_MASK DesiredAccess);

NTSTATUS CreatedFileHeaderInfo(PIRP_CONTEXT IrpContext);

NTSTATUS CreatedFileWriteHeader(PIRP_CONTEXT IrpContext);

#endif