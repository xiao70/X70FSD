
#include "X70FsdData.h"
#include "X70FsdSupport.h"


extern NPAGED_LOOKASIDE_LIST  G_IoContextLookasideList;
extern USHORT gOsServicePackMajor;
extern ULONG gOsMajorVersion;
extern ULONG gOsMinorVersion;
extern DYNAMIC_FUNCTION_POINTERS gDynamicFunctions;

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationCheckIfPossible(
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

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationFileSystemControl(
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

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationLockControl(
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

	return FLT_POSTOP_FINISHED_PROCESSING;
}
FLT_POSTOP_CALLBACK_STATUS
PtPostOperationFlushBuffers(
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

	return FLT_POSTOP_FINISHED_PROCESSING;
}
//IRP_MJ_QUERY_SECURITY
FLT_POSTOP_CALLBACK_STATUS
PtPostOperationQuerySecurity(
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

	return FLT_POSTOP_FINISHED_PROCESSING;
}
//IRP_MJ_SET_SECURITY
FLT_POSTOP_CALLBACK_STATUS
PtPostOperationSetSecurity(
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

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationAcquireForCcFlush(
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

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationReleaseForCcFlush(
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

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_POSTOP_CALLBACK_STATUS
PtPostOperationAcquireForCreateSection(
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

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationReleaseForCreateSection(
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

	return FLT_POSTOP_FINISHED_PROCESSING;
}



FLT_POSTOP_CALLBACK_STATUS
PtPostOperationAcquireForModWrite(
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

	return FLT_POSTOP_FINISHED_PROCESSING;
}
FLT_POSTOP_CALLBACK_STATUS
PtPostOperationReleaseForModWrite(
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

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationAcquireForModWrite(
								 __inout PFLT_CALLBACK_DATA Data,
								 __in PCFLT_RELATED_OBJECTS FltObjects,
								 __deref_out_opt PVOID *CompletionContext
								 )
{

	BOOLEAN AcquiredFile = FALSE;
	PFSRTL_COMMON_FCB_HEADER Header;
	NTSTATUS Status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
	BOOLEAN AcquireExclusive = FALSE;
	PERESOURCE ResourceAcquired;

	PLARGE_INTEGER EndingOffset = Data->Iopb->Parameters.AcquireForModifiedPageWriter.EndingOffset;
	PERESOURCE * ResourceToRelease = Data->Iopb->Parameters.AcquireForModifiedPageWriter.ResourceToRelease;

	PAGED_CODE();

	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	FsRtlEnterFileSystem();

	Header = (PFSRTL_COMMON_FCB_HEADER) FltObjects->FileObject->FsContext;

	if (Header->Resource == NULL) 
	{
		*ResourceToRelease = NULL;

		Status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
		goto FsRtlAcquireFileForModWrite_CallCompletionCallbacks;
	}
#ifdef CV
	VirtualizerStart();
#endif
	if (FlagOn( Header->Flags, FSRTL_FLAG_ACQUIRE_MAIN_RSRC_EX ) ||
		(EndingOffset->QuadPart > Header->ValidDataLength.QuadPart &&
		Header->ValidDataLength.QuadPart != Header->FileSize.QuadPart)) //扩展文件有效大小
	{

		ResourceAcquired = Header->Resource;
		AcquireExclusive = TRUE;


	} 
	else if (FlagOn( Header->Flags, FSRTL_FLAG_ACQUIRE_MAIN_RSRC_SH ) ||
		Header->PagingIoResource == NULL) 
	{

		ResourceAcquired = Header->Resource;
		AcquireExclusive = FALSE;

	}
	else 
	{

		ResourceAcquired = Header->PagingIoResource;
		AcquireExclusive = FALSE;
	}
#ifdef CV
	VirtualizerEnd();
#endif
	while (TRUE) 
	{

		if (AcquireExclusive)
		{

			if (!ExAcquireResourceExclusiveLite( ResourceAcquired, FALSE )) 
			{

				Status = STATUS_CANT_WAIT;
				goto FsRtlAcquireFileForModWrite_CallCompletionCallbacks;
			}

		} 
		else if (!ExAcquireSharedWaitForExclusive( ResourceAcquired, FALSE )) 
		{

			Status = STATUS_CANT_WAIT;
			goto FsRtlAcquireFileForModWrite_CallCompletionCallbacks;
		}

		if (FlagOn( Header->Flags, FSRTL_FLAG_ACQUIRE_MAIN_RSRC_EX ) ||
			EndingOffset->QuadPart > Header->ValidDataLength.QuadPart) 
		{

			if (!AcquireExclusive) 
			{

				ExReleaseResourceLite( ResourceAcquired );
				AcquireExclusive = TRUE;
				ResourceAcquired = Header->Resource;
				continue;
			}


		} 
		else if (FlagOn( Header->Flags, FSRTL_FLAG_ACQUIRE_MAIN_RSRC_SH )) 
		{

			if (AcquireExclusive) 
			{
				ExConvertExclusiveToSharedLite( ResourceAcquired );

			} 
			else if (ResourceAcquired != Header->Resource) 
			{

				ExReleaseResourceLite( ResourceAcquired );
				ResourceAcquired = Header->Resource;
				AcquireExclusive = TRUE;
				continue;
			}

		} 
		else if (Header->PagingIoResource != NULL
			&& ResourceAcquired != Header->PagingIoResource) 
		{

			ResourceAcquired = NULL;

			if (ExAcquireSharedWaitForExclusive( Header->PagingIoResource, FALSE )) 
			{

				ResourceAcquired = Header->PagingIoResource;
			}

			ExReleaseResourceLite( Header->Resource );

			if (ResourceAcquired == NULL) 
			{

				Status = STATUS_CANT_WAIT;
				goto FsRtlAcquireFileForModWrite_CallCompletionCallbacks;
			}

		} else if (AcquireExclusive) 
		{

			ExConvertExclusiveToSharedLite( ResourceAcquired );

		}

		break;
	}

	*ResourceToRelease = ResourceAcquired;

	Status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;

FsRtlAcquireFileForModWrite_CallCompletionCallbacks:

	Data->IoStatus.Status = Status;
	FsRtlExitFileSystem();

	return FLT_PREOP_COMPLETE;
}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationReleaseForModWrite(
								 __inout PFLT_CALLBACK_DATA Data,
								 __in PCFLT_RELATED_OBJECTS FltObjects,
								 __deref_out_opt PVOID *CompletionContext
								 )
{

	PAGED_CODE();

	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	//Data->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
	//return FLT_PREOP_COMPLETE;

	FsRtlEnterFileSystem();

	if (Data->Iopb->Parameters.ReleaseForModifiedPageWriter.ResourceToRelease) 
	{
		ExReleaseResourceLite(Data->Iopb->Parameters.ReleaseForModifiedPageWriter.ResourceToRelease);
	}

	Data->IoStatus.Status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;

	FsRtlExitFileSystem();

	return FLT_PREOP_COMPLETE;

}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationReleaseForCreateSection(
									  __inout PFLT_CALLBACK_DATA Data,
									  __in PCFLT_RELATED_OBJECTS FltObjects,
									  __deref_out_opt PVOID *CompletionContext
									  )
{
	PFCB Fcb;

	PAGED_CODE();

	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	FsRtlEnterFileSystem();

	Fcb = FltObjects->FileObject->FsContext;

	if (Fcb->Header.Resource) 
	{

		ExReleaseResourceLite( Fcb->Header.Resource);
	}

	Data->IoStatus.Status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;

	FsRtlExitFileSystem();

	return FLT_PREOP_COMPLETE;

}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationAcquireForCreateSection(
									  __inout PFLT_CALLBACK_DATA Data,
									  __in PCFLT_RELATED_OBJECTS FltObjects,
									  __deref_out_opt PVOID *CompletionContext
									  )
{
	PFCB Fcb;
	PCCB Ccb;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	
	PAGED_CODE();

	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	FsRtlEnterFileSystem();

#ifdef CV
	VirtualizerStart();
#endif
	Fcb = FltObjects->FileObject->FsContext;
	Ccb = FltObjects->FileObject->FsContext2;

	if (Fcb->Header.Resource) {

		ExAcquireResourceExclusiveLite( Fcb->Header.Resource, TRUE );
	}
	if(IS_WINDOWSVISTA_OR_LAYER())
	{
		if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) {

			Data->IoStatus.Status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;

		} else if (Fcb->ShareAccess.Writers == 0) {

			Data->IoStatus.Status = STATUS_FILE_LOCKED_WITH_ONLY_READERS;

		} else {

			Data->IoStatus.Status = STATUS_FILE_LOCKED_WITH_WRITERS;
		}
	}
	else
	{
		Data->IoStatus.Status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
	}
	//如果是网络文件,在vista系统以后需要增加缓存中对象的交换
	if(FlagOn(Ccb->CcbState,CCB_FLAG_NETWORK_FILE) && (IS_WINDOWSVISTA_OR_LAYER()))
	{
		ULONG WritableReferences = gDynamicFunctions.pMmDoesFileHaveUserWritableReferences(&Fcb->SectionObjectPointers);

		if(Fcb->CacheType != CACHE_READWRITE && FileObject->WriteAccess)
		{
#ifdef TEST
			DbgPrint("CreateSection Change object !\n");
#endif
			if(Fcb->SectionObjectPointers.DataSectionObject != NULL)
			{
				gDynamicFunctions.pFsRtlChangeBackingFileObject(NULL,FileObject,ChangeDataControlArea,0);
			}
			if(Fcb->SectionObjectPointers.ImageSectionObject != NULL)
			{
				gDynamicFunctions.pFsRtlChangeBackingFileObject(NULL,FileObject,ChangeImageControlArea,0);
			}
			if(Fcb->SectionObjectPointers.SharedCacheMap != NULL)
			{
				gDynamicFunctions.pFsRtlChangeBackingFileObject(NULL,FileObject,ChangeSharedCacheMap,0);
			}
			SetFlag(Fcb->FcbState,SCB_STATE_CHANGE_BACKING);
		}
	}
#ifdef CV
	VirtualizerEnd();
#endif

	FsRtlExitFileSystem();

	return FLT_PREOP_COMPLETE;

}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationReleaseForCcFlush(
								__inout PFLT_CALLBACK_DATA Data,
								__in PCFLT_RELATED_OBJECTS FltObjects,
								__deref_out_opt PVOID *CompletionContext
								)
{
	PFCB Fcb;
	PCCB Ccb;
	PFSRTL_COMMON_FCB_HEADER Header;

	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	FsRtlEnterFileSystem();

	if (IoGetTopLevelIrp() == (PIRP)FSRTL_CACHE_TOP_LEVEL_IRP) 
	{
		IoSetTopLevelIrp( NULL );
	}

	Header = (PFSRTL_COMMON_FCB_HEADER) FltObjects->FileObject->FsContext;

	if (Header->Resource) 
	{

		ExReleaseResourceLite( Header->Resource );
	}


	if (Header->PagingIoResource) 
	{

		ExReleaseResourceLite( Header->PagingIoResource );
	}

	Data->IoStatus.Status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;

	FsRtlExitFileSystem();
	return FLT_PREOP_COMPLETE;
}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationAcquireForCcFlush(
								__inout PFLT_CALLBACK_DATA Data,
								__in PCFLT_RELATED_OBJECTS FltObjects,
								__deref_out_opt PVOID *CompletionContext
								)
{
	PFCB Fcb;
	PCCB Ccb;
	PFSRTL_COMMON_FCB_HEADER Header;

	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	FsRtlEnterFileSystem();
#ifdef CV
	VirtualizerStart();
#endif
	ASSERT( IoGetTopLevelIrp() != (PIRP)FSRTL_CACHE_TOP_LEVEL_IRP );

	if (IoGetTopLevelIrp() == NULL) 
	{    
		IoSetTopLevelIrp((PIRP)FSRTL_CACHE_TOP_LEVEL_IRP);
	}

	Header = (PFSRTL_COMMON_FCB_HEADER) FltObjects->FileObject->FsContext;

	if (Header->Resource) 
	{

		if (!ExIsResourceAcquiredSharedLite( Header->Resource )) 
		{

			ExAcquireResourceExclusiveLite( Header->Resource, TRUE );

		} 
		else 
		{

			ExAcquireResourceSharedLite( Header->Resource, TRUE );
		}
	}

	if (Header->PagingIoResource)
	{    
		ExAcquireResourceSharedLite( Header->PagingIoResource, TRUE );
	}

	Data->IoStatus.Status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
#ifdef CV
	VirtualizerEnd();
#endif
	FsRtlExitFileSystem();

	return FLT_PREOP_COMPLETE;
}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationCheckIfPossible(
							  __inout PFLT_CALLBACK_DATA Data,
							  __in PCFLT_RELATED_OBJECTS FltObjects,
							  __deref_out_opt PVOID *CompletionContext
							  )
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_DISALLOW_FASTIO;
	PFLT_IO_PARAMETER_BLOCK  Iopb = Data->Iopb;
	ULONG Length = Iopb->Parameters.FastIoCheckIfPossible.Length;
	ULONG LockKey = Iopb->Parameters.FastIoCheckIfPossible.LockKey;
	BOOLEAN CheckForReadOperation = Iopb->Parameters.FastIoCheckIfPossible.CheckForReadOperation;
	LARGE_INTEGER  FileOffset =	Iopb->Parameters.FastIoCheckIfPossible.FileOffset;

	PFILE_OBJECT FileObject = FltObjects->FileObject;
	PFCB Fcb = FileObject->FsContext;

	LARGE_INTEGER LargeLength;


	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	LargeLength.QuadPart = Length;

	if (CheckForReadOperation) 
	{

		if (FsRtlFastCheckLockForRead( Fcb->FileLock,
			&FileOffset,
			&LargeLength,
			LockKey,
			FileObject,
			PsGetCurrentProcess() )) 
		{
			Data->IoStatus.Status = STATUS_SUCCESS;
			return FLT_PREOP_COMPLETE;
		}

	} 
	else 
	{

		if (FsRtlFastCheckLockForWrite( Fcb->FileLock,
			&FileOffset,
			&LargeLength,
			LockKey,
			FileObject,
			PsGetCurrentProcess() )) 
		{
			Data->IoStatus.Status = STATUS_SUCCESS;
			return FLT_PREOP_COMPLETE;
		}
	}

	return FLT_PREOP_DISALLOW_FASTIO;
}



FLT_PREOP_CALLBACK_STATUS
PtPreOperationFileSystemControl(
								__inout PFLT_CALLBACK_DATA Data,
								__in PCFLT_RELATED_OBJECTS FltObjects,
								__deref_out_opt PVOID *CompletionContext
						  )
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	PCCB Ccb;
	PFCB Fcb;
	NTSTATUS Status;
	BOOLEAN Wait = FALSE;
	BOOLEAN PagingIo = FALSE;

	BOOLEAN PagingIoAcquireResource = FALSE;
	BOOLEAN FcbAcquireResource = FALSE;
	BOOLEAN VolAcquireResource = FALSE;
	BOOLEAN MoveFile = FALSE;
	BOOLEAN DisableLocalBuffer = FALSE;
	BOOLEAN UsnData = FALSE;

	PVOLUME_CONTEXT volCtx = NULL;

	PFLT_CALLBACK_DATA  RetNewCallbackData = NULL;
	KEVENT StackEvent;

	CACHE_UNINITIALIZE_EVENT UninitializeCompleteEvent;
	NTSTATUS WaitStatus;
	BOOLEAN WaitCompleteEvent = FALSE;

	FsRtlEnterFileSystem();
	//
	if(!IsMyFakeFcb(FltObjects->FileObject)) 
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	ASSERT(FileObject != NULL);

	PagingIo      = BooleanFlagOn(Data->Iopb->IrpFlags , IRP_PAGING_IO);

	Wait = CanFsdWait( Data );

	Fcb = FileObject->FsContext;
	Ccb = FileObject->FsContext2;

	try{

		Status = FltGetVolumeContext( FltObjects->Filter,
			FltObjects->Volume,
			&volCtx );
		if(!NT_SUCCESS(Status))
		{
			Data->IoStatus.Status = Status;
			Data->IoStatus.Information = 0;
			try_return(FltStatus = FLT_PREOP_COMPLETE);
		}

		if(IRP_MN_USER_FS_REQUEST == Data->Iopb->MinorFunction )
		{

			ULONG FsControlCode = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;

			switch ( FsControlCode ) 
			{
			case FSCTL_REQUEST_OPLOCK_LEVEL_1:
			case FSCTL_REQUEST_OPLOCK_LEVEL_2:
			case FSCTL_REQUEST_BATCH_OPLOCK:
			case FSCTL_OPLOCK_BREAK_ACKNOWLEDGE:
			case FSCTL_OPBATCH_ACK_CLOSE_PENDING:
			case FSCTL_OPLOCK_BREAK_NOTIFY:
			case FSCTL_OPLOCK_BREAK_ACK_NO_2:
			case FSCTL_REQUEST_FILTER_OPLOCK:
			case FSCTL_REQUEST_OPLOCK:
				{
					ULONG OplockCount = 0;

					ULONG  OutputBufferLength = Data->Iopb->Parameters.FileSystemControl.Common.OutputBufferLength;
					ULONG  InputBufferLength = Data->Iopb->Parameters.FileSystemControl.Common.InputBufferLength;

					PREQUEST_OPLOCK_INPUT_BUFFER InputBuffer = NULL;

					if (FsControlCode == FSCTL_REQUEST_OPLOCK) 
					{

						InputBuffer = (PREQUEST_OPLOCK_INPUT_BUFFER)Data->Iopb->Parameters.FileSystemControl.Buffered.SystemBuffer;

						if ((InputBufferLength < sizeof( REQUEST_OPLOCK_INPUT_BUFFER )) ||
							(OutputBufferLength < sizeof( REQUEST_OPLOCK_OUTPUT_BUFFER ))) 
						{

							Data->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
							Data->IoStatus.Information = 0;
							try_return(FltStatus = FLT_PREOP_COMPLETE);
						}
					}
#ifdef CV
					VirtualizerStart();
#endif
					if ((FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
						(FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
						(FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
						(FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2) ||
						((FsControlCode == FSCTL_REQUEST_OPLOCK) &&
						FlagOn( InputBuffer->Flags, REQUEST_OPLOCK_INPUT_FLAG_REQUEST )))
					{
						ExAcquireResourceSharedLite( volCtx->VolResource, TRUE );
						VolAcquireResource = TRUE;
						ExAcquireResourceExclusiveLite( Fcb->Header.Resource, TRUE );
						FcbAcquireResource = TRUE;

						if (FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2) {

							OplockCount = (ULONG) FsRtlAreThereCurrentFileLocks( Fcb->FileLock );

						} else {

							OplockCount = Fcb->OpenHandleCount;
						}
					}
					else if((FsControlCode == FSCTL_OPLOCK_BREAK_ACKNOWLEDGE) ||
						(FsControlCode == FSCTL_OPBATCH_ACK_CLOSE_PENDING) ||
						(FsControlCode == FSCTL_OPLOCK_BREAK_NOTIFY) ||
						(FsControlCode == FSCTL_OPLOCK_BREAK_ACK_NO_2) ||
						((FsControlCode == FSCTL_REQUEST_OPLOCK) &&
						FlagOn( InputBuffer->Flags, REQUEST_OPLOCK_INPUT_FLAG_ACK )))
					{
						ExAcquireResourceSharedLite( Fcb->Header.Resource, TRUE );
						FcbAcquireResource = TRUE;
					}

					//检测oplock
					FltStatus = FltOplockFsctrl( &Fcb->Oplock,
						Data,
						OplockCount );

					ExAcquireFastMutex(Fcb->Header.FastMutex);

					if ( FltOplockIsFastIoPossible(&Fcb->Oplock) )
					{
						if ( Fcb->FileLock && 
							Fcb->FileLock->FastIoIsQuestionable )
						{
							Fcb->Header.IsFastIoPossible = FastIoIsQuestionable;
						}
						else
						{
							Fcb->Header.IsFastIoPossible = FastIoIsPossible;
						}
					}
					else
					{
						Fcb->Header.IsFastIoPossible = FastIoIsNotPossible;
					}

					ExReleaseFastMutex(Fcb->Header.FastMutex);
#ifdef CV
					VirtualizerEnd();
#endif
					try_return(Status);
				}
				break;
			case FSCTL_MOVE_FILE:
				{
					Wait = TRUE;

					KeInitializeEvent( &StackEvent, NotificationEvent, FALSE );

					ExAcquireResourceExclusiveLite( Fcb->Header.PagingIoResource, TRUE );
					PagingIoAcquireResource = TRUE;

					Fcb->MoveFileEvent = &StackEvent;
					MoveFile = TRUE;

					//ExReleaseResourceLite( Fcb->Header.PagingIoResource );

				}
				break;
			case IOCTL_LMR_DISABLE_LOCAL_BUFFERING:
				{
					DbgPrint("取消本地缓存 \n");
					//#ifdef OTHER_NETWORK
					DisableLocalBuffer = TRUE;

					ExAcquireResourceExclusiveLite( Fcb->Header.Resource, TRUE );
					FcbAcquireResource = TRUE;
					//#endif
				}
				break;
			case FSCTL_READ_FILE_USN_DATA:
				{
					/*Data->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
					Data->IoStatus.Information = 0;
					try_return(FltStatus = FLT_PREOP_COMPLETE);*/
					UsnData = TRUE;
				}
				break;

			}
		}
		//

		//if(!PagingIo)
		//{
		//	ExAcquireResourceExclusiveLite( Fcb->Header.Resource, TRUE );
		//	FcbAcquireResource = TRUE;
		//}
		//else
		//{
		//	ExAcquireResourceExclusiveLite( Fcb->Header.PagingIoResource, TRUE );
		//	PagingIoAcquireResource = TRUE;
		//}
#ifdef CV
		VirtualizerStart();
#endif
		if(Ccb->StreamFileInfo.StreamObject == NULL)
		{
			try_return(Data->IoStatus.Status = STATUS_FILE_DELETED);
		}

		Status = FltAllocateCallbackData(FltObjects->Instance,Ccb->StreamFileInfo.StreamObject,&RetNewCallbackData);

		if(NT_SUCCESS(Status))
		{

			RtlCopyMemory(RetNewCallbackData->Iopb,Data->Iopb,sizeof(FLT_IO_PARAMETER_BLOCK));

			RetNewCallbackData->Iopb->TargetFileObject = Ccb->StreamFileInfo.StreamObject;

			FltPerformSynchronousIo(RetNewCallbackData);

			Data->IoStatus = RetNewCallbackData->IoStatus;

		}
		else
		{
			Data->IoStatus.Status = Status;
		}

#ifdef CV
		VirtualizerEnd();
#endif
try_exit: NOTHING;
#ifdef CV
		VirtualizerStart();
#endif
		if(UsnData)
		{
			/*PUSN_RECORD pUsnRecode = Data->Iopb->Parameters.FileSystemControl.Neither.OutputBuffer;
			DbgPrint("Data->Iopb->Parameters.FileSystemControl = %x \n",pUsnRecode->Reason);
			DbgPrint("Data->Iopb->Parameters.FileSystemControl = %x \n",pUsnRecode->SourceInfo);*/
		}
		if(MoveFile)
		{
			KeSetEvent( &StackEvent, 0, FALSE );		

			Fcb->MoveFileEvent = NULL;

			KeClearEvent( &StackEvent );

		}
		if(NT_SUCCESS(Data->IoStatus.Status))
		{
			if(DisableLocalBuffer)
			{
				if (Fcb->SectionObjectPointers.DataSectionObject != NULL) //先刷新下
				{

					CcFlushCache( &Fcb->SectionObjectPointers, NULL, 0, NULL );  //内部调用MmFlushSection 这个函数内部会申请共享的pagingio资源

					ExAcquireResourceExclusiveLite( Fcb->Header.PagingIoResource, TRUE);
					ExReleaseResourceLite( Fcb->Header.PagingIoResource );

					CcPurgeCacheSection( &Fcb->SectionObjectPointers,
						NULL,
						0,
						BooleanFlagOn(Ccb->CcbState,CCB_FLAG_NETWORK_FILE));
				}

				if(FlagOn(Ccb->CcbState,CCB_FLAG_NETWORK_FILE))
				{


					KeInitializeEvent( &UninitializeCompleteEvent.Event,
						SynchronizationEvent,
						FALSE);

					CcUninitializeCacheMap( FileObject,
						NULL,
						&UninitializeCompleteEvent );

					WaitCompleteEvent = TRUE;

					if(Fcb->CacheObject == FileObject)
					{
						Fcb->CacheType = CACHE_DISABLE;
					}
				}

				//SetFlag(Fcb->FcbState,SCB_STATE_DISABLE_LOCAL_BUFFERING);					
			}
		}
#ifdef CV
		VirtualizerEnd();
#endif
	}
	finally
	{

		if(FcbAcquireResource)
		{
			ExReleaseResourceLite( Fcb->Header.Resource );	// 释放FCB主资源 ///
		}
		if(PagingIoAcquireResource)
		{
			ExReleaseResourceLite( Fcb->Header.PagingIoResource );	
		}

		if(RetNewCallbackData != NULL)
		{
			FltFreeCallbackData(RetNewCallbackData);
		}

		if(WaitCompleteEvent)
		{
			WaitStatus = KeWaitForSingleObject( &UninitializeCompleteEvent.Event,
				Executive,
				KernelMode,
				FALSE,
				NULL);


			MmForceSectionClosed(&Fcb->SectionObjectPointers,TRUE);

		}
		if(VolAcquireResource)
		{
			ExReleaseResourceLite(volCtx->VolResource);
		}
		if(volCtx != NULL)
		{
			FltReleaseContext(volCtx);
		}
		if(Data->IoStatus.Status == STATUS_PENDING)
		{
			FltStatus = FLT_PREOP_PENDING;
		}
		if(FltStatus != FLT_PREOP_PENDING)
		{
			FltStatus = FLT_PREOP_COMPLETE;
		}
	}

	FsRtlExitFileSystem();

	return FltStatus;
}

//#define SYSTEM_PID	4
//////如果system进程对加密文件发出的Oplock我们也要处理，暂时先这样
//FLT_PREOP_CALLBACK_STATUS
//SystemOplockControl(
//					__inout PFLT_CALLBACK_DATA Data,
//					__in PCFLT_RELATED_OBJECTS FltObjects,
//					__deref_out_opt PVOID *CompletionContext
//					)
//{
//	NTSTATUS Status;
//	PFLT_FILE_NAME_INFORMATION nameInfo;
//	UCHAR HashValue[MD5_LENGTH] = {0};
//	PFCB Fcb = NULL;
//	//如果远程的文件请求，system会打开文件，然后对文件操作这时候会发出oplock的请求，这个时候如果直接给底层，我们的文件系统就处理不了了，所以
//	//这里拦截一下如果是我们的文件的话直接给他返回
//	if(SYSTEM_PID == PsGetCurrentProcessId())
//	{
//
//		if(IRP_MN_USER_FS_REQUEST == Data->Iopb->MinorFunction )
//		{
//
//			ULONG FsControlCode = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;
//
//			switch ( FsControlCode ) 
//			{
//			case FSCTL_REQUEST_OPLOCK_LEVEL_1:
//			case FSCTL_REQUEST_OPLOCK_LEVEL_2:
//			case FSCTL_REQUEST_BATCH_OPLOCK:
//			case FSCTL_OPLOCK_BREAK_ACKNOWLEDGE:
//			case FSCTL_OPBATCH_ACK_CLOSE_PENDING:
//			case FSCTL_OPLOCK_BREAK_NOTIFY:
//			case FSCTL_OPLOCK_BREAK_ACK_NO_2:
//			case FSCTL_REQUEST_FILTER_OPLOCK:
//			case FSCTL_REQUEST_OPLOCK:
//				{
//					Status = FltGetFileNameInformation( Data,
//						FLT_FILE_NAME_NORMALIZED |
//						FLT_FILE_NAME_QUERY_DEFAULT,
//						&nameInfo );
//					if (!NT_SUCCESS( Status )) 
//					{
//						Status = FltGetFileNameInformation( Data,
//							FLT_FILE_NAME_OPENED |
//							FLT_FILE_NAME_QUERY_DEFAULT,
//							&nameInfo );
//					}
//					if(!NT_SUCCESS(Status))
//					{
//
//					}
//					//哈希文件名查找是不是在fcb中
//					if(!HashFilePath(&nameInfo->Name,HashValue)) //hash失败了直接完成
//					{	
//						DbgPrint("Hash路径出错\n");
//					}
//
//					FsRtlEnterFileSystem();
//					{
//						j = (HashValue[0]) % NUMHASH;
//						ExAcquireResourceSharedLite( &FcbTableResource, TRUE );
//						AcquireResource = TRUE;
//
//						if(IsListEmpty(&FcbTable[j].ListEntry)) //空的表
//						{	
//
//						}
//						else //不是空表对这个表进行查找
//						{
//
//							for(pListEntry = FcbTable[j].ListEntry.Flink; pListEntry !=  &FcbTable[j].ListEntry ; pListEntry = pListEntry->Flink) //查找数据 查找到了进行添加否则建立一个新的数据到链表中
//							{
//								PHASH_ENTRY hashEntry = CONTAINING_RECORD(pListEntry, HASH_ENTRY, ListEntry);
//
//								if(RtlCompareMemory(hashEntry->HashValue,HashValue,MD5_LENGTH) == MD5_LENGTH)
//								{
//									Fcb = hashEntry->Fcb;
//
//									break;
//								}
//							}
//						}
//					}
//					if(Fcb != NULL)
//						//找到了按照正常逻辑处理
//					{
//						ULONG OplockCount = 0;
//
//						ULONG  OutputBufferLength = Data->Iopb->Parameters.FileSystemControl.Common.OutputBufferLength;
//						ULONG  InputBufferLength = Data->Iopb->Parameters.FileSystemControl.Common.InputBufferLength;
//
//						PREQUEST_OPLOCK_INPUT_BUFFER InputBuffer = NULL;
//
//						if (FsControlCode == FSCTL_REQUEST_OPLOCK) 
//						{
//
//							InputBuffer = (PREQUEST_OPLOCK_INPUT_BUFFER)Data->Iopb->Parameters.FileSystemControl.Buffered.SystemBuffer;
//
//							if ((InputBufferLength < sizeof( REQUEST_OPLOCK_INPUT_BUFFER )) ||
//								(OutputBufferLength < sizeof( REQUEST_OPLOCK_OUTPUT_BUFFER ))) 
//							{
//
//								Data->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
//								Data->IoStatus.Information = 0;
//								try_return(FltStatus = FLT_PREOP_COMPLETE);
//							}
//						}
//#ifdef CV
//						VirtualizerStart();
//#endif
//						if ((FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
//							(FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
//							(FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
//							(FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2) ||
//							((FsControlCode == FSCTL_REQUEST_OPLOCK) &&
//							FlagOn( InputBuffer->Flags, REQUEST_OPLOCK_INPUT_FLAG_REQUEST )))
//						{
//							ExAcquireResourceSharedLite( volCtx->VolResource, TRUE );
//							VolAcquireResource = TRUE;
//							ExAcquireResourceExclusiveLite( Fcb->Header.Resource, TRUE );
//							FcbAcquireResource = TRUE;
//
//							if (FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2) {
//
//								OplockCount = (ULONG) FsRtlAreThereCurrentFileLocks( Fcb->FileLock );
//
//							} else {
//
//								OplockCount = Fcb->OpenHandleCount;
//							}
//						}
//						else if((FsControlCode == FSCTL_OPLOCK_BREAK_ACKNOWLEDGE) ||
//							(FsControlCode == FSCTL_OPBATCH_ACK_CLOSE_PENDING) ||
//							(FsControlCode == FSCTL_OPLOCK_BREAK_NOTIFY) ||
//							(FsControlCode == FSCTL_OPLOCK_BREAK_ACK_NO_2) ||
//							((FsControlCode == FSCTL_REQUEST_OPLOCK) &&
//							FlagOn( InputBuffer->Flags, REQUEST_OPLOCK_INPUT_FLAG_ACK )))
//						{
//							ExAcquireResourceSharedLite( Fcb->Header.Resource, TRUE );
//							FcbAcquireResource = TRUE;
//						}
//
//						//检测oplock
//						FltStatus = FltOplockFsctrl( &Fcb->Oplock,
//							Data,
//							OplockCount );
//
//						ExAcquireFastMutex(Fcb->Header.FastMutex);
//
//						if ( FltOplockIsFastIoPossible(&Fcb->Oplock) )
//						{
//							if ( Fcb->FileLock && 
//								Fcb->FileLock->FastIoIsQuestionable )
//							{
//								Fcb->Header.IsFastIoPossible = FastIoIsQuestionable;
//							}
//							else
//							{
//								Fcb->Header.IsFastIoPossible = FastIoIsPossible;
//							}
//						}
//						else
//						{
//							Fcb->Header.IsFastIoPossible = FastIoIsNotPossible;
//						}
//
//						ExReleaseFastMutex(Fcb->Header.FastMutex);
//#ifdef CV
//						VirtualizerEnd();
//#endif
//						try_return(Status);
//					}
//				}
//				break;
//			default:
//				{
//
//				}
//			}
//		}
//	}
//	if(VolAcquireResource)
//	{
//		ExReleaseResourceLite(volCtx->VolResource);
//	}
//	if(volCtx != NULL)
//	{
//		FltReleaseContext(volCtx);
//	}
//	if(FcbAcquireResource)
//	{
//		ExReleaseResourceLite( Fcb->Header.Resource );	// 释放FCB主资源 ///
//	}
//	if(PagingIoAcquireResource)
//	{
//		ExReleaseResourceLite( Fcb->Header.PagingIoResource );	
//	}
//}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationLockControl(
						  __inout PFLT_CALLBACK_DATA Data,
						  __in PCFLT_RELATED_OBJECTS FltObjects,
						  __deref_out_opt PVOID *CompletionContext
						  )
{

	FLT_PREOP_CALLBACK_STATUS	FltStatus;
	BOOLEAN TopLevel = FALSE;
	PIRP_CONTEXT IrpContext = NULL;

	FsRtlEnterFileSystem();

	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if(FLT_IS_IRP_OPERATION(Data)) //irp read
	{
		//
		//设置顶层组件

		TopLevel = X70FsdIsIrpTopLevel( Data );
		//创建irp上下文
		try
		{
			IrpContext = X70FsdCreateIrpContext( Data,FltObjects, CanFsdWait( Data ) );

			if(IrpContext == NULL)
			{
				X70FsdRaiseStatus(IrpContext,STATUS_INSUFFICIENT_RESOURCES);
			}

			FltStatus = X70FsdCommonLockControl(Data, FltObjects,IrpContext); //FLT_PREOP_COMPLETE;

		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			//出现异常直接返回
			DbgPrint("LockControl出现异常直接返回 \n");
			X70FsdProcessException(&IrpContext,&Data,GetExceptionCode());
			FltStatus = FLT_PREOP_COMPLETE;
		}

		// 恢复Top-Level IRP
		if (TopLevel) { IoSetTopLevelIrp( NULL ); }

	}
	else if(FLT_IS_FASTIO_OPERATION(Data)) //fastio Write
	{
		//FltStatus = X70FsdFastIoWrite(Data, FltObjects); 
		//DbgPrint("FastIoLockControl \n");
		FltStatus = FLT_PREOP_DISALLOW_FASTIO;

	}
	else
	{
		Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		Data->IoStatus.Information = 0;
		FltStatus = FLT_PREOP_COMPLETE;
		/*FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;*/
		DbgPrint("收到其他的LockControl类型请求 \n");
	}


	FsRtlExitFileSystem();
	return FltStatus;
}

NTSTATUS CompleteLock(
					  IN PVOID  Context,
					  IN PFLT_CALLBACK_DATA  CallbackData
					  )
{
	return CallbackData->IoStatus.Status;
}


//#define IRP_MN_LOCK                     0x01
//#define IRP_MN_UNLOCK_SINGLE            0x02
//#define IRP_MN_UNLOCK_ALL               0x03
//#define IRP_MN_UNLOCK_ALL_BY_KEY        0x04
//锁定控制
FLT_PREOP_CALLBACK_STATUS
X70FsdCommonLockControl(
						  __inout PFLT_CALLBACK_DATA Data,
						  __in    PCFLT_RELATED_OBJECTS FltObjects,
						  __in	  PIRP_CONTEXT IrpContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	PFLT_IO_PARAMETER_BLOCK  Iopb = Data->Iopb;
	PFILE_OBJECT FileObject;
	PFCB Fcb = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	BOOLEAN  FcbAcquired = FALSE;
	PLARGE_INTEGER  Length;
	BOOLEAN OplockPostIrp = FALSE;
	BOOLEAN PostIrp = FALSE;

	BOOLEAN Wait          = BooleanFlagOn( IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT );

	if(FltObjects == NULL)
	{
		FltObjects = &IrpContext->FltObjects;
	}

	if(FltObjects != NULL)
	{
		FileObject = FltObjects->FileObject;
	}
	else
	{
		FileObject = Iopb->TargetFileObject;
	}

	Fcb = FileObject->FsContext;

	//DbgPrint("收到LockControl %ws \n",FileObject->FileName.Buffer);
	//DbgPrint("锁定操作的MinorFunction = %x \n",Data->Iopb->MinorFunction);

	if (!X70FsdAcquireSharedFcb( IrpContext, Fcb )) 
	{

		Status = X70FsdPostRequest(Data, IrpContext );


		if(Status == STATUS_PENDING)
		{
			FltStatus = FLT_PREOP_PENDING;
		}
		else
		{
			FltStatus = FLT_PREOP_COMPLETE;
		}
		return FltStatus;
	}

	try {

		FLT_PREOP_CALLBACK_STATUS FltOplockStatus;

		FltOplockStatus = FltCheckOplock( &Fcb->Oplock,
			Data,
			IrpContext,
			X70FsdOplockComplete,
			NULL );

		if(FltOplockStatus == FLT_PREOP_COMPLETE)
		{
			try_return( Status = Data->IoStatus.Status);
		}

		if (FltOplockStatus == FLT_PREOP_PENDING) 
		{
			FltStatus = FLT_PREOP_PENDING;
			OplockPostIrp = TRUE;
			PostIrp = TRUE;
			try_return( NOTHING );
		}

		ExAcquireFastMutex(Fcb->Header.FastMutex);

		if ( FltOplockIsFastIoPossible(&Fcb->Oplock) )
		{
			if ( Fcb->FileLock && 
				Fcb->FileLock->FastIoIsQuestionable )
			{
				Fcb->Header.IsFastIoPossible = FastIoIsQuestionable;
			}
			else
			{
				Fcb->Header.IsFastIoPossible = FastIoIsPossible;
			}
		}
		else
		{
			Fcb->Header.IsFastIoPossible = FastIoIsNotPossible;
		}

		ExReleaseFastMutex(Fcb->Header.FastMutex);

		if(IS_FLT_FILE_LOCK())
		{
			if(Fcb->FileLock == NULL)
			{
				Fcb->FileLock = FltAllocateFileLock(NULL,NULL);
			}

			//锁定
			FltStatus = FltProcessFileLock(Fcb->FileLock,Data,NULL);
		}
		else
		{
			if(Fcb->FileLock == NULL)
			{
				Fcb->FileLock = FsRtlAllocateFileLock(NULL,NULL);
			}

			//锁定
			FltStatus = MyFltProcessFileLock(Fcb->FileLock,Data,NULL);
		}
try_exit: NOTHING;

	} finally {

		X70FsdReleaseFcb( IrpContext, Fcb );

		if(FltStatus != FLT_PREOP_PENDING)
		{
			FltStatus = FLT_PREOP_COMPLETE;
		}

		if (!OplockPostIrp && !AbnormalTermination())
		{
			X70FsdCompleteRequest( &IrpContext, NULL, 0 ,FALSE );
		}

	}

	return FltStatus;

}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//查询eafile
FLT_PREOP_CALLBACK_STATUS
X70FsdCommonQueryEa(
					  __inout PFLT_CALLBACK_DATA Data,
					  __in    PCFLT_RELATED_OBJECTS FltObjects,
					  __in	  PIRP_CONTEXT IrpContext,
					  __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	PFLT_IO_PARAMETER_BLOCK  Iopb = Data->Iopb;
	PFILE_OBJECT FileObject;
	PFCB Fcb = NULL;
	PCCB Ccb = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	BOOLEAN  AcquiredFcb = FALSE;
	PLARGE_INTEGER  Length;
	BOOLEAN OplockPostIrp = FALSE;
	BOOLEAN PostIrp = FALSE;

	BOOLEAN Wait = CanFsdWait( Data );

	PFLT_CALLBACK_DATA  RetNewCallbackData = NULL;
	PLAYERFSD_IO_CONTEXT X70FsdIoContext = NULL;

	if (!FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT)) 
	{

		Status = X70FsdPostRequest( Data,IrpContext );

		if(Status == STATUS_PENDING)
		{
			FltStatus = FLT_PREOP_PENDING;
		}
		else
		{
			FltStatus = FLT_PREOP_COMPLETE;
		}
		return FltStatus;
	}

	if(FltObjects == NULL)
	{
		FltObjects = &IrpContext->FltObjects;
	}

	if(FltObjects != NULL)
	{
		FileObject = FltObjects->FileObject;
	}
	else
	{
		FileObject = Iopb->TargetFileObject;
	}

	Fcb = FileObject->FsContext;
	Ccb = FileObject->FsContext2;

	try {

		X70FsdAcquireExclusiveFcb( IrpContext, Fcb );
		AcquiredFcb = TRUE;

		if(Ccb->StreamFileInfo.StreamObject == NULL)
		{
			try_return(Data->IoStatus.Status = STATUS_FILE_DELETED);
		}
		Status = FltAllocateCallbackData(FltObjects->Instance,Ccb->StreamFileInfo.StreamObject,&RetNewCallbackData);

		if(NT_SUCCESS(Status))
		{

			RtlCopyMemory(RetNewCallbackData->Iopb,Data->Iopb,sizeof(FLT_IO_PARAMETER_BLOCK));

			RetNewCallbackData->Iopb->TargetFileObject = Ccb->StreamFileInfo.StreamObject;

			if(Wait)
			{
				FltPerformSynchronousIo(RetNewCallbackData);

				Data->IoStatus = RetNewCallbackData->IoStatus;
			}
			else
			{
				X70FsdIoContext = (PLAYERFSD_IO_CONTEXT)ExAllocateFromNPagedLookasideList( &G_IoContextLookasideList );
				RtlZeroMemory(X70FsdIoContext,sizeof(LAYERFSD_IO_CONTEXT));

				if(AcquiredFcb)
				{
					X70FsdIoContext->Wait.Async.Resource = Fcb->Header.Resource;
					AcquiredFcb = FALSE;
				}

				X70FsdIoContext->Data = Data;
				Status = FltPerformAsynchronousIo(RetNewCallbackData ,PassThroughAsyncCompletionRoutine,X70FsdIoContext);
				RetNewCallbackData = NULL;
				FltStatus = FLT_PREOP_PENDING;
			}
		}
		else
		{
			Data->IoStatus.Status = Status;
		}
try_exit:NOTHING;
	} finally {

		//出现异常直接返回

		if(AcquiredFcb)
		{
			X70FsdReleaseFcb( IrpContext, Fcb );
		}

		if(RetNewCallbackData != NULL)
		{
			FltFreeCallbackData(RetNewCallbackData);
		}

		if (!AbnormalTermination())
		{
			X70FsdCompleteRequest( &IrpContext, NULL, 0 ,FALSE );
		}

	}

	return FltStatus;

}


FLT_PREOP_CALLBACK_STATUS
PtPreOperationQueryEa(
					  __inout PFLT_CALLBACK_DATA Data,
					  __in PCFLT_RELATED_OBJECTS FltObjects,
					  __deref_out_opt PVOID *CompletionContext
					  )
{

	FLT_PREOP_CALLBACK_STATUS	FltStatus;
	BOOLEAN TopLevel = FALSE;
	PIRP_CONTEXT IrpContext = NULL;

	FsRtlEnterFileSystem();

	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if(FLT_IS_IRP_OPERATION(Data)) //irp 
	{
		//
		//设置顶层组件

		TopLevel = X70FsdIsIrpTopLevel( Data );
		//创建irp上下文
		try
		{
			IrpContext = X70FsdCreateIrpContext( Data,FltObjects, CanFsdWait( Data ) );

			if(IrpContext == NULL)
			{
				X70FsdRaiseStatus(IrpContext,STATUS_INSUFFICIENT_RESOURCES);
			}


			FltStatus = X70FsdCommonQueryEa(Data, FltObjects,IrpContext,CompletionContext); //FLT_PREOP_COMPLETE;

		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			//出现异常直接返回
			DbgPrint("queryea出现异常直接返回 \n");
			X70FsdProcessException(&IrpContext,&Data,GetExceptionCode());
			FltStatus = FLT_PREOP_COMPLETE;
		}

		// 恢复Top-Level IRP
		if (TopLevel) { IoSetTopLevelIrp( NULL ); }

	}
	else if(FLT_IS_FASTIO_OPERATION(Data)) //fastio
	{
		//FltStatus = X70FsdFastIoWrite(Data, FltObjects); 
		DbgPrint("queryea \n");
		FltStatus = FLT_PREOP_DISALLOW_FASTIO;

	}
	else
	{
		Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		Data->IoStatus.Information = 0;
		FltStatus = FLT_PREOP_COMPLETE;
		/*FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;*/
		DbgPrint("收到其他的类型请求 \n");
	}


	FsRtlExitFileSystem();
	return FltStatus;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//设置eafile
FLT_PREOP_CALLBACK_STATUS
X70FsdCommonSetEa(
					__inout PFLT_CALLBACK_DATA Data,
					__in    PCFLT_RELATED_OBJECTS FltObjects,
					__in	  PIRP_CONTEXT IrpContext,
					__deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	PFLT_IO_PARAMETER_BLOCK  Iopb = Data->Iopb;
	PFILE_OBJECT FileObject;
	PFCB Fcb = NULL;
	PCCB Ccb = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	BOOLEAN  AcquiredFcb = FALSE;
	BOOLEAN AcquiredVcb = FALSE;
	PLARGE_INTEGER  Length;
	BOOLEAN OplockPostIrp = FALSE;
	BOOLEAN PostIrp = FALSE;
	PVOLUME_CONTEXT volCtx = NULL;

	BOOLEAN Wait = CanFsdWait( Data );

	PFLT_CALLBACK_DATA  RetNewCallbackData = NULL;
	PLAYERFSD_IO_CONTEXT X70FsdIoContext = NULL;

	if (!FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT)) 
	{

		Status = X70FsdPostRequest( Data,IrpContext );

		if(Status == STATUS_PENDING)
		{
			FltStatus = FLT_PREOP_PENDING;
		}
		else
		{
			FltStatus = FLT_PREOP_COMPLETE;
		}
		return FltStatus;
	}

	if(FltObjects == NULL)
	{
		FltObjects = &IrpContext->FltObjects;
	}

	if(FltObjects != NULL)
	{
		FileObject = FltObjects->FileObject;
	}
	else
	{
		FileObject = Iopb->TargetFileObject;
	}

	Fcb = FileObject->FsContext;
	Ccb = FileObject->FsContext2;

	FltObjects->FileObject->Flags |= FO_FILE_MODIFIED;

	try {

		Status = FltGetVolumeContext( FltObjects->Filter,
			FltObjects->Volume,
			&volCtx );

		if(!NT_SUCCESS(Status))
		{
			Data->IoStatus.Status = Status;
			Data->IoStatus.Information = 0;
			try_return(FltStatus = FLT_PREOP_COMPLETE);
		}

		ExAcquireResourceSharedLite( volCtx->VolResource, BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT));
		AcquiredVcb = TRUE;

		X70FsdAcquireExclusiveFcb( IrpContext, Fcb );
		AcquiredFcb = TRUE;

		if(Ccb->StreamFileInfo.StreamObject == NULL)
		{
			try_return(Data->IoStatus.Status = STATUS_FILE_DELETED);
		}
		Status = FltAllocateCallbackData(FltObjects->Instance,Ccb->StreamFileInfo.StreamObject,&RetNewCallbackData);

		if(NT_SUCCESS(Status))
		{

			RtlCopyMemory(RetNewCallbackData->Iopb,Data->Iopb,sizeof(FLT_IO_PARAMETER_BLOCK));

			RetNewCallbackData->Iopb->TargetFileObject = Ccb->StreamFileInfo.StreamObject;

			if(Wait)
			{
				FltPerformSynchronousIo(RetNewCallbackData);

				Data->IoStatus = RetNewCallbackData->IoStatus;
			}
			else
			{
				X70FsdIoContext = (PLAYERFSD_IO_CONTEXT)ExAllocateFromNPagedLookasideList( &G_IoContextLookasideList );
				RtlZeroMemory(X70FsdIoContext,sizeof(LAYERFSD_IO_CONTEXT));

				if(AcquiredFcb)
				{
					X70FsdIoContext->Wait.Async.Resource = Fcb->Header.Resource;
					AcquiredFcb = FALSE;
				}
				if(AcquiredVcb)
				{
					X70FsdIoContext->Wait.Async.Resource2 = volCtx->VolResource;
					AcquiredVcb = FALSE;
				}

				X70FsdIoContext->volCtx = volCtx;
				volCtx = NULL;

				X70FsdIoContext->Data = Data;
				Status = FltPerformAsynchronousIo(RetNewCallbackData ,PassThroughAsyncCompletionRoutine,X70FsdIoContext);

				RetNewCallbackData = NULL;
				FltStatus = FLT_PREOP_PENDING;
			}
		}
		else
		{
			Data->IoStatus.Status = Status;
		}

try_exit: NOTHING;

	} finally {

		//出现异常直接返回
		if(AcquiredVcb)
		{
			ExReleaseResourceLite(volCtx->VolResource);
		}
		if(volCtx != NULL)
		{
			FltReleaseContext(volCtx);
		}

		if(AcquiredFcb)
		{
			X70FsdReleaseFcb( IrpContext, Fcb );
		}

		if(RetNewCallbackData != NULL)
		{
			FltFreeCallbackData(RetNewCallbackData);
		}

		if (!AbnormalTermination())
		{
			X70FsdCompleteRequest( &IrpContext, NULL, 0 ,FALSE );
		}

	}

	return FltStatus;

}


FLT_PREOP_CALLBACK_STATUS
PtPreOperationSetEa(
					__inout PFLT_CALLBACK_DATA Data,
					__in PCFLT_RELATED_OBJECTS FltObjects,
					__deref_out_opt PVOID *CompletionContext
					)
{

	FLT_PREOP_CALLBACK_STATUS	FltStatus;
	BOOLEAN TopLevel = FALSE;
	PIRP_CONTEXT IrpContext = NULL;

	FsRtlEnterFileSystem();

	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if(FLT_IS_IRP_OPERATION(Data)) //irp 
	{
		//
		//设置顶层组件

		TopLevel = X70FsdIsIrpTopLevel( Data );
		//创建irp上下文
		try
		{
			IrpContext = X70FsdCreateIrpContext( Data,FltObjects, CanFsdWait( Data ) );

			if(IrpContext == NULL)
			{
				X70FsdRaiseStatus(IrpContext,STATUS_INSUFFICIENT_RESOURCES);
			}

			FltStatus = X70FsdCommonSetEa(Data, FltObjects,IrpContext,CompletionContext); //FLT_PREOP_COMPLETE;

		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			//出现异常直接返回
			DbgPrint("setea出现异常直接返回 \n");
			X70FsdProcessException(&IrpContext,&Data,GetExceptionCode());
			FltStatus = FLT_PREOP_COMPLETE;
		}

		// 恢复Top-Level IRP
		if (TopLevel) { IoSetTopLevelIrp( NULL ); }

	}
	else if(FLT_IS_FASTIO_OPERATION(Data)) //fastio
	{
		//FltStatus = X70FsdFastIoWrite(Data, FltObjects); 
		DbgPrint("setea \n");
		FltStatus = FLT_PREOP_DISALLOW_FASTIO;

	}
	else
	{
		Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		Data->IoStatus.Information = 0;
		FltStatus = FLT_PREOP_COMPLETE;
		/*FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;*/
		DbgPrint("收到其他的类型请求 \n");
	}


	FsRtlExitFileSystem();
	return FltStatus;
}



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//刷新
FLT_PREOP_CALLBACK_STATUS
X70FsdCommonFlushBuffers(
						   __inout PFLT_CALLBACK_DATA Data,
						   __in    PCFLT_RELATED_OBJECTS FltObjects,
						   __in	  PIRP_CONTEXT IrpContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	PFILE_OBJECT FileObject;
	PFCB Fcb = NULL;
	PCCB Ccb = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	BOOLEAN  FcbAcquired = FALSE;
	PLARGE_INTEGER  Length;

	if(FltObjects == NULL)
	{
		FltObjects = &IrpContext->FltObjects;
	}

	FileObject = FltObjects->FileObject;

	Fcb = FileObject->FsContext;
	Ccb = FileObject->FsContext2;
	//DbgPrint("收到FlushBuffers %ws \n",FileObject->FileName.Buffer);

	if ( !FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT) ) 
	{

		Status = X70FsdPostRequest(Data, IrpContext );

		if(Status == STATUS_PENDING)
		{
			FltStatus = FLT_PREOP_PENDING;
		}
		else
		{
			FltStatus = FLT_PREOP_COMPLETE;
		}
		return FltStatus;
	}

	try 
	{

		(VOID)X70FsdAcquireExclusiveFcb( IrpContext, Fcb );

		FcbAcquired = TRUE;	

		SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);

		CcFlushCache((PSECTION_OBJECT_POINTERS)&Fcb->SectionObjectPointers, NULL, 0, &Data->IoStatus);

		ExAcquireResourceExclusiveLite( Fcb->Header.PagingIoResource, TRUE); 
		ExReleaseResourceLite( Fcb->Header.PagingIoResource );

		if(NT_SUCCESS(Data->IoStatus.Status))
		{
			SetFlag(FileObject->Flags, FO_FILE_SIZE_CHANGED);
			SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_WRITE_THROUGH);
		}

		if(Ccb->StreamFileInfo.StreamObject != NULL)
		{
			FltFlushBuffers(FltObjects->Instance ,Ccb->StreamFileInfo.StreamObject);
		}

		//try_exit: NOTHING;
	} 
	finally 
	{

		if(FcbAcquired )
		{
			ExReleaseResourceLite(Fcb->Header.Resource);
		}

		IrpContext->FcbWithPagingExclusive = NULL;

		if (!AbnormalTermination())
		{
			X70FsdCompleteRequest( &IrpContext, &Data, Data->IoStatus.Status,FALSE );
		}

	}

	return FltStatus;

}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationFlushBuffers(
						   __inout PFLT_CALLBACK_DATA Data,
						   __in PCFLT_RELATED_OBJECTS FltObjects,
						   __deref_out_opt PVOID *CompletionContext
						   )
{

	FLT_PREOP_CALLBACK_STATUS	FltStatus;
	BOOLEAN TopLevel = FALSE;
	PIRP_CONTEXT IrpContext = NULL;

	FsRtlEnterFileSystem();

	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if(FLT_IS_IRP_OPERATION(Data)) //irp read
	{
		//
		//设置顶层组件

		TopLevel = X70FsdIsIrpTopLevel(Data);

		//创建irp上下文
		try
		{
			IrpContext = X70FsdCreateIrpContext( Data,FltObjects, CanFsdWait( Data ) );

			if(IrpContext == NULL)
			{
				X70FsdRaiseStatus(IrpContext,STATUS_INSUFFICIENT_RESOURCES);
			}

			FltStatus = X70FsdCommonFlushBuffers(Data, FltObjects,IrpContext); //FLT_PREOP_COMPLETE;

		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			//出现异常直接返回
			DbgPrint("FlushBuffers出现异常直接返回 \n");
			X70FsdProcessException(&IrpContext,&Data,GetExceptionCode());
			FltStatus = FLT_PREOP_COMPLETE;
		}

		// 恢复Top-Level IRP
		if (TopLevel) { IoSetTopLevelIrp( NULL ); }

	}
	else if(FLT_IS_FASTIO_OPERATION(Data)) //fastio Write
	{
		//FltStatus = X70FsdFastIoWrite(Data, FltObjects); 
		DbgPrint("FlushBuffers \n");
		FltStatus = FLT_PREOP_DISALLOW_FASTIO;

	}
	else
	{
		Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		Data->IoStatus.Information = 0;
		FltStatus = FLT_PREOP_COMPLETE;
		/*FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;*/
		DbgPrint("收到其他的FlushBuffers类型请求 \n");
	}


	FsRtlExitFileSystem();
	return FltStatus;
}

//设置安全描述
FLT_PREOP_CALLBACK_STATUS
X70FsdCommonSetSecurity(
						  __inout PFLT_CALLBACK_DATA Data,
						  __in    PCFLT_RELATED_OBJECTS FltObjects,
						  __in	  PIRP_CONTEXT IrpContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	PFILE_OBJECT FileObject;
	PFCB Fcb = NULL;
	PCCB Ccb = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	BOOLEAN  FcbAcquired = FALSE;
	KEVENT event;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;

	PDEVICE_OBJECT FltDeviceObject = NULL;
	PDEVICE_OBJECT DeviceObject = NULL;
	PIRP newIrp = NULL;
	PIO_STACK_LOCATION nextIrpSp = NULL;
	BOOLEAN AcquireVolResource = FALSE;
	PVOLUME_CONTEXT volCtx = NULL;

	FileObject = FltObjects->FileObject;

	Fcb = FileObject->FsContext;
	Ccb = FileObject->FsContext2;

	//DbgPrint("收到X70FsdCommonSetSecurity %ws \n",FileObject->FileName.Buffer);

	try 
	{
		Status = FltGetVolumeContext( FltObjects->Filter,
			FltObjects->Volume,
			&volCtx );

		if(!NT_SUCCESS(Status))
		{
			Data->IoStatus.Status = Status;
			Data->IoStatus.Information = 0;
			try_return(FltStatus = FLT_PREOP_COMPLETE);
		}

		//互斥取得资源
		ExAcquireResourceExclusiveLite(volCtx->VolResource, TRUE);
		AcquireVolResource = TRUE;

		ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
		FcbAcquired = TRUE;

		Status = FltGetDeviceObject(FltObjects->Volume,&FltDeviceObject);

		if(NT_SUCCESS(Status))
		{
			DeviceObject = IoGetDeviceAttachmentBaseRef(FltDeviceObject);

			//把上层的信息发给下层
			newIrp = IoAllocateIrp(DeviceObject->StackSize+1, FALSE);

			if(newIrp == NULL)
			{
				Status = STATUS_INSUFFICIENT_RESOURCES;
				try_return(Status);
			}

			newIrp->Flags = IRP_SYNCHRONOUS_API;			
			newIrp->RequestorMode = KernelMode;
			newIrp->UserIosb  = NULL;
			newIrp->UserEvent = NULL;
			newIrp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();

			KeInitializeEvent(&event, NotificationEvent, FALSE);

			nextIrpSp = IoGetNextIrpStackLocation(newIrp);

			nextIrpSp->MajorFunction = Iopb->MajorFunction;
			nextIrpSp->MinorFunction = Iopb->MinorFunction;
			nextIrpSp->FileObject    = Ccb->StreamFileInfo.StreamObject;

			nextIrpSp->Parameters.SetSecurity.SecurityDescriptor = Iopb->Parameters.SetSecurity.SecurityDescriptor;
			nextIrpSp->Parameters.SetSecurity.SecurityInformation = Iopb->Parameters.SetSecurity.SecurityInformation;

			IoSetCompletionRoutine(
				newIrp,
				X70FsdSyncMoreProcessingCompRoutine,
				&event,
				TRUE, TRUE, TRUE );
			//ExAcquireFastMutex(&Ccb->StreamFileInfo.FileObjectMutex);
			if( IoCallDriver(DeviceObject, newIrp) == STATUS_PENDING )
			{
				KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
			}
			//ExReleaseFastMutex(&Ccb->StreamFileInfo.FileObjectMutex);
			Status = newIrp->IoStatus.Status;
			Data->IoStatus.Status = newIrp->IoStatus.Status;
			Data->IoStatus.Information = newIrp->IoStatus.Information;

			IoFreeIrp(newIrp);
			if(!NT_SUCCESS(Status))
			{
				DbgPrint("setsecurity失败 %x\n",Status);
			}

		}
try_exit: NOTHING;
	} 
	finally 
	{

		if(FltDeviceObject != NULL)
		{
			ObDereferenceObject(FltDeviceObject);
		}
		if(DeviceObject != NULL)
		{
			ObDereferenceObject(DeviceObject);
		}
		if(FcbAcquired)
		{
			ExReleaseResourceLite(Fcb->Header.Resource);
		}
		if(AcquireVolResource)
		{
			ExReleaseResourceLite(volCtx->VolResource);
		}
		if (!AbnormalTermination())
		{
			X70FsdCompleteRequest( &IrpContext, &Data, Status,FALSE );
		}
		if(AbnormalTermination())
		{
			DbgPrint("setsecurity AbnormalTermination \n");
			X70FsdCompleteRequest(&IrpContext,&Data,STATUS_UNSUCCESSFUL,FALSE);
		}
	}

	return FltStatus;

}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationSetSecurity(
						  __inout PFLT_CALLBACK_DATA Data,
						  __in PCFLT_RELATED_OBJECTS FltObjects,
						  __deref_out_opt PVOID *CompletionContext
						  )
{

	FLT_PREOP_CALLBACK_STATUS	FltStatus;
	BOOLEAN TopLevel = FALSE;
	PIRP_CONTEXT IrpContext = NULL;

	FsRtlEnterFileSystem();

	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if(FLT_IS_IRP_OPERATION(Data)) //irp read
	{
		//
		//设置顶层组件

		TopLevel = X70FsdIsIrpTopLevel(Data);
		//创建irp上下文
		try
		{
			IrpContext = X70FsdCreateIrpContext( Data,FltObjects, CanFsdWait( Data ) );

			if(IrpContext == NULL)
			{
				X70FsdRaiseStatus(IrpContext,STATUS_INSUFFICIENT_RESOURCES);
			}

			FltStatus = X70FsdCommonSetSecurity(Data, FltObjects,IrpContext); //FLT_PREOP_COMPLETE;

		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			//出现异常直接返回
			DbgPrint("SetSecurity出现异常直接返回 \n");
			X70FsdProcessException(&IrpContext,&Data,GetExceptionCode());
			FltStatus = FLT_PREOP_COMPLETE;
		}

		// 恢复Top-Level IRP
		if (TopLevel) { IoSetTopLevelIrp( NULL ); }

	}
	else if(FLT_IS_FASTIO_OPERATION(Data)) //fastio Write
	{
		//FltStatus = X70FsdFastIoWrite(Data, FltObjects); 
		DbgPrint("SetSecurity \n");
		FltStatus = FLT_PREOP_DISALLOW_FASTIO;

	}
	else
	{
		Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		Data->IoStatus.Information = 0;
		FltStatus = FLT_PREOP_COMPLETE;
		/*FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;*/
		DbgPrint("收到其他的SetSecurity类型请求 \n");
	}


	FsRtlExitFileSystem();
	return FltStatus;
}
//设置安全描述
FLT_PREOP_CALLBACK_STATUS
X70FsdCommonQuerySecurity(
							__inout PFLT_CALLBACK_DATA Data,
							__in    PCFLT_RELATED_OBJECTS FltObjects,
							__in	  PIRP_CONTEXT IrpContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	PFILE_OBJECT FileObject;
	PFCB Fcb = NULL;
	PCCB Ccb = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	BOOLEAN  FcbAcquired = FALSE;
	KEVENT event;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;

	PDEVICE_OBJECT FltDeviceObject = NULL;
	PDEVICE_OBJECT DeviceObject = NULL;
	PIRP newIrp = NULL;
	PIO_STACK_LOCATION nextIrpSp = NULL;
	BOOLEAN AcquireVolResource = FALSE;
	PVOLUME_CONTEXT volCtx = NULL;

	FileObject = FltObjects->FileObject;

	Fcb = FileObject->FsContext;
	Ccb = FileObject->FsContext2;

	//DbgPrint("收到X70FsdCommonQuerySecurity %ws \n",FileObject->FileName.Buffer);

	try 
	{

		Status = FltGetVolumeContext( FltObjects->Filter,
			FltObjects->Volume,
			&volCtx );

		if(!NT_SUCCESS(Status))
		{
			Data->IoStatus.Status = Status;
			Data->IoStatus.Information = 0;
			try_return(FltStatus = FLT_PREOP_COMPLETE);
		}

		//互斥取得资源
		ExAcquireResourceExclusiveLite(volCtx->VolResource, TRUE);
		AcquireVolResource = TRUE;

		ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
		FcbAcquired = TRUE;

		Status = FltGetDeviceObject(FltObjects->Volume,&FltDeviceObject);

		if(NT_SUCCESS(Status))
		{
			DeviceObject = IoGetDeviceAttachmentBaseRef(FltDeviceObject);

			//把上层的信息发给下层
			newIrp = IoAllocateIrp(DeviceObject->StackSize+1, FALSE);

			if(newIrp == NULL)
			{
				Status = STATUS_INSUFFICIENT_RESOURCES;
				try_return(Status);
			}

			newIrp->Flags = IRP_SYNCHRONOUS_API;			
			newIrp->RequestorMode = KernelMode;
			newIrp->UserIosb  = NULL;
			newIrp->UserEvent = NULL;
			newIrp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();

			KeInitializeEvent(&event, NotificationEvent, FALSE);

			nextIrpSp = IoGetNextIrpStackLocation(newIrp);

			nextIrpSp->MajorFunction = Iopb->MajorFunction;
			nextIrpSp->MinorFunction = Iopb->MinorFunction;
			nextIrpSp->FileObject    = Ccb->StreamFileInfo.StreamObject;

			nextIrpSp->Parameters.QuerySecurity.Length  = Iopb->Parameters.QuerySecurity.Length ;
			nextIrpSp->Parameters.QuerySecurity.SecurityInformation = Iopb->Parameters.QuerySecurity.SecurityInformation;
			newIrp->UserBuffer = Iopb->Parameters.QuerySecurity.SecurityBuffer;
			newIrp->MdlAddress = Iopb->Parameters.QuerySecurity.MdlAddress;

			IoSetCompletionRoutine(
				newIrp,
				X70FsdSyncMoreProcessingCompRoutine,
				&event,
				TRUE, TRUE, TRUE );

			//ExAcquireFastMutex(&Ccb->StreamFileInfo.FileObjectMutex);

			if( IoCallDriver(DeviceObject, newIrp) == STATUS_PENDING )
			{
				KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
			}
			//ExReleaseFastMutex(&Ccb->StreamFileInfo.FileObjectMutex);
			Status = newIrp->IoStatus.Status;
			Data->IoStatus.Status = newIrp->IoStatus.Status;
			Data->IoStatus.Information = newIrp->IoStatus.Information;

			IoFreeIrp(newIrp);
			if(!NT_SUCCESS(Status))
			{
				DbgPrint("querysecurity失败 %x \n",Status);
			}

		}
try_exit: NOTHING;
	} 
	finally 
	{

		if(FltDeviceObject != NULL)
		{
			ObDereferenceObject(FltDeviceObject);
		}
		if(DeviceObject != NULL)
		{
			ObDereferenceObject(DeviceObject);
		}
		if(FcbAcquired)
		{
			ExReleaseResourceLite(Fcb->Header.Resource);
		}

		if(AcquireVolResource)
		{
			ExReleaseResourceLite(volCtx->VolResource);
		}

		if (!AbnormalTermination())
		{
			X70FsdCompleteRequest( &IrpContext, &Data, Status,FALSE );
		}
		if(AbnormalTermination())
		{
			DbgPrint("querysecurity AbnormalTermination \n");
			X70FsdCompleteRequest(&IrpContext,&Data,STATUS_UNSUCCESSFUL,FALSE);
		}
	}

	return FltStatus;

}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationQuerySecurity(
							__inout PFLT_CALLBACK_DATA Data,
							__in PCFLT_RELATED_OBJECTS FltObjects,
							__deref_out_opt PVOID *CompletionContext
							)
{

	FLT_PREOP_CALLBACK_STATUS	FltStatus;
	BOOLEAN TopLevel = FALSE;
	PIRP_CONTEXT IrpContext = NULL;

	FsRtlEnterFileSystem();

	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if(FLT_IS_IRP_OPERATION(Data)) //irp read
	{
		//
		//设置顶层组件

		TopLevel = X70FsdIsIrpTopLevel( Data );
		//创建irp上下文
		try
		{
			IrpContext = X70FsdCreateIrpContext( Data,FltObjects, CanFsdWait( Data ) );

			if(IrpContext == NULL)
			{
				X70FsdRaiseStatus(IrpContext,STATUS_INSUFFICIENT_RESOURCES);
			}

			FltStatus = X70FsdCommonQuerySecurity(Data, FltObjects,IrpContext); //FLT_PREOP_COMPLETE;

		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			//出现异常直接返回
			DbgPrint("QuerySecurity出现异常直接返回 \n");
			X70FsdProcessException(&IrpContext,&Data,GetExceptionCode());
			FltStatus = FLT_PREOP_COMPLETE;
		}

		// 恢复Top-Level IRP
		if (TopLevel) { IoSetTopLevelIrp( NULL ); }

	}
	else if(FLT_IS_FASTIO_OPERATION(Data)) //fastio Write
	{
		//FltStatus = X70FsdFastIoWrite(Data, FltObjects); 
		DbgPrint("QuerySecurity \n");
		FltStatus = FLT_PREOP_DISALLOW_FASTIO;

	}
	else
	{
		Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		Data->IoStatus.Information = 0;
		FltStatus = FLT_PREOP_COMPLETE;
		/*FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;*/
		DbgPrint("收到其他的QuerySecurity类型请求 \n");
	}


	FsRtlExitFileSystem();
	return FltStatus;
}

VOID PassThroughAsyncCompletionRoutine(
									   IN PFLT_CALLBACK_DATA CallbackData,
									   IN PFLT_CONTEXT Context
									   )
{
	PLAYERFSD_IO_CONTEXT X70FsdIoContext  = (PLAYERFSD_IO_CONTEXT)Context;

	if(X70FsdIoContext != NULL)
	{
		PFLT_CALLBACK_DATA Data = X70FsdIoContext->Data;

		PERESOURCE Resource  = X70FsdIoContext->Wait.Async.Resource;

		PERESOURCE Resource2  = X70FsdIoContext->Wait.Async.Resource2;

		PVOLUME_CONTEXT volCtx = X70FsdIoContext->volCtx;

		ERESOURCE_THREAD ResourceThreadId = X70FsdIoContext->Wait.Async.ResourceThreadId;

		Data->IoStatus = CallbackData->IoStatus;

		if ( Resource != NULL )
		{
			ExReleaseResourceForThreadLite(
				Resource,
				ResourceThreadId
				);
		}

		if ( Resource2 != NULL )
		{
			ExReleaseResourceForThreadLite(
				Resource2,
				ResourceThreadId
				);
		}

		if(volCtx != NULL)
		{
			FltReleaseContext(volCtx);
		}

		if(X70FsdIoContext != NULL)
		{
			ExFreeToNPagedLookasideList(
				&G_IoContextLookasideList,
				X70FsdIoContext
				);
		}

		FltCompletePendedPreOperation(Data,FLT_PREOP_COMPLETE,NULL); //可以在dpc级别调用

	}
	FltFreeCallbackData(CallbackData);

}

VOID X70PostFsdPassThroughIrp(PVOID CompletionContext)
{
	PLAYERFSD_IO_CONTEXT X70FsdIoContext =(PLAYERFSD_IO_CONTEXT) CompletionContext;

	PFLT_CALLBACK_DATA Data = X70FsdIoContext->Data;

	PERESOURCE Resource  = X70FsdIoContext->Wait.Async.Resource;

	PERESOURCE Resource2  = X70FsdIoContext->Wait.Async.Resource2;

	PVOLUME_CONTEXT volCtx = X70FsdIoContext->volCtx;

	ERESOURCE_THREAD ResourceThreadId = X70FsdIoContext->Wait.Async.ResourceThreadId;

	if ( Resource != NULL )
	{
		ExReleaseResourceForThreadLite(
			Resource,
			ResourceThreadId
			);
	}

	if ( Resource2 != NULL )
	{
		ExReleaseResourceForThreadLite(
			Resource2,
			ResourceThreadId
			);
	}

	if(volCtx != NULL)
	{
		FltReleaseContext(volCtx);
	}

	ExFreeToNPagedLookasideList(
		&G_IoContextLookasideList,
		X70FsdIoContext
		);
	return;
}

//下发一些不需要自己处理的irp
FLT_PREOP_CALLBACK_STATUS
X70FsdPrePassThroughIrp(
						  __inout PFLT_CALLBACK_DATA Data,
						  __in    PCFLT_RELATED_OBJECTS FltObjects,
						  __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	PCCB Ccb;
	PFCB Fcb;
	NTSTATUS Status;
	BOOLEAN Wait = FALSE;
	BOOLEAN PagingIo = FALSE;

	BOOLEAN PagingIoAcquireResource = FALSE;
	BOOLEAN FcbAcquireResource = FALSE;
	BOOLEAN VolAcquireResource = FALSE;

	PLAYERFSD_IO_CONTEXT X70FsdIoContext = NULL;
	PVOLUME_CONTEXT volCtx = NULL;

	PFLT_CALLBACK_DATA  RetNewCallbackData = NULL;

	ASSERT(FileObject != NULL);

	PagingIo      = BooleanFlagOn(Data->Iopb->IrpFlags , IRP_PAGING_IO);

	Wait = CanFsdWait( Data );

	Fcb = FileObject->FsContext;
	Ccb = FileObject->FsContext2;

	FsRtlEnterFileSystem();

	try{

		if(Ccb == NULL || Ccb->StreamFileInfo.StreamObject == NULL)
		{
			Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
			try_return(FltStatus = FLT_PREOP_COMPLETE);
		}

		Status = FltGetVolumeContext( FltObjects->Filter,
			FltObjects->Volume,
			&volCtx );

		if(!NT_SUCCESS(Status))
		{
			Data->IoStatus.Status = Status;
			Data->IoStatus.Information = 0;
			try_return(FltStatus = FLT_PREOP_COMPLETE);
		}

		////互斥取得资源
		//ExAcquireResourceExclusiveLite(volCtx->VolResource, TRUE);
		//VolAcquireResource = TRUE;

		if(!PagingIo)
		{
			ExAcquireResourceExclusiveLite( Fcb->Header.Resource, TRUE );
			FcbAcquireResource = TRUE;
		}
		else
		{
			ExAcquireResourceExclusiveLite( Fcb->Header.PagingIoResource, TRUE );
			PagingIoAcquireResource = TRUE;
		}

		if(Ccb->StreamFileInfo.StreamObject == NULL)
		{
			try_return(Data->IoStatus.Status = STATUS_FILE_DELETED);
		}
		Status = FltAllocateCallbackData(FltObjects->Instance,Ccb->StreamFileInfo.StreamObject,&RetNewCallbackData);

		if(NT_SUCCESS(Status))
		{

			RtlCopyMemory(RetNewCallbackData->Iopb,Data->Iopb,sizeof(FLT_IO_PARAMETER_BLOCK));

			RetNewCallbackData->Iopb->TargetFileObject = Ccb->StreamFileInfo.StreamObject;

			if(Wait)
			{
				FltPerformSynchronousIo(RetNewCallbackData);

				Data->IoStatus = RetNewCallbackData->IoStatus;
			}
			else
			{
				X70FsdIoContext = (PLAYERFSD_IO_CONTEXT)ExAllocateFromNPagedLookasideList( &G_IoContextLookasideList );
				RtlZeroMemory(X70FsdIoContext,sizeof(LAYERFSD_IO_CONTEXT));

				if(FcbAcquireResource)
				{
					X70FsdIoContext->Wait.Async.Resource = Fcb->Header.Resource;
					FcbAcquireResource = FALSE;
				}
				if(PagingIoAcquireResource)
				{
					X70FsdIoContext->Wait.Async.Resource2 = Fcb->Header.PagingIoResource;
					PagingIoAcquireResource = FALSE;
				}

				X70FsdIoContext->volCtx = volCtx;
				volCtx = NULL;

				X70FsdIoContext->Data = Data;

				Status = FltPerformAsynchronousIo(RetNewCallbackData ,PassThroughAsyncCompletionRoutine,X70FsdIoContext);
				RetNewCallbackData = NULL;
				FltStatus = FLT_PREOP_PENDING;
			}
		}
		else
		{
			Data->IoStatus.Status = Status;
		}


try_exit: NOTHING;

	}
	finally
	{

		if(FcbAcquireResource)
		{
			ExReleaseResourceLite( Fcb->Header.Resource );	// 释放FCB主资源 ///
		}
		if(PagingIoAcquireResource)
		{
			ExReleaseResourceLite( Fcb->Header.PagingIoResource );	
		}
		if(VolAcquireResource)
		{
			ExReleaseResourceLite(volCtx->VolResource);
		}
		if(volCtx != NULL)
		{
			FltReleaseContext(volCtx);
		}

		if(RetNewCallbackData != NULL)
		{
			FltFreeCallbackData(RetNewCallbackData);
		}

		if(AbnormalTermination())
		{
			Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
			Data->IoStatus.Information = 0;
			FltStatus = FLT_PREOP_COMPLETE;
		}
	}

	FsRtlExitFileSystem();
	return FltStatus;
}