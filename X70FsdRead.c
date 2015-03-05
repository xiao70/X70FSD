#include"X70FsdRead.h"
#include"X70FsdData.h"

extern CACHE_MANAGER_CALLBACKS  G_CacheMgrCallbacks;
extern NPAGED_LOOKASIDE_LIST  G_IoContextLookasideList;

extern USHORT gOsServicePackMajor;
extern ULONG gOsMajorVersion;
extern ULONG gOsMinorVersion;

extern FAST_MUTEX EncryptMutex;

#define SafeZeroMemory(AT,BYTE_COUNT) {                            \
	try {                                                          \
	RtlZeroMemory((AT), (BYTE_COUNT));                         \
} except(EXCEPTION_EXECUTE_HANDLER) {                          \
	X70FsdRaiseStatus( IrpContext, STATUS_INVALID_USER_BUFFER ); \
}                                                              \
}

#if defined(_M_IX86)
#define OVERFLOW_READ_THRESHHOLD         (0xE00)
#else
#define OVERFLOW_READ_THRESHHOLD         (0x1000)
#endif // defined(_M_IX86)

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationRead  (
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


VOID
X70FsdStackOverflowRead (
						   IN PVOID Context,
						   IN PKEVENT Event
						   )
{

	PIRP_CONTEXT IrpContext = Context;

	SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT );
	SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_IN_FSP ); 
	try 
	{
		(VOID) X70FsdCommonRead( IrpContext->OriginatingData,NULL,IrpContext );
	}
	except(EXCEPTION_EXECUTE_HANDLER) 
	{

		NTSTATUS ExceptionCode;

		ExceptionCode = GetExceptionCode();

		if (ExceptionCode == STATUS_FILE_DELETED) {

			IrpContext->ExceptionStatus = ExceptionCode = STATUS_END_OF_FILE;
			IrpContext->OriginatingData->IoStatus.Information = 0;
		}

		X70FsdProcessException( &IrpContext, &IrpContext->OriginatingData, ExceptionCode );
	}

	KeSetEvent( Event, 0, FALSE );
}

NTSTATUS
X70FsdPostStackOverflowRead (
							   __inout PFLT_CALLBACK_DATA Data,
							   __in PCFLT_RELATED_OBJECTS FltObjects,
							   __in PIRP_CONTEXT IrpContext
							   )
{
	KEVENT Event;
	PERESOURCE Resource;
	PFCB Fcb ;
	KeInitializeEvent( &Event, NotificationEvent, FALSE );

	Fcb = Data->Iopb->TargetFileObject->FsContext;

	if (FlagOn(Data->Iopb->IrpFlags , IRP_PAGING_IO) && (Fcb->Header.PagingIoResource != NULL)) 
	{

		Resource = Fcb->Header.PagingIoResource;

	} 
	else 
	{
		Resource = Fcb->Header.Resource;
	}

	if (Resource) 
	{
		ExAcquireResourceSharedLite( Resource, TRUE );
	}

	try {

		X70FsdPrePostIrp( Data,IrpContext );

		FsRtlPostStackOverflow( IrpContext, &Event, X70FsdStackOverflowRead );

		KeWaitForSingleObject( &Event, Executive, KernelMode, FALSE, NULL );

	} finally {

		if (Resource) {

			ExReleaseResourceLite( Resource );
		}
	}

	return FLT_PREOP_PENDING;
}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationRead (
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

	if(FLT_IS_IRP_OPERATION(Data)) 
	{

		try
		{
			TopLevel = X70FsdIsIrpTopLevel(Data);

			IrpContext = X70FsdCreateIrpContext( Data,FltObjects, CanFsdWait( Data ) );

			if(IrpContext == NULL)
			{
				X70FsdRaiseStatus(IrpContext,STATUS_INSUFFICIENT_RESOURCES);
			}

			if (FlagOn( Data->Iopb->MinorFunction, IRP_MN_COMPLETE ))  
			{
				FltStatus = X70FsdCompleteMdl(Data, FltObjects,IrpContext);
			}
			else if (IoGetRemainingStackSize() < OVERFLOW_READ_THRESHHOLD) 
			{
				FltStatus = X70FsdPostStackOverflowRead( Data, FltObjects,IrpContext );
			}
			else
			{
				FltStatus = X70FsdCommonRead(Data, FltObjects,IrpContext);
			}

		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{

			X70FsdProcessException(&IrpContext,&Data,GetExceptionCode());

			FltStatus = FLT_PREOP_COMPLETE;
		}


		if (TopLevel) 
		{ 
			IoSetTopLevelIrp( NULL ); 
		}

	}
	else if(FLT_IS_FASTIO_OPERATION(Data)) 
	{
		FltStatus = X70FsdFastIoRead(Data, FltObjects); 
		
	}
	else
	{
		Data->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Data->IoStatus.Information = 0;
		FltStatus = FLT_PREOP_COMPLETE;
	}

	FsRtlExitFileSystem();
	return FltStatus;
}


FLT_PREOP_CALLBACK_STATUS
X70FsdFastIoRead(__inout PFLT_CALLBACK_DATA Data,
				   __in PCFLT_RELATED_OBJECTS FltObjects)
{

	PCCB Ccb;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_DISALLOW_FASTIO;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	PFLT_IO_PARAMETER_BLOCK	Iopb = Data->Iopb;
	PDEVICE_OBJECT targetVdo = IoGetRelatedDeviceObject( FileObject );
	PFAST_IO_DISPATCH FastIoDispatch = targetVdo->DriverObject->FastIoDispatch;

	PLARGE_INTEGER FileOffset = &Iopb->Parameters.Read.ByteOffset;
	ULONG LockKey = Iopb->Parameters.Read.Key;
	ULONG Length = Iopb->Parameters.Read.Length;

	BOOLEAN Status = TRUE;

	BOOLEAN Wait = FltIsOperationSynchronous(Data);
	PIO_STATUS_BLOCK IoStatus = &Data->IoStatus;

	PVOID Buffer = X70FsdMapUserBuffer(Data);

	PAGED_CODE();

	Ccb = FileObject->FsContext2;

	if(FlagOn(Ccb->CcbState,CCB_FLAG_NETWORK_FILE))
	{
		return FLT_PREOP_DISALLOW_FASTIO;
	}

	Status = FsRtlCopyRead(FileObject,FileOffset,Length,Wait,LockKey,Buffer, IoStatus,targetVdo);

	if(Status)
	{
		FltStatus = FLT_PREOP_COMPLETE;
	}
	return FltStatus;
}


FLT_PREOP_CALLBACK_STATUS
X70FsdCommonRead(
				   __inout PFLT_CALLBACK_DATA Data,
				   __in PCFLT_RELATED_OBJECTS FltObjects,
				   __in PIRP_CONTEXT IrpContext)
{
	NTSTATUS Status = STATUS_SUCCESS;
	FLT_PREOP_CALLBACK_STATUS	FltStatus = FLT_PREOP_COMPLETE;
	PFLT_IO_PARAMETER_BLOCK  Iopb = Data->Iopb;

	LARGE_INTEGER StartingByte;
	LARGE_INTEGER ByteRange;
	LARGE_INTEGER ValidDataLength;

	ULONG ByteCount;
	ULONG RequestedByteCount;
	LARGE_INTEGER FileSize;
	PFILE_OBJECT FileObject;
	PFCB Fcb = NULL;
	PCCB Ccb = NULL;

	BOOLEAN Wait = FALSE;
	BOOLEAN PagingIo = FALSE;
	BOOLEAN NonCachedIo = FALSE;
	BOOLEAN	SynchronousIo = FALSE;
	BOOLEAN DoingIoAtEof = FALSE;

	BOOLEAN PagingIoAcquired = FALSE;
	BOOLEAN ScbAcquired = FALSE;
	BOOLEAN PostIrp = FALSE;
	BOOLEAN OplockPostIrp = FALSE;
	BOOLEAN FOResourceAcquired = FALSE;
	BOOLEAN NonCachedIoPending = FALSE;
	BOOLEAN EncryptResourceAcquired = FALSE;
	BOOLEAN InFsp = FALSE;

	PVOLUME_CONTEXT volCtx = NULL;
	PVOID SystemBuffer = NULL;
	ULONG_PTR i;

	LAYERFSD_IO_CONTEXT StackX70FsdIoContext;
	
	PFILE_OBJECT StreamObject;
	PVOID Bcb;
	PVOID PinBuffer;

	StartingByte = Iopb->Parameters.Read.ByteOffset;
	ByteCount = Iopb->Parameters.Read.Length;
	ByteRange.QuadPart = StartingByte.QuadPart  + (LONGLONG) ByteCount;
	RequestedByteCount = ByteCount;

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


	ASSERT(FileObject != NULL);

	Fcb = FileObject->FsContext;
	Ccb = FileObject->FsContext2;


	Wait          = BooleanFlagOn( IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT );
	PagingIo      = BooleanFlagOn(Iopb->IrpFlags , IRP_PAGING_IO);
	NonCachedIo   = BooleanFlagOn(Iopb->IrpFlags ,IRP_NOCACHE);
	SynchronousIo = BooleanFlagOn(FileObject->Flags, FO_SYNCHRONOUS_IO);

	if(FlagOn(Ccb->CcbState,CCB_FLAG_NETWORK_FILE))
	{
		SetFlag(IrpContext->Flags,IRP_CONTEXT_NETWORK_FILE);
	}

	if (ByteCount == 0) 
	{ 
		Data->IoStatus.Status = STATUS_SUCCESS;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}

	Status = FltGetVolumeContext( FltObjects->Filter,
		FltObjects->Volume,
		&volCtx );
	if(!NT_SUCCESS(Status))
	{
		Data->IoStatus.Status = Status;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}

	if(NonCachedIo) 
	{
		if (IrpContext->X70FsdIoContext == NULL)  
		{

			if (!Wait) 
			{
				IrpContext->X70FsdIoContext = (PLAYERFSD_IO_CONTEXT)ExAllocateFromNPagedLookasideList( &G_IoContextLookasideList );

				ClearFlag( IrpContext->Flags, IRP_CONTEXT_STACK_IO_CONTEXT );

			} 
			else 
			{

				IrpContext->X70FsdIoContext = &StackX70FsdIoContext;

				SetFlag( IrpContext->Flags, IRP_CONTEXT_STACK_IO_CONTEXT );
			}
		}

		RtlZeroMemory( IrpContext->X70FsdIoContext, sizeof(LAYERFSD_IO_CONTEXT) );

		if (Wait) 
		{

			KeInitializeEvent( &IrpContext->X70FsdIoContext->Wait.SyncEvent,
				NotificationEvent,
				FALSE );

			IrpContext->X70FsdIoContext->PagingIo = PagingIo;

		}
		else 
		{
			IrpContext->X70FsdIoContext->PagingIo = PagingIo;

			IrpContext->X70FsdIoContext->Wait.Async.ResourceThreadId =
				ExGetCurrentResourceThread();

			IrpContext->X70FsdIoContext->Wait.Async.RequestedByteCount =
				ByteCount;

			IrpContext->X70FsdIoContext->Wait.Async.FileObject = FileObject;
		}
	}


	try{

		//文件有一个缓存，并且是非缓存的I0,并且不是分页io 这个时候刷新缓存,分页io是vmm缺页调用的，这个时候不能刷新缓存数据
		
		if ((NonCachedIo || FlagOn(Ccb->CcbState,CCB_FLAG_NETWORK_FILE)) && //如果是非缓存或者是网络文件的写要刷下缓存
			!PagingIo &&
			(FileObject->SectionObjectPointer->DataSectionObject != NULL)) 
		{

			if (!X70FsdAcquireExclusiveFcb( IrpContext, Fcb )) 
			{
				try_return( PostIrp = TRUE );
			}

			ExAcquireResourceSharedLite( Fcb->Header.PagingIoResource, TRUE ); 

			CcFlushCache( FileObject->SectionObjectPointer,
				(PLARGE_INTEGER)&StartingByte,
				(ULONG)ByteCount,
				&Data->IoStatus );

			ExReleaseResourceLite( Fcb->Header.PagingIoResource );
			ExReleaseResource(Fcb->Header.Resource);

			Status = Data->IoStatus.Status;

			if (!NT_SUCCESS( Status)) 
			{
				try_return( Status );
			}

			ExAcquireResourceExclusive( Fcb->Header.PagingIoResource, TRUE ); 
			ExReleaseResource( Fcb->Header.PagingIoResource );
		}

		if ( !PagingIo ) //
		{


			if ( !Wait && NonCachedIo ) 
			{
				if (!X70FsdAcquireSharedFcbWaitForEx( IrpContext,Fcb))
				{
					try_return( PostIrp = TRUE );
				}

				IrpContext->X70FsdIoContext->Wait.Async.Resource = Fcb->Header.Resource; 

			}
			else
			{
				if (!X70FsdAcquireSharedFcb( IrpContext, Fcb )) 
					try_return( PostIrp = TRUE );

				}

			}

		}
		else
		{
			if ( Fcb->Header.PagingIoResource != NULL )
			{

				if ( !ExAcquireResourceSharedLite( Fcb->Header.PagingIoResource, Wait ) )
				{
					try_return( PostIrp = TRUE );
				}

				if (!Wait) 
				{
					IrpContext->X70FsdIoContext->Wait.Async.Resource = Fcb->Header.PagingIoResource; //保存资源

				}

			}
		}

		ScbAcquired = TRUE;

		if (!PagingIo) 
		{
			FLT_PREOP_CALLBACK_STATUS FltOplockStatus;

			FltOplockStatus = FltCheckOplock( &Fcb->Oplock,
				Data,
				IrpContext,
				X70FsdOplockComplete,
				X70FsdPrePostIrp );

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

		}

		if(IS_FLT_FILE_LOCK())
		{
			if ( !PagingIo &&
				(Fcb->FileLock != NULL) &&
				!FltCheckLockForReadAccess( Fcb->FileLock, Data ))
			{
				try_return( Status = STATUS_FILE_LOCK_CONFLICT );
			}
		}
		else
		{
			if ( !PagingIo &&
				(Fcb->FileLock != NULL) &&
				!MyFltCheckLockForReadAccess( Fcb->FileLock, Data ))
			{
				try_return( Status = STATUS_FILE_LOCK_CONFLICT );
			}
		}

		FileSize.QuadPart = Fcb->Header.FileSize.QuadPart;
		ValidDataLength.QuadPart = Fcb->Header.ValidDataLength.QuadPart;

		if ( StartingByte.QuadPart >= FileSize.QuadPart ) 
		{

			Data->IoStatus.Status = 0;
			try_return ( Status = STATUS_END_OF_FILE );
		}

		
		if(Fcb->CcFileObject == NULL && Ccb->StreamFileInfo.StreamObject == NULL)
		{
			try_return(Status = STATUS_FILE_DELETED);
		}

		if ( ByteRange.QuadPart > FileSize.QuadPart ) 
		{
			ByteCount = (ULONG)(FileSize.QuadPart - StartingByte.QuadPart);

			ByteRange.QuadPart = StartingByte.QuadPart  +(LONGLONG ) ByteCount;

			RequestedByteCount = (ULONG)ByteCount;

			if ( NonCachedIo && !Wait ) //
			{
				IrpContext->X70FsdIoContext->Wait.Async.RequestedByteCount = (ULONG)RequestedByteCount; 
			}
		}

		if ( NonCachedIo ) 
		{
			LARGE_INTEGER NewByteOffset;
			ULONG readLen = ByteCount;	
			PUCHAR newBuf = NULL;
			PMDL newMdl = NULL;
			PMDL mdl;
			ULONG_PTR RetBytes = 0;

			ULONG_PTR ZeroOffset = 0;
			ULONG_PTR ZeroLength = 0;

			SystemBuffer = X70FsdMapUserBuffer(Data);

			if ( ByteRange.QuadPart > ValidDataLength.QuadPart )
			{

				if (StartingByte.QuadPart < ValidDataLength.QuadPart) 
				{

					ZeroLength = (ULONG_PTR)ByteCount;

					ZeroOffset = (ULONG_PTR)(ValidDataLength.QuadPart - StartingByte.QuadPart);

					if (ByteCount > ZeroOffset) 
					{
						SafeZeroMemory( Add2Ptr( SystemBuffer, ZeroOffset ), ZeroLength - ZeroOffset);
					}
				}
				else 
				{

					SafeZeroMemory( (PUCHAR)SystemBuffer, ByteCount );

					Data->IoStatus.Information = (ULONG_PTR)ByteCount;

					try_return ( Status = STATUS_SUCCESS );
				}
			}

			ByteCount = ((ULONG)(ValidDataLength.QuadPart - StartingByte.QuadPart) < ByteCount) ?
                             (ULONG)(ValidDataLength.QuadPart - StartingByte.QuadPart) : ByteCount;

			readLen = (ULONG)ROUND_TO_SIZE(ByteCount,volCtx->SectorSize);
			
			newBuf = FltAllocatePoolAlignedWithTag(FltObjects->Instance,NonPagedPool,readLen,'rn');

			if(newBuf == NULL)
			{
				try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
			}

			RtlZeroMemory(newBuf,readLen);

			ExAcquireResourceSharedLite(Ccb->StreamFileInfo.FO_Resource,TRUE);
			FOResourceAcquired = TRUE;
			IrpContext->X70FsdIoContext->Wait.Async.FO_Resource = Ccb->StreamFileInfo.FO_Resource;


			ExAcquireResourceSharedLite(Fcb->EncryptResource,TRUE);
			EncryptResourceAcquired = TRUE;
			IrpContext->X70FsdIoContext->Wait.Async.Resource2 = Fcb->EncryptResource;


			NewByteOffset.QuadPart = StartingByte.QuadPart + Fcb->FileHeaderLength;

			IrpContext->FileObject = BooleanFlagOn(Ccb->CcbState,CCB_FLAG_NETWORK_FILE)?Ccb->StreamFileInfo.StreamObject:Fcb->CcFileObject;

			IrpContext->X70FsdIoContext->Data = Data;

			IrpContext->X70FsdIoContext->SystemBuffer = SystemBuffer;

			IrpContext->X70FsdIoContext->SwapBuffer = newBuf;

			IrpContext->X70FsdIoContext->SwapMdl = newMdl;

			IrpContext->X70FsdIoContext->volCtx = volCtx;

			IrpContext->X70FsdIoContext->Wait.Async.ByteCount = ByteCount;

			IrpContext->X70FsdIoContext->Wait.Async.pFileObjectMutex = NULL;

			IrpContext->X70FsdIoContext->FltObjects = FltObjects;

			IrpContext->X70FsdIoContext->Instance = FltObjects->Instance;

			IrpContext->X70FsdIoContext->FileHeaderLength = Fcb->FileHeaderLength;

			IrpContext->X70FsdIoContext->IsEnFile = Fcb->IsEnFile;

			IrpContext->X70FsdIoContext->pCryptionKey = &Fcb->CryptionKey;


			Status = RealReadFile(FltObjects,IrpContext,newBuf,NewByteOffset,readLen,&RetBytes);  //FltReadFile

			if(Wait) 
			{

				if(Fcb->IsEnFile)
				{
					for(i = 0 ; i < RetBytes/CRYPT_UNIT ; i++)
					{
						aes_ecb_decrypt(Add2Ptr(newBuf,i*CRYPT_UNIT),Add2Ptr(newBuf,i*CRYPT_UNIT),&Fcb->CryptionKey);
					}
				}

				RtlCopyMemory(SystemBuffer,newBuf,ByteCount);

				if(NT_SUCCESS(Status))
				{
					Data->IoStatus.Information =  (RetBytes < ByteCount)? RetBytes:RequestedByteCount;
				}

			}
			else if(NT_SUCCESS(Status))
			{
				NonCachedIoPending = TRUE;
				IrpContext->X70FsdIoContext = NULL;
				volCtx = NULL;
				newBuf = NULL;
				newMdl = NULL;
			}

			if(newMdl != NULL)
			{
				IoFreeMdl(newMdl);
			}
			if(newBuf != NULL)
			{
				FltFreePoolAlignedWithTag(FltObjects->Instance,newBuf,'rn');	
			}
			try_return(Status);

		}
#ifdef OTHER_NETWORK //网络因为oplock还是有问题的，具体见create里面说明
		if(FlagOn(Ccb->CcbState,CCB_FLAG_NETWORK_FILE))
		{
	
			if ( FileObject->PrivateCacheMap == NULL && Fcb->CacheType != CACHE_DISABLE)
			{

				if (Fcb->Header.AllocationSize.QuadPart == FCB_LOOKUP_ALLOCATIONSIZE_HINT) 
				{
					X70FsdLookupFileAllocationSize( IrpContext, Fcb, Ccb);
				}

				if ( FileSize.QuadPart > Fcb->Header.AllocationSize.QuadPart ) 
				{

					X70FsdPopUpFileCorrupt( IrpContext, Fcb );

					X70FsdRaiseStatus( IrpContext, STATUS_FILE_CORRUPT_ERROR );
				}

				CcInitializeCacheMap(
					FileObject,
					(PCC_FILE_SIZES)&Fcb->Header.AllocationSize,
					FALSE,
					&G_CacheMgrCallbacks,
					Fcb
					);

				CcSetAdditionalCacheAttributes(FileObject,TRUE,TRUE);

				CcSetReadAheadGranularity( FileObject, READ_AHEAD_GRANULARITY );

				if(Fcb->CacheType == CACHE_ALLOW)
				{
					if(Ccb->StreamFileInfo.StreamObject->ReadAccess)
					{
						Fcb->CacheType = CACHE_READ;
					}
					if(Ccb->StreamFileInfo.StreamObject->WriteAccess)
					{
						Fcb->CacheType = CACHE_READWRITE;
					}
					Fcb->CacheObject = FileObject;
				}

			}
			if(Fcb->CacheType == CACHE_READWRITE || Fcb->CacheType == CACHE_READ)
			{
				if (!FlagOn(IrpContext->MinorFunction, IRP_MN_MDL)) 
				{

					SystemBuffer = X70FsdMapUserBuffer( Data );


					if (!CcCopyRead( FileObject,
						(PLARGE_INTEGER)&StartingByte,
						(ULONG)ByteCount,
						Wait,
						SystemBuffer,
						&Data->IoStatus )) 
					{
						try_return( PostIrp = TRUE );
					}

					Status = Data->IoStatus.Status;

					ASSERT( NT_SUCCESS( Status ));

					try_return( Status );
				}
				else 
				{

					ASSERT( Wait );

					CcMdlRead( FileObject,
						(PLARGE_INTEGER)&StartingByte,
						(ULONG)ByteCount,
						&Iopb->Parameters.Read.MdlAddress,
						&Data->IoStatus );

					Status = Data->IoStatus.Status;

					ASSERT( NT_SUCCESS( Status ));

					try_return( Status );
				}
			}
			else 
			{

				LARGE_INTEGER NewByteOffset;
				ULONG ReadLen = ByteCount;	
				PUCHAR newBuf = NULL;
				ULONG_PTR RetBytes;
				ULONG i;
				ULONG LessenOffset = 0;  
				PFLT_CALLBACK_DATA RetNewCallbackData = NULL;

				NewByteOffset.QuadPart = StartingByte.QuadPart;

				SystemBuffer = X70FsdMapUserBuffer(Data);

				ExAcquireResourceSharedLite(Ccb->StreamFileInfo.FO_Resource,TRUE);
				FOResourceAcquired = TRUE;

				ExAcquireResourceSharedLite(Fcb->EncryptResource,TRUE);
				EncryptResourceAcquired = TRUE;

				Status = FltAllocateCallbackData(FltObjects->Instance, Ccb->StreamFileInfo.StreamObject,&RetNewCallbackData);

				if(!NT_SUCCESS(Status))
				{
					try_return(Status);
				}
				if(Fcb->IsEnFile)
				{
					LessenOffset = StartingByte.QuadPart % CRYPT_UNIT;
					NewByteOffset.QuadPart  = NewByteOffset.QuadPart - LessenOffset;
					ReadLen += LessenOffset;
					ReadLen = (ULONG)ROUND_TO_SIZE(ReadLen,CRYPT_UNIT);
					NewByteOffset.QuadPart  += Fcb->FileHeaderLength;
					
					newBuf = FltAllocatePoolAlignedWithTag(FltObjects->Instance,NonPagedPool,ReadLen,'rn');

					if(newBuf == NULL)
					{
						try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
					}
					RtlZeroMemory(newBuf,ReadLen);
					
				}

				{
#ifdef CHANGE_TOP_IRP

					PIRP TopLevelIrp = IoGetTopLevelIrp();
					IoSetTopLevelIrp(NULL);		
#endif
					RetNewCallbackData->Iopb->MajorFunction = IRP_MJ_READ;

					RetNewCallbackData->Iopb->Parameters.Read.ByteOffset = (Fcb->IsEnFile ? NewByteOffset:StartingByte);
					RetNewCallbackData->Iopb->Parameters.Read.Length = ReadLen;
					RetNewCallbackData->Iopb->Parameters.Read.ReadBuffer = (Fcb->IsEnFile ? newBuf:SystemBuffer);
					RetNewCallbackData->Iopb->TargetFileObject =  Ccb->StreamFileInfo.StreamObject;
					SetFlag( RetNewCallbackData->Iopb->IrpFlags, Data->Iopb->IrpFlags );

					FltPerformSynchronousIo(RetNewCallbackData);

					Status = RetNewCallbackData->IoStatus.Status;
					RetBytes = RetNewCallbackData->IoStatus.Information;

#ifdef	CHANGE_TOP_IRP
					IoSetTopLevelIrp(TopLevelIrp);
#endif
				}
				if(Fcb->IsEnFile)
				{
					for(i = 0 ; i < RetBytes/CRYPT_UNIT ; i++)
					{
						aes_ecb_decrypt(Add2Ptr(newBuf,i*CRYPT_UNIT),Add2Ptr(newBuf,i*CRYPT_UNIT),&Fcb->CryptionKey);
					}
					RtlCopyMemory(SystemBuffer,Add2Ptr(newBuf,LessenOffset),ByteCount); //同步的拷贝
				}

				if(NT_SUCCESS(Status))
				{
					Data->IoStatus.Information =  (RetBytes < ByteCount)? RetBytes:ByteCount;
				}

				if(RetNewCallbackData != NULL)
				{
					FltFreeCallbackData(RetNewCallbackData);
				}
				if(newBuf != NULL)
				{
					FltFreePoolAlignedWithTag(FltObjects->Instance,newBuf,'wn');
				}
				try_return(Status);
			}

		}
		else
#endif
		{
			if ( FileObject->PrivateCacheMap == NULL )
			{

				if (Fcb->Header.AllocationSize.QuadPart == FCB_LOOKUP_ALLOCATIONSIZE_HINT) 
				{
					
					X70FsdLookupFileAllocationSize( IrpContext, Fcb, Ccb );
				}

				if ( FileSize.QuadPart > Fcb->Header.AllocationSize.QuadPart ) 
				{
					X70FsdPopUpFileCorrupt( IrpContext, Fcb );

					X70FsdRaiseStatus( IrpContext, STATUS_FILE_CORRUPT_ERROR );
				}

				CcInitializeCacheMap(
					FileObject,
					(PCC_FILE_SIZES)&Fcb->Header.AllocationSize,
					FALSE,
					&G_CacheMgrCallbacks,
					Fcb
					);

				CcSetReadAheadGranularity( FileObject, READ_AHEAD_GRANULARITY );

				Fcb->CacheObject = FileObject;
			}

			if (!FlagOn(IrpContext->MinorFunction, IRP_MN_MDL)) {


				SystemBuffer = X70FsdMapUserBuffer( Data );
				
				if (!CcCopyRead( FileObject,
					(PLARGE_INTEGER)&StartingByte,
					(ULONG)ByteCount,
					Wait,
					SystemBuffer,
					&Data->IoStatus )) 
				{

					try_return( PostIrp = TRUE );
				}

				Status = Data->IoStatus.Status;

				ASSERT( NT_SUCCESS( Status ));

				try_return( Status );
			}
			else 
			{

				ASSERT( Wait );

				CcMdlRead( FileObject,
					(PLARGE_INTEGER)&StartingByte,
					(ULONG)ByteCount,
					&Iopb->Parameters.Read.MdlAddress,
					&Data->IoStatus );

				Status = Data->IoStatus.Status;

				ASSERT( NT_SUCCESS( Status ));

				try_return( Status );
			}
		}


try_exit:NOTHING;

		if(!NonCachedIoPending)
		{
			if ( !PostIrp ) 
			{

				ULONG ActualBytesRead;

				ActualBytesRead = (ULONG)Data->IoStatus.Information;

				if (SynchronousIo && !PagingIo) 
				{

					FileObject->CurrentByteOffset.QuadPart =
						StartingByte.QuadPart + ActualBytesRead;
				}

				if (NT_SUCCESS(Status) && !PagingIo) 
				{

					SetFlag( FileObject->Flags, FO_FILE_FAST_IO_READ );
				}
			} 
			else 
			{
				if (!OplockPostIrp) 
				{

					Status = X70FsdPostRequest(Data, IrpContext );

					FltStatus = FLT_PREOP_PENDING;

				}

			}
		}
	}
	finally{

		if(!NonCachedIoPending)
		{
			if ( FOResourceAcquired )
			{
				ExReleaseResourceLite( Ccb->StreamFileInfo.FO_Resource );
			}

			if(EncryptResourceAcquired)
			{
				ExReleaseResourceLite( Fcb->EncryptResource );
			}

			if (ScbAcquired) 
			{

				if ( PagingIo ) 
				{

					ExReleaseResourceLite( Fcb->Header.PagingIoResource );

				} 
				else 
				{

					X70FsdReleaseFcb( NULL, Fcb );
				}
			}
		}

		if(volCtx != NULL)
		{
			FltReleaseContext(volCtx);
			volCtx = NULL;
		}

		if(NonCachedIoPending || Status == STATUS_PENDING)
		{
			FltStatus = FLT_PREOP_PENDING;
		}
		if(FltStatus != FLT_PREOP_PENDING)
		{
			Data->IoStatus.Status = Status;

			FltStatus = FLT_PREOP_COMPLETE;
		}

		if(AbnormalTermination())
		{
			DbgPrint("CcFileObject = %x ,StreamObject = %x,Flags = %x, \n",Fcb->CcFileObject,Ccb->StreamFileInfo.StreamObject,Data->Iopb->IrpFlags);
		}
		if(!PostIrp && !AbnormalTermination())
		{
			X70FsdCompleteRequest(&IrpContext,&Data,Data->IoStatus.Status,FALSE);
		}

	}

	return FltStatus;
}

VOID ReadFileAsyncCompletionRoutine(
									IN PFLT_CALLBACK_DATA CallbackData,
									IN PFLT_CONTEXT Context
									)
{

	PLAYERFSD_IO_CONTEXT X70FsdIoContext = (PLAYERFSD_IO_CONTEXT)Context;

	PERESOURCE Resource  = X70FsdIoContext->Wait.Async.Resource;

	PERESOURCE Resource2  = X70FsdIoContext->Wait.Async.Resource2;

	PERESOURCE FO_Resource  = X70FsdIoContext->Wait.Async.FO_Resource;

	PVOLUME_CONTEXT volCtx = X70FsdIoContext->volCtx;

	ERESOURCE_THREAD ResourceThreadId = X70FsdIoContext->Wait.Async.ResourceThreadId;

	PFLT_CALLBACK_DATA Data = X70FsdIoContext->Data;

	PFAST_MUTEX pFileObjectMutex = X70FsdIoContext->Wait.Async.pFileObjectMutex;

	ULONG RequestedByteCount = X70FsdIoContext->Wait.Async.RequestedByteCount;

	ULONG ByteCount = X70FsdIoContext->Wait.Async.ByteCount;

	ULONG_PTR RetBytes = CallbackData->IoStatus.Information ;

	PIRP TopLevelIrp = X70FsdIoContext->TopLevelIrp;

	Data->IoStatus.Status = CallbackData->IoStatus.Status;

	if ( NT_SUCCESS(Data->IoStatus.Status) )
	{
		if ( !X70FsdIoContext->PagingIo )
		{
			SetFlag( X70FsdIoContext->Wait.Async.FileObject->Flags, FO_FILE_FAST_IO_READ );
		}	
	}

	Data->IoStatus.Information =  (RetBytes < ByteCount)? RetBytes:RequestedByteCount;

	if ( Resource != NULL)
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


	if (NT_SUCCESS( Data->IoStatus.Status))
	{
		ULONG i;
		if(X70FsdIoContext->IsEnFile)
		{	
			
			for(i = 0 ; i < RetBytes/CRYPT_UNIT ; i++)
			{
				aes_ecb_decrypt(Add2Ptr(X70FsdIoContext->SwapBuffer,i*CRYPT_UNIT),
					Add2Ptr(X70FsdIoContext->SwapBuffer,i*CRYPT_UNIT),
					X70FsdIoContext->pCryptionKey);
			}

		}
		RtlCopyMemory(X70FsdIoContext->SystemBuffer,X70FsdIoContext->SwapBuffer,ByteCount);

	}

	FltFreeCallbackData(CallbackData);

	if(X70FsdIoContext->SwapMdl != NULL)
	{
		IoFreeMdl(X70FsdIoContext->SwapMdl);
	}
	FltFreePoolAlignedWithTag(X70FsdIoContext->Instance ,X70FsdIoContext->SwapBuffer,'rn');


	ExFreeToNPagedLookasideList(
		&G_IoContextLookasideList,
		X70FsdIoContext
		);

	if(pFileObjectMutex != NULL)
	{
		ExReleaseFastMutex(pFileObjectMutex);
	}
	if ( FO_Resource != NULL )
	{
		ExReleaseResourceForThreadLite(
			FO_Resource,
			ResourceThreadId
			);
	}

	if(volCtx != NULL)
	{
		FltReleaseContext(volCtx);
		volCtx = NULL;
	}

	FltCompletePendedPreOperation(Data,FLT_PREOP_COMPLETE,NULL); //可以在dpc级别调用

	return ;
}



NTSTATUS RealReadFile(
				  IN PCFLT_RELATED_OBJECTS FltObjects,
				  IN PIRP_CONTEXT IrpContext,
				  IN PVOID SystemBuffer,
				  IN LARGE_INTEGER ByteOffset,
				  IN ULONG ByteCount,
				  OUT PULONG_PTR RetBytes
				  )
{
	NTSTATUS Status;
	PFLT_CALLBACK_DATA RetNewCallbackData = NULL;

	PFILE_OBJECT FileObject = IrpContext->FileObject;

	BOOLEAN Wait = BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);

	ULONG IrpFlags = IRP_READ_OPERATION;
	
#ifndef USE_CACHE_READWRITE
	SetFlag(IrpFlags,IRP_NOCACHE);
#endif
	Status = FltAllocateCallbackData(FltObjects->Instance,FileObject,&RetNewCallbackData);

	if(NT_SUCCESS(Status))
	{

		PIRP TopLevelIrp = NULL;

		if(!InSameVACB(ByteOffset.QuadPart,ByteOffset.QuadPart+ByteCount))
		{
			//
		}

#ifdef CHANGE_TOP_IRP

		TopLevelIrp = IoGetTopLevelIrp();
		IoSetTopLevelIrp(NULL);		
#endif
		RetNewCallbackData->Iopb->MajorFunction = IRP_MJ_READ;

		RetNewCallbackData->Iopb->Parameters.Read.ByteOffset = ByteOffset;
		RetNewCallbackData->Iopb->Parameters.Read.Length = ByteCount;
		RetNewCallbackData->Iopb->Parameters.Read.ReadBuffer = SystemBuffer;

		RetNewCallbackData->Iopb->TargetFileObject = FileObject;

		SetFlag( RetNewCallbackData->Iopb->IrpFlags, IrpFlags );

		if(Wait)
		{

			SetFlag( RetNewCallbackData->Iopb->IrpFlags,IRP_SYNCHRONOUS_API);
			FltPerformSynchronousIo(RetNewCallbackData);

			Status = RetNewCallbackData->IoStatus.Status;
			*RetBytes = RetNewCallbackData->IoStatus.Information;

		}
		else
		{

			Status = FltPerformAsynchronousIo(RetNewCallbackData,ReadFileAsyncCompletionRoutine,IrpContext->X70FsdIoContext);

		}
#ifdef	CHANGE_TOP_IRP
		IoSetTopLevelIrp(TopLevelIrp);
#endif
	}

	if(RetNewCallbackData != NULL && Wait)
	{
		FltFreeCallbackData(RetNewCallbackData);
	}
	return Status;
}
