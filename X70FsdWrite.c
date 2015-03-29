#include"X70FsdWrite.h"
#include"X70FsdData.h"

extern CACHE_MANAGER_CALLBACKS  G_CacheMgrCallbacks;
extern NPAGED_LOOKASIDE_LIST  G_IoContextLookasideList;

extern LARGE_INTEGER X70FsdLarge0;
extern LARGE_INTEGER X70FsdLarge1;

extern KSPIN_LOCK GeneralSpinLock;

extern USHORT gOsServicePackMajor;
extern ULONG gOsMajorVersion;
extern ULONG gOsMinorVersion;

#define Li0                              (X70FsdLarge0)
#define Li1                              (X70FsdLarge1)

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationWrite (
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
PtPreOperationWrite (
					 __inout PFLT_CALLBACK_DATA Data,
					 __in PCFLT_RELATED_OBJECTS FltObjects,
					 __deref_out_opt PVOID *CompletionContext
					 )
{
	FLT_PREOP_CALLBACK_STATUS	FltStatus;
	BOOLEAN TopLevel = FALSE;
	BOOLEAN ModWriter = FALSE;
	PIRP_CONTEXT IrpContext = NULL;

	FsRtlEnterFileSystem();

	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if(FLT_IS_IRP_OPERATION(Data)) //irp Write
	{

		//创建irp上下文
		try
		{
			TopLevel = X70FsdIsIrpTopLevel( Data );

			IrpContext = X70FsdCreateIrpContext( Data,FltObjects, CanFsdWait( Data ) );

			if(IrpContext == NULL)
			{
				X70FsdRaiseStatus(IrpContext,STATUS_INSUFFICIENT_RESOURCES);
			}

			if (IoGetTopLevelIrp() == (PIRP)FSRTL_MOD_WRITE_TOP_LEVEL_IRP) 
			{
				ModWriter = TRUE;

				IoSetTopLevelIrp((PIRP)Data );
			}

			if (FlagOn( Data->Iopb->MinorFunction, IRP_MN_COMPLETE )) //上层用来 FreeMdl请求的
			{
				FltStatus = X70FsdCompleteMdl(Data, FltObjects,IrpContext);
			}
			else
			{
				FltStatus = X70FsdCommonWrite(Data, FltObjects,IrpContext);
			}

		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{

			X70FsdProcessException(&IrpContext,&Data,GetExceptionCode());
			FltStatus = FLT_PREOP_COMPLETE;
		}

		// 恢复Top-Level IRP
		if (ModWriter) { IoSetTopLevelIrp((PIRP)FSRTL_MOD_WRITE_TOP_LEVEL_IRP); }

		if (TopLevel) { IoSetTopLevelIrp( NULL ); }

	}
	else if(FLT_IS_FASTIO_OPERATION(Data)) //fastio Write
	{
		FltStatus = X70FsdFastIoWrite(Data, FltObjects); 
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
X70FsdFastIoWrite(__inout PFLT_CALLBACK_DATA Data,
					__in PCFLT_RELATED_OBJECTS FltObjects)
{
	PFCB Fcb;
	PCCB Ccb;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_DISALLOW_FASTIO;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	PFLT_IO_PARAMETER_BLOCK	Iopb = Data->Iopb;
	PDEVICE_OBJECT targetVdo = IoGetRelatedDeviceObject( FileObject );
	PFAST_IO_DISPATCH FastIoDispatch = targetVdo->DriverObject->FastIoDispatch;

	PLARGE_INTEGER FileOffset = &Iopb->Parameters.Write.ByteOffset;
	ULONG LockKey = Iopb->Parameters.Write.Key;
	ULONG Length = Iopb->Parameters.Write.Length;
	BOOLEAN ExtendingFile = FALSE;
	BOOLEAN Status = TRUE;

	BOOLEAN Wait = FltIsOperationSynchronous(Data);
	PIO_STATUS_BLOCK IoStatus = &Data->IoStatus;

	PVOID Buffer = X70FsdMapUserBuffer(Data);

	PAGED_CODE();

	Fcb = FileObject->FsContext;
	Ccb = FileObject->FsContext2;

	if(FlagOn(Ccb->CcbState,CCB_FLAG_NETWORK_FILE))
	{
		return FLT_PREOP_DISALLOW_FASTIO;
	}
	ExAcquireResourceSharedLite(Fcb->EncryptResource,TRUE);

	if(!Fcb->IsEnFile && BooleanFlagOn(Fcb->FileType,FILE_ACCESS_WRITE_CHANGE_TO_ENCRYPTION))
	{
		ExReleaseResourceLite(Fcb->EncryptResource);
		return FLT_PREOP_DISALLOW_FASTIO;
	}

	ExReleaseResourceLite(Fcb->EncryptResource);

	Status = FsRtlCopyWrite(FileObject,FileOffset,Length,Wait,LockKey,Buffer, IoStatus,targetVdo);

	if(Status)
	{
		FltStatus = FLT_PREOP_COMPLETE;
	}
	return FltStatus;
}

FLT_PREOP_CALLBACK_STATUS
X70FsdCommonWrite(
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
	LARGE_INTEGER InitialFileSize;
	LARGE_INTEGER InitialValidDataLength;

	LONGLONG OldFileSize;
	LONGLONG LlTemp1;
	ULONG ByteCount;
	ULONG RequestedByteCount;

	LARGE_INTEGER FileSize;
	PFILE_OBJECT FileObject;
	PFCB Fcb;
	PCCB Ccb;
	PFSRTL_ADVANCED_FCB_HEADER Header;

	BOOLEAN Wait;
	BOOLEAN PagingIo;
	BOOLEAN NonCachedIo;
	BOOLEAN	SynchronousIo;
	BOOLEAN	WriteToEof;

	KEVENT Event;

	BOOLEAN PostIrp = FALSE;
	BOOLEAN DoingIoAtEof = FALSE;
	BOOLEAN SetWriteSeen = FALSE;
	BOOLEAN OplockPostIrp = FALSE;
	BOOLEAN CalledByLazyWriter = FALSE;
	BOOLEAN RecursiveWriteThrough = FALSE;

	BOOLEAN PagingIoResourceAcquired = FALSE;
	BOOLEAN ScbAcquired = FALSE;
	BOOLEAN CcFileSizeChangeDue = FALSE;
	BOOLEAN FcbAcquired = FALSE;
	BOOLEAN FOResourceAcquired = FALSE;
	BOOLEAN	NonCachedIoPending = FALSE;
	BOOLEAN FcbAcquiredExclusive = FALSE;
	BOOLEAN FcbCanDemoteToShared = FALSE;
	BOOLEAN EncryptResourceAcquired = FALSE;

	BOOLEAN SwitchBackToAsync = FALSE;
	BOOLEAN UnwindOutstandingAsync = FALSE;
	BOOLEAN ExtendingValidData = FALSE;
	BOOLEAN WriteFileSizeToDirent = FALSE;

	BOOLEAN ExtendingFile = FALSE;
	EOF_WAIT_BLOCK EofWaitBlock;
	PVOID SystemBuffer = NULL;
	PVOLUME_CONTEXT volCtx = NULL;

	LAYERFSD_IO_CONTEXT StackX70FsdIoContext;

	StartingByte = Iopb->Parameters.Write.ByteOffset;

	ByteCount = Iopb->Parameters.Write.Length;

	ByteRange.QuadPart = StartingByte.QuadPart  + (LONGLONG) ByteCount;

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

	WriteToEof = ( (StartingByte.LowPart == FILE_WRITE_TO_END_OF_FILE) &&
		(StartingByte.HighPart == -1) );

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

	//如果一个非加密文件收到了写请求转变他成为加密文件
	if(!PagingIo && !Fcb->IsEnFile && BooleanFlagOn(Fcb->FileType,FILE_ACCESS_WRITE_CHANGE_TO_ENCRYPTION))
	{	

		Status = TransformFileToEncrypted(Data,FltObjects,Fcb,Ccb);

		if(!NT_SUCCESS(Status))
		{
			Data->IoStatus.Status = Status;
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;
		}
	}

	//
	// 处理延迟写请求
	//

	if (!PagingIo &&
		(!NonCachedIo) && //非缓存跟pagingio 均不支持延迟写入
		!CcCanIWrite(FileObject,
		(ULONG)ByteCount,
		(BOOLEAN)(FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT) &&
		!FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_IN_FSP)), 
		BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_DEFERRED_WRITE)))  //
	{ 

		BOOLEAN Retrying = BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_DEFERRED_WRITE); //延迟写

		X70FsdPrePostIrp(Data, IrpContext); //锁定用户内存等操作为延迟操作做准备

		SetFlag( IrpContext->Flags, IRP_CONTEXT_DEFERRED_WRITE );

		CcDeferWrite( FileObject,
			(PCC_POST_DEFERRED_WRITE)X70FsdAddToWorkque,
			Data,
			IrpContext,
			(ULONG)ByteCount,
			Retrying ); //延迟写请求

		return FLT_PREOP_PENDING;
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

	Header = &Fcb->Header;

	if (NonCachedIo) 
	{

		if (IrpContext->X70FsdIoContext == NULL) 
		{

			if (!Wait) 
			{

				IrpContext->X70FsdIoContext = (PLAYERFSD_IO_CONTEXT)ExAllocateFromNPagedLookasideList( &G_IoContextLookasideList );

			} else {

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

	try {

		//非缓存的io需要刷新下缓存，让缓存内容先写到磁盘上
		if ((NonCachedIo || FlagOn(Ccb->CcbState,CCB_FLAG_NETWORK_FILE)) && //如果是非缓存或者是网络文件的写要刷下缓存
			!PagingIo &&
			(FileObject->SectionObjectPointer->DataSectionObject != NULL))
		{

			if (!X70FsdAcquireExclusiveFcb( IrpContext, Fcb ))
			{
				try_return( PostIrp = TRUE );
			}
			ScbAcquired = TRUE;
			FcbAcquiredExclusive = TRUE;

			ExAcquireSharedStarveExclusive( Header->PagingIoResource, TRUE ); //饥饿的取得pagingio资源

			CcFlushCache( FileObject->SectionObjectPointer,
				WriteToEof ? &Header->FileSize : (PLARGE_INTEGER)&StartingByte,
				(ULONG)ByteCount,
				&Data->IoStatus ); //刷新缓存

			ExReleaseResourceLite( Fcb->Header.PagingIoResource );

			if ( !NT_SUCCESS( Data->IoStatus.Status ) )
			{
				try_return( Status = Data->IoStatus.Status );

			}
			ExAcquireResourceExclusiveLite( Fcb->Header.PagingIoResource, TRUE);
			PagingIoResourceAcquired = TRUE;

			CcPurgeCacheSection(
				FileObject->SectionObjectPointer,
				WriteToEof ? &Header->FileSize : (PLARGE_INTEGER)&StartingByte,
				(ULONG)ByteCount,
				FALSE ); //清理缓存

			//改变独占资源变成共享资源
			FcbCanDemoteToShared = TRUE;
		}

		if (PagingIo) //取得相关资源然后校验写操作请求
		{

			(VOID)ExAcquireResourceSharedLite( Fcb->Header.PagingIoResource, TRUE );
			PagingIoResourceAcquired = TRUE;

			if (!Wait) 
			{
				IrpContext->X70FsdIoContext->Wait.Async.Resource = Header->PagingIoResource;

			}
			if (Fcb->MoveFileEvent) {

				(VOID)KeWaitForSingleObject( Fcb->MoveFileEvent,
					Executive,
					KernelMode,
					FALSE,
					NULL );
			}
		}
		else
		{
			if (!Wait && NonCachedIo) 
			{

				if (!ScbAcquired &&
					!X70FsdAcquireSharedFcbWaitForEx( IrpContext, Fcb )) 
				{
					try_return( PostIrp = TRUE );
				}

				IrpContext->X70FsdIoContext->Wait.Async.Resource = Fcb->Header.Resource;

				if (FcbCanDemoteToShared) 
				{

					IrpContext->X70FsdIoContext->Wait.Async.Resource2 = Fcb->Header.PagingIoResource;

				}
			} 
			else 
			{

				if (!ScbAcquired &&
					!X70FsdAcquireSharedFcb( IrpContext, Fcb )) 
				{
					try_return( PostIrp = TRUE );
				}
			}

			ScbAcquired = TRUE;
		}

		ValidDataLength.QuadPart = Fcb->Header.ValidDataLength.QuadPart;
		FileSize.QuadPart = Fcb->Header.FileSize.QuadPart;

		if(PagingIo)
		{
			if (StartingByte.QuadPart >= FileSize.QuadPart) 
			{
				Data->IoStatus.Information = 0;

				try_return( Status = STATUS_SUCCESS );
			}

			if (ByteCount > (ULONG)(FileSize.QuadPart - StartingByte.QuadPart))
			{

				ByteCount = (ULONG)(FileSize.QuadPart - StartingByte.QuadPart);
			}
		}

		if ((Fcb->LazyWriteThread[0]  == PsGetCurrentThread()) ||
			(Fcb->LazyWriteThread[1]  == PsGetCurrentThread()))  //表示这是一个延迟写
		{

			CalledByLazyWriter = TRUE; //当前是一个延迟的写请求的话 是不能扩展文件大小的

			if (FlagOn( Fcb->Header.Flags, FSRTL_FLAG_USER_MAPPED_FILE ))  //如果是文件映射
			{

				if ((StartingByte.QuadPart + ByteCount > ValidDataLength.QuadPart) &&
					(StartingByte.QuadPart < FileSize.QuadPart)) 
				{

					if (StartingByte.QuadPart + ByteCount > ((ValidDataLength.QuadPart + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))) //保证这次刷新的页包含有效数据
					{
						try_return( Status = STATUS_FILE_LOCK_CONFLICT );
					}
				}
			}
		}

		if (FlagOn(Iopb->IrpFlags , IRP_SYNCHRONOUS_PAGING_IO) &&
			FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_RECURSIVE_CALL)) 
		{
			//如果顶层操作也是写就直接写入
			PFLT_CALLBACK_DATA TopLevelData;

			TopLevelData = (PFLT_CALLBACK_DATA) IoGetTopLevelIrp();

			if ((ULONG_PTR)TopLevelData > FSRTL_MAX_TOP_LEVEL_IRP_FLAG &&
				FLT_IS_IRP_OPERATION(TopLevelData)) 
			{

				PFLT_IO_PARAMETER_BLOCK Iopb = TopLevelData->Iopb;

				if ((Iopb->MajorFunction == IRP_MJ_WRITE) &&
					(Iopb->TargetFileObject->FsContext == FileObject->FsContext)) 
				{
					RecursiveWriteThrough = TRUE;
					SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_WRITE_THROUGH );
				}
			}
		}
		if ( !CalledByLazyWriter &&
			!RecursiveWriteThrough &&
			(WriteToEof ||
			StartingByte.QuadPart + ByteCount > ValidDataLength.QuadPart)) //需要转变成为同步操作
		{

			if (!Wait)  //异步的设置成同步
			{

				Wait = TRUE;
				SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT );

				if (NonCachedIo) 
				{
					SwitchBackToAsync = TRUE; //非同步的转变成为同步的。
				}
			}
			//如果扩展的文件我们就要独占资源了
			if ( PagingIo ) 
			{

				ExReleaseResourceLite( Fcb->Header.PagingIoResource );
				PagingIoResourceAcquired = FALSE;

			}
			else 
			{

				if (!FcbAcquiredExclusive) {

					X70FsdReleaseFcb( IrpContext, Fcb );
					ScbAcquired = FALSE;

					if (!X70FsdAcquireExclusiveFcb( IrpContext, Fcb )) 
					{
						try_return( PostIrp = TRUE );
					}

					ScbAcquired = TRUE;
					FcbAcquiredExclusive = TRUE;
				}
			}

			if (SwitchBackToAsync) //检查是否要转换回异步，我们要fcb主资源释放前更新有效大小
			{

				if ((Fcb->SectionObjectPointers.DataSectionObject != NULL) ||		//如果这里是有数据视图需要保持同步
					(StartingByte.QuadPart + ByteCount > Fcb->Header.ValidDataLength.QuadPart))
				{

					RtlZeroMemory( IrpContext->X70FsdIoContext, sizeof(LAYERFSD_IO_CONTEXT) );

					KeInitializeEvent( &IrpContext->X70FsdIoContext->Wait.SyncEvent,
						NotificationEvent,
						FALSE );

					SwitchBackToAsync = FALSE;

				} 
				else 
				{

					if (!Fcb->OutstandingAsyncEvent) 
					{

						Fcb->OutstandingAsyncEvent =
							FsRtlAllocatePoolWithTag( NonPagedPool,
							sizeof(KEVENT),
							'evn' );

						KeInitializeEvent( Fcb->OutstandingAsyncEvent,
							NotificationEvent,
							FALSE );
					}

					if (ExInterlockedAddUlong( &Fcb->OutstandingAsyncWrites,
						1,
						&GeneralSpinLock ) == 0)  //事件用来同步异步的扩展有效长度的非缓存写
					{

						KeClearEvent( Fcb->OutstandingAsyncEvent );
					}

					UnwindOutstandingAsync = TRUE;

					IrpContext->X70FsdIoContext->Wait.Async.OutstandingAsyncEvent = Fcb->OutstandingAsyncEvent;
					IrpContext->X70FsdIoContext->Wait.Async.OutstandingAsyncWrites = &Fcb->OutstandingAsyncWrites;
				}
			}
			//调整资源后重新取得文件大小信息
			ValidDataLength.QuadPart = Fcb->Header.ValidDataLength.QuadPart;
			FileSize.QuadPart = Fcb->Header.FileSize.QuadPart;

			if ( PagingIo ) 
			{

				if (StartingByte.QuadPart >= FileSize.QuadPart) 
				{
					Data->IoStatus.Information = 0;
					try_return( Status = STATUS_SUCCESS );
				}

				ByteCount = Iopb->Parameters.Write.Length;

				if (ByteCount > (ULONG)(FileSize.QuadPart - StartingByte.QuadPart)) 
				{
					ByteCount = (ULONG)(FileSize.QuadPart - StartingByte.QuadPart);
				}
			}
		}

		if (NonCachedIo && !Wait) 
		{
			IrpContext->X70FsdIoContext->Wait.Async.RequestedByteCount =
				ByteCount;
		}

		if(Fcb->CcFileObject == NULL && Ccb->StreamFileInfo.StreamObject == NULL)
		{
			try_return(Status = STATUS_FILE_DELETED);
		}

		InitialFileSize.QuadPart = FileSize.QuadPart;

		InitialValidDataLength.QuadPart = ValidDataLength.QuadPart;

		if ( WriteToEof ) 
		{
			StartingByte = Fcb->Header.FileSize;
		}

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
				!FltCheckLockForWriteAccess( Fcb->FileLock, Data ))
			{
				try_return( Status = STATUS_FILE_LOCK_CONFLICT );
			}
		}
		else
		{
			if ( !PagingIo &&
				(Fcb->FileLock != NULL) &&
				!MyFltCheckLockForWriteAccess( Fcb->FileLock, Data ))
			{
				try_return( Status = STATUS_FILE_LOCK_CONFLICT );
			}
		}

		if (!PagingIo && (StartingByte.QuadPart + ByteCount > FileSize.QuadPart)) 
		{
			ExtendingFile = TRUE;
		}

		if ( ExtendingFile ) //扩展了文件大小
		{
			FileSize.QuadPart = StartingByte.QuadPart + ByteCount;

			if (Fcb->Header.AllocationSize.QuadPart == FCB_LOOKUP_ALLOCATIONSIZE_HINT) 
			{
				X70FsdLookupFileAllocationSize( IrpContext, Fcb ,Ccb);
			}

			if ( FileSize.QuadPart > Fcb->Header.AllocationSize.QuadPart ) 
			{

				ULONG ClusterSize = volCtx->SectorSize * volCtx->SectorsPerAllocationUnit; //簇大小

				LARGE_INTEGER TempLI;

				TempLI.QuadPart = FileSize.QuadPart;//占用大小
				TempLI.QuadPart += ClusterSize;
				TempLI.HighPart += (ULONG)( (LONGLONG)ClusterSize >> 32 );

				if ( TempLI.LowPart == 0 ) //不需要进位 
				{
					TempLI.HighPart -= 1;
				}

				Fcb->Header.AllocationSize.LowPart  = ( (ULONG)FileSize.LowPart + (ClusterSize - 1) ) & ( ~(ClusterSize - 1) );

				Fcb->Header.AllocationSize.HighPart = TempLI.HighPart;

			}
			ASSERT( FileSize.QuadPart <= Fcb->Header.AllocationSize.QuadPart );

			Fcb->Header.FileSize.QuadPart = FileSize.QuadPart;

			if (CcIsFileCached(FileObject)) 
			{
				CcSetFileSizes( FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize );
			}
		}

		//
		if ( !CalledByLazyWriter &&
			!RecursiveWriteThrough &&
			(StartingByte.QuadPart + ByteCount > ValidDataLength.QuadPart) ) 
		{

			ExtendingValidData = TRUE;

#ifndef CHANGE_TOP_IRP

			ExtendingValidDataSetFile(FltObjects,Fcb,Ccb);
#endif
		}
		else
		{

			if (FcbCanDemoteToShared) 
			{
				ASSERT( FcbAcquiredExclusive && ExIsResourceAcquiredExclusiveLite( Fcb->Header.Resource ));
				ExConvertExclusiveToSharedLite( Fcb->Header.Resource );
				FcbAcquiredExclusive = FALSE;
			}
		}

		if (NonCachedIo) 
		{
			{
				LARGE_INTEGER NewByteOffset;
				ULONG WriteLen = ByteCount;	
				ULONG RealWriteLen = ByteCount;	
				PUCHAR newBuf = NULL;
				PMDL newMdl = NULL;
				ULONG_PTR RetBytes = 0 ;
				ULONG_PTR i;
				ULONG SectorSize = volCtx->SectorSize;

				SystemBuffer = X70FsdMapUserBuffer(Data);

				//修正大小变成扇区整数倍

				//WriteLen = (ULONG)ROUND_TO_SIZE(WriteLen,CRYPT_UNIT); error

				WriteLen = (ULONG)ROUND_TO_SIZE(WriteLen,SectorSize);

				if ((((ULONG)StartingByte.QuadPart) & (SectorSize - 1))||

					((WriteLen != (ULONG)ByteCount)
					&& (StartingByte.QuadPart + (LONGLONG)ByteCount < ValidDataLength.QuadPart))) 
				{

					try_return( Status = STATUS_NOT_IMPLEMENTED );
				}

				//清0数据
				if (!CalledByLazyWriter &&
					!RecursiveWriteThrough &&
					(StartingByte.QuadPart > ValidDataLength.QuadPart)) 
				{

					X70FsdZeroData( IrpContext,
						Fcb,
						FileObject,
						ValidDataLength.QuadPart,
						StartingByte.QuadPart - ValidDataLength.QuadPart,
						volCtx->SectorSize);

				}

				WriteFileSizeToDirent = TRUE;

				if (SwitchBackToAsync) 
				{
					//依然是一个异步操作，这样肯定能异步完成例程里面完成事件
					Wait = FALSE;
					ClearFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT );
				}

				//利用我们的原始文件对象对数据进行读取，然后复制到需要的数据区里面
				newBuf = FltAllocatePoolAlignedWithTag(FltObjects->Instance,NonPagedPool,WriteLen,'wn');

				if(newBuf == NULL)
				{
					try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
				}

				RtlZeroMemory(newBuf,WriteLen);

				RtlCopyMemory(newBuf,SystemBuffer,ByteCount);

				ExAcquireResourceSharedLite(Ccb->StreamFileInfo.FO_Resource,TRUE);
				FOResourceAcquired = TRUE;
				IrpContext->X70FsdIoContext->Wait.Async.FO_Resource = Ccb->StreamFileInfo.FO_Resource;


				ExAcquireResourceSharedLite(Fcb->EncryptResource,TRUE);
				EncryptResourceAcquired = TRUE;
				IrpContext->X70FsdIoContext->Wait.Async.Resource2 = Fcb->EncryptResource;

				NewByteOffset.QuadPart = StartingByte.QuadPart + Fcb->FileHeaderLength;

				if(Fcb->IsEnFile)
				{			
					//RealWriteLen = (ULONG)ROUND_TO_SIZE(RealWriteLen,CRYPT_UNIT);

					for(i = 0 ; i < WriteLen/CRYPT_UNIT ; i++)
					{
						aes_ecb_encrypt(Add2Ptr(newBuf,i*CRYPT_UNIT),Add2Ptr(newBuf,i*CRYPT_UNIT),&Fcb->CryptionKey);
					}
				}
			
				IrpContext->FileObject = BooleanFlagOn(Ccb->CcbState,CCB_FLAG_NETWORK_FILE)?Ccb->StreamFileInfo.StreamObject:Fcb->CcFileObject;

				IrpContext->X70FsdIoContext->Data = Data;

				IrpContext->X70FsdIoContext->SystemBuffer = SystemBuffer;

				IrpContext->X70FsdIoContext->SwapBuffer = newBuf;

				IrpContext->X70FsdIoContext->SwapMdl = newMdl;

				IrpContext->X70FsdIoContext->volCtx = volCtx;

				IrpContext->X70FsdIoContext->Wait.Async.RequestedByteCount = ByteCount;

				IrpContext->X70FsdIoContext->Wait.Async.pFileObjectMutex = NULL;//&Ccb->StreamFileInfo.FileObjectMutex;

				IrpContext->X70FsdIoContext->ByteOffset.QuadPart = StartingByte.QuadPart;

				IrpContext->X70FsdIoContext->FltObjects = FltObjects;

				IrpContext->X70FsdIoContext->Instance = FltObjects->Instance;

				Status = RealWriteFile(FltObjects,IrpContext,newBuf,NewByteOffset,WriteLen,&RetBytes);  

				if(Wait) 
				{
					Data->IoStatus.Status = Status;
					Data->IoStatus.Information =  (RetBytes < ByteCount)? RetBytes:ByteCount;

				}
				else if(NT_SUCCESS(Status))
				{
					UnwindOutstandingAsync = FALSE;

					Wait = TRUE;

					SetFlag( IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT );
					NonCachedIoPending = TRUE;
					IrpContext->X70FsdIoContext = NULL;
					volCtx = NULL;
					newBuf = NULL;
				}

				if(newMdl != NULL)//释放内存
				{
					IoFreeMdl(newMdl);
				}
				if(newBuf != NULL)
				{
					FltFreePoolAlignedWithTag(FltObjects->Instance,newBuf,'wn');
				}
				try_return(Status);

			}

		}

		ASSERT( !PagingIo );

#ifdef OTHER_NETWORK

		if(FlagOn(Ccb->CcbState,CCB_FLAG_NETWORK_FILE))
		{

			if ( FileObject->PrivateCacheMap == NULL && Fcb->CacheType != CACHE_DISABLE)
			{

				if (Fcb->Header.AllocationSize.QuadPart == FCB_LOOKUP_ALLOCATIONSIZE_HINT) 
				{

					X70FsdLookupFileAllocationSize( IrpContext, Fcb ,Ccb);

				}

				if ( FileSize.QuadPart > Fcb->Header.AllocationSize.QuadPart ) 
				{

					X70FsdPopUpFileCorrupt( IrpContext, Fcb );

					X70FsdRaiseStatus( IrpContext, STATUS_FILE_CORRUPT_ERROR );
				}


				CcInitializeCacheMap(
					FileObject,
					(PCC_FILE_SIZES)&Header->AllocationSize,
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

			//如果写入的时候大小超过了有效数据范围我们需要清0
			LlTemp1 = StartingByte.QuadPart - ValidDataLength.QuadPart;

			if ( LlTemp1 > 0 )
			{
				if ( !X70FsdZeroData( 
					IrpContext,
					Fcb,
					FileObject,
					ValidDataLength.QuadPart,
					LlTemp1 ,
					volCtx->SectorSize) )
				{

					try_return( PostIrp = TRUE );
				}

			}

			WriteFileSizeToDirent = BooleanFlagOn(IrpContext->Flags,IRP_CONTEXT_FLAG_WRITE_THROUGH);

			if(Fcb->CacheType == CACHE_READ && CcIsFileCached(FileObject))
			{
				Fcb->CacheType = CACHE_DISABLE;
			}

			if(Fcb->CacheType == CACHE_READWRITE) //可以用缓存
			{
				if (!FlagOn(IrpContext->MinorFunction, IRP_MN_MDL)) 
				{

					SystemBuffer = X70FsdMapUserBuffer( Data );

					if (!CcCopyWrite( FileObject,
						(PLARGE_INTEGER)&StartingByte,
						(ULONG)ByteCount,
						BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT),
						SystemBuffer ))
					{

						try_return( PostIrp = TRUE );

					}

					Data->IoStatus.Status = STATUS_SUCCESS;
					Data->IoStatus.Information = (ULONG)ByteCount;

					try_return( Status = STATUS_SUCCESS );

				} 
				else 
				{

					ASSERT( FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT) );

					CcPrepareMdlWrite( FileObject,
						(PLARGE_INTEGER)&StartingByte,
						(ULONG)ByteCount,
						&Iopb->Parameters.Write.MdlAddress,
						&Data->IoStatus );

					Status = Data->IoStatus.Status;

					ASSERT( NT_SUCCESS( Status ));

					try_return( Status );
				}
			}
			else //按照16字节对齐来写,写之前先读一下文件内的内容
			{
				LARGE_INTEGER NewByteOffset;
				ULONG WriteLen = ByteCount;	
				PUCHAR newBuf = NULL;
				ULONG_PTR RetBytes;
				ULONG_PTR i;
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

				if(Fcb->IsEnFile) //对齐数据
				{
					LessenOffset = StartingByte.QuadPart % CRYPT_UNIT;
					NewByteOffset.QuadPart = NewByteOffset.QuadPart - LessenOffset;
					WriteLen += LessenOffset;
					WriteLen = (ULONG)ROUND_TO_SIZE(WriteLen,CRYPT_UNIT);
					NewByteOffset.QuadPart += Fcb->FileHeaderLength;


					newBuf = FltAllocatePoolAlignedWithTag(FltObjects->Instance,NonPagedPool,WriteLen,'wn');

					if(newBuf == NULL)
					{
						try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
					}
					RtlZeroMemory(newBuf,WriteLen);

					//读文件然后拷贝

					{
#ifdef CHANGE_TOP_IRP

						PIRP TopLevelIrp = IoGetTopLevelIrp();
						IoSetTopLevelIrp(NULL);		
#endif
						RetNewCallbackData->Iopb->MajorFunction = IRP_MJ_READ;

						RetNewCallbackData->Iopb->Parameters.Read.ByteOffset = NewByteOffset;
						RetNewCallbackData->Iopb->Parameters.Read.Length = WriteLen;
						RetNewCallbackData->Iopb->Parameters.Read.ReadBuffer = newBuf;
						RetNewCallbackData->Iopb->TargetFileObject =  Ccb->StreamFileInfo.StreamObject;

						FltPerformSynchronousIo(RetNewCallbackData);

						Status = RetNewCallbackData->IoStatus.Status;
						RetBytes = RetNewCallbackData->IoStatus.Information;

#ifdef	CHANGE_TOP_IRP
						IoSetTopLevelIrp(TopLevelIrp);
#endif
					}

					for(i = 0 ; i < RetBytes/CRYPT_UNIT ; i++)
					{
						aes_ecb_decrypt(Add2Ptr(newBuf,i*CRYPT_UNIT),Add2Ptr(newBuf,i*CRYPT_UNIT),&Fcb->CryptionKey);
					}

					RtlCopyMemory(Add2Ptr(newBuf,LessenOffset),SystemBuffer,ByteCount); 

					for(i = 0 ; i < WriteLen/CRYPT_UNIT ; i++)
					{
						aes_ecb_encrypt(Add2Ptr(newBuf,i*CRYPT_UNIT),Add2Ptr(newBuf,i*CRYPT_UNIT),&Fcb->CryptionKey);
					}


					FltReuseCallbackData(RetNewCallbackData);
				}
				//向下层发出对应的写请求
				{
#ifdef CHANGE_TOP_IRP

					PIRP TopLevelIrp = IoGetTopLevelIrp();
					IoSetTopLevelIrp(NULL);		
#endif
					RetNewCallbackData->Iopb->MajorFunction = IRP_MJ_WRITE;

					RetNewCallbackData->Iopb->Parameters.Write.ByteOffset = (Fcb->IsEnFile ? NewByteOffset : StartingByte);
					RetNewCallbackData->Iopb->Parameters.Write.Length = WriteLen;
					RetNewCallbackData->Iopb->Parameters.Write.WriteBuffer = (Fcb->IsEnFile ? newBuf : SystemBuffer);
					RetNewCallbackData->Iopb->TargetFileObject =  Ccb->StreamFileInfo.StreamObject;
					SetFlag( RetNewCallbackData->Iopb->IrpFlags, Data->Iopb->IrpFlags );

					FltPerformSynchronousIo(RetNewCallbackData);

					Status = RetNewCallbackData->IoStatus.Status;
					RetBytes = RetNewCallbackData->IoStatus.Information;

#ifdef	CHANGE_TOP_IRP
					IoSetTopLevelIrp(TopLevelIrp);
#endif
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
					X70FsdLookupFileAllocationSize( IrpContext, Fcb ,Ccb);
				}

				if ( FileSize.QuadPart > Fcb->Header.AllocationSize.QuadPart ) 
				{

					X70FsdPopUpFileCorrupt( IrpContext, Fcb );

					X70FsdRaiseStatus( IrpContext, STATUS_FILE_CORRUPT_ERROR );
				}


				CcInitializeCacheMap(
					FileObject,
					(PCC_FILE_SIZES)&Header->AllocationSize,
					FALSE,
					&G_CacheMgrCallbacks,
					Fcb
					);

				CcSetReadAheadGranularity( FileObject, READ_AHEAD_GRANULARITY );
				//CcSetAdditionalCacheAttributes(FileObject,TRUE,TRUE);
				Fcb->CacheObject = FileObject;

			}

			//如果写入的时候大小超过了有效数据范围我们需要清0
			LlTemp1 = StartingByte.QuadPart - ValidDataLength.QuadPart;

			if ( LlTemp1 > 0 )
			{
				if ( !X70FsdZeroData( 
					IrpContext,
					Fcb,
					FileObject,
					ValidDataLength.QuadPart,
					LlTemp1 ,
					volCtx->SectorSize) )
				{

					try_return( PostIrp = TRUE );
				}

			}
			WriteFileSizeToDirent = BooleanFlagOn(IrpContext->Flags,IRP_CONTEXT_FLAG_WRITE_THROUGH);

			if (!FlagOn(IrpContext->MinorFunction, IRP_MN_MDL)) 
			{

				SystemBuffer = X70FsdMapUserBuffer( Data );

				if (!CcCopyWrite( FileObject,
					(PLARGE_INTEGER)&StartingByte,
					(ULONG)ByteCount,
					BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT),
					SystemBuffer ))
				{

					try_return( PostIrp = TRUE );

				}

				Data->IoStatus.Status = STATUS_SUCCESS;
				Data->IoStatus.Information = (ULONG)ByteCount;

				try_return( Status = STATUS_SUCCESS );

			} 
			else 
			{

				ASSERT( FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT) );

				CcPrepareMdlWrite( FileObject,
					(PLARGE_INTEGER)&StartingByte,
					(ULONG)ByteCount,
					&Iopb->Parameters.Write.MdlAddress,
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
				ULONG ActualBytesWrote;

				ActualBytesWrote = (ULONG)Data->IoStatus.Information;

				if ( SynchronousIo && !PagingIo )
				{
					FileObject->CurrentByteOffset.QuadPart = StartingByte.QuadPart + ActualBytesWrote;
				}

				if ( NT_SUCCESS(Status) )
				{
					if ( !PagingIo )
					{
						SetFlag( FileObject->Flags, FO_FILE_MODIFIED );
					}

					if ( ExtendingFile && !WriteFileSizeToDirent ) 
					{
						SetFlag( FileObject->Flags, FO_FILE_SIZE_CHANGED );
					}

					if ( ExtendingValidData ) 
					{

						LARGE_INTEGER EndingVboWritten;
						EndingVboWritten.QuadPart = StartingByte.QuadPart + ActualBytesWrote;

						if ( FileSize.QuadPart < EndingVboWritten.QuadPart ) 
						{

							Fcb->Header.ValidDataLength.QuadPart = FileSize.QuadPart;

						} 
						else 
						{

							Fcb->Header.ValidDataLength.QuadPart = EndingVboWritten.QuadPart;
						}

						if (NonCachedIo && CcIsFileCached(FileObject))  //更新下缓存中的记录
						{
							CcSetFileSizes( FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize );
						}
					}
				}

			}

			else 
			{
				if (!OplockPostIrp) 
				{
					if ( ExtendingFile ) 
					{

						if ( Fcb->Header.PagingIoResource != NULL ) {

							(VOID)ExAcquireResourceExclusiveLite(Fcb->Header.PagingIoResource, TRUE);
						}

						Fcb->Header.FileSize.QuadPart = InitialFileSize.QuadPart;

						if (FileObject->SectionObjectPointer->SharedCacheMap != NULL) {

							CcGetFileSizePointer(FileObject)->QuadPart = Fcb->Header.FileSize.QuadPart;
						}

						if ( Fcb->Header.PagingIoResource != NULL ) {

							ExReleaseResourceLite( Fcb->Header.PagingIoResource );
						}
					}

					Status = X70FsdPostRequest(Data, IrpContext );

				}

			}
		}

	}
	finally
	{

		if (AbnormalTermination()) 
		{

			PERESOURCE PagingIoResource = NULL;

			if (ExtendingFile || ExtendingValidData) 
			{

				Fcb->Header.FileSize.QuadPart = InitialFileSize.QuadPart;
				Fcb->Header.ValidDataLength.QuadPart = InitialValidDataLength.QuadPart;

				if (FileObject->SectionObjectPointer->SharedCacheMap != NULL) 
				{
					CcGetFileSizePointer(FileObject)->QuadPart = Fcb->Header.FileSize.QuadPart;
				}
			}
		}

		if (UnwindOutstandingAsync) 
		{

			ExInterlockedAddUlong( &Fcb->OutstandingAsyncWrites,
				0xffffffff,
				&GeneralSpinLock );
		}
		if(!NonCachedIoPending)
		{
			if (ScbAcquired ) 
			{

				X70FsdReleaseFcb( NULL, Fcb );
			}

			if (PagingIoResourceAcquired ) 
			{

				ExReleaseResourceLite( Fcb->Header.PagingIoResource );
			}

			if ( FOResourceAcquired )
			{
				ExReleaseResourceLite( Ccb->StreamFileInfo.FO_Resource );
			}

			if(EncryptResourceAcquired)
			{
				ExReleaseResourceLite( Fcb->EncryptResource );
			}		
		}

		if(volCtx != NULL)
		{
			FltReleaseContext(volCtx);
			volCtx = NULL;
		}
		
		if(!NT_SUCCESS(Status))
		{

		}
		else
		{
			SetFlag(Ccb->CcbState,CCB_FLAG_FILE_CHANGED);
		}
		if(Status == STATUS_FILE_CLOSED)
		{

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

		if(!PostIrp && !AbnormalTermination())
		{
			X70FsdCompleteRequest(&IrpContext,&Data,Data->IoStatus.Status,FALSE);
		}

	}
	return FltStatus;
}

VOID WriteFileAsyncCompletionRoutine(
									 IN PFLT_CALLBACK_DATA CallbackData,
									 IN PFLT_CONTEXT Context
									 )
{

	PLAYERFSD_IO_CONTEXT X70FsdIoContext = (PLAYERFSD_IO_CONTEXT)Context;

	PERESOURCE Resource  = X70FsdIoContext->Wait.Async.Resource;

	PERESOURCE Resource2  = X70FsdIoContext->Wait.Async.Resource2;

	PERESOURCE FO_Resource  = X70FsdIoContext->Wait.Async.FO_Resource;

	ERESOURCE_THREAD ResourceThreadId = X70FsdIoContext->Wait.Async.ResourceThreadId;

	PVOLUME_CONTEXT volCtx = X70FsdIoContext->volCtx;

	PFLT_CALLBACK_DATA Data = X70FsdIoContext->Data;

	PFILE_OBJECT FileObject = X70FsdIoContext->Wait.Async.FileObject;

	PFCB Fcb = (PFCB)FileObject->FsContext;

	PFAST_MUTEX pFileObjectMutex = X70FsdIoContext->Wait.Async.pFileObjectMutex;

	LONGLONG EndByteOffset = 0;

	ULONG ByteCount = X70FsdIoContext->Wait.Async.RequestedByteCount;

	ULONG_PTR RetBytes = CallbackData->IoStatus.Information ;

	PIRP TopLevelIrp = X70FsdIoContext->TopLevelIrp;

	EndByteOffset = X70FsdIoContext->ByteOffset.QuadPart + 
		ByteCount;

	Data->IoStatus.Status = CallbackData->IoStatus.Status;

	if ( NT_SUCCESS(Data->IoStatus.Status) )
	{

		if ( !X70FsdIoContext->PagingIo )
		{
			SetFlag( FileObject->Flags, FO_FILE_MODIFIED );
		}

	}

	Data->IoStatus.Information =  (RetBytes < ByteCount)? RetBytes:ByteCount;

	if ((X70FsdIoContext->Wait.Async.OutstandingAsyncEvent != NULL) &&
		(ExInterlockedAddUlong( X70FsdIoContext->Wait.Async.OutstandingAsyncWrites,
		0xffffffff,
		&GeneralSpinLock ) == 1)) 
	{
		KeSetEvent( X70FsdIoContext->Wait.Async.OutstandingAsyncEvent, 0, FALSE );
	}

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
	FltFreeCallbackData(CallbackData);

	if(X70FsdIoContext->SwapMdl != NULL)
	{
		IoFreeMdl(X70FsdIoContext->SwapMdl);
	}

	FltFreePoolAlignedWithTag(X70FsdIoContext->Instance,X70FsdIoContext->SwapBuffer,'rn');

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
	FltCompletePendedPreOperation(Data,FLT_PREOP_COMPLETE,NULL);

	return ;

}


//真正的写文件
NTSTATUS RealWriteFile(
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

	ULONG IrpFlags = IRP_WRITE_OPERATION;

#ifndef USE_CACHE_READWRITE
	SetFlag(IrpFlags,IRP_NOCACHE);
#endif

	Status = FltAllocateCallbackData(FltObjects->Instance,FileObject,&RetNewCallbackData);

	if(NT_SUCCESS(Status))
	{
#ifdef CHANGE_TOP_IRP

		PIRP TopLevelIrp = IoGetTopLevelIrp();

		IoSetTopLevelIrp(NULL);
#endif	

		RetNewCallbackData->Iopb->MajorFunction = IRP_MJ_WRITE;

		RetNewCallbackData->Iopb->Parameters.Write.ByteOffset = ByteOffset;
		RetNewCallbackData->Iopb->Parameters.Write.Length = ByteCount;
		RetNewCallbackData->Iopb->Parameters.Write.WriteBuffer = SystemBuffer;

		//RetNewCallbackData->Iopb->Parameters.Write.MdlAddress = IrpContext->X70FsdIoContext->SwapMdl;

		RetNewCallbackData->Iopb->TargetFileObject = FileObject;
		/*SetFlag( RetNewCallbackData->Iopb->IrpFlags, IRP_WRITE_OPERATION );*/
		SetFlag( RetNewCallbackData->Iopb->IrpFlags, IrpFlags );

		if(Wait)
		{
			SetFlag( RetNewCallbackData->Iopb->IrpFlags,IRP_SYNCHRONOUS_API);
			FltPerformSynchronousIo(RetNewCallbackData);

			Status = RetNewCallbackData->IoStatus.Status;
			*RetBytes = RetNewCallbackData->IoStatus.Information;


			//直接解密取出来的数据
		}
		else
		{

			Status = FltPerformAsynchronousIo(RetNewCallbackData,WriteFileAsyncCompletionRoutine,IrpContext->X70FsdIoContext);
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
