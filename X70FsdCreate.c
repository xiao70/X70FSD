/*
驱动暂时用hashtable来做fcb的存贮，以后准备换成splay tree
*/

#include"X70FSDCreate.h"
#include"X70FsdData.h"
#include"X70FsdSupport.h"
#include"X70FsdInterface.h"
extern LARGE_INTEGER  Li0;

extern NPAGED_LOOKASIDE_LIST  G_FcbLookasideList;
extern NPAGED_LOOKASIDE_LIST  G_CcbLookasideList;
extern NPAGED_LOOKASIDE_LIST  G_EResourceLookasideList;

extern USHORT gOsServicePackMajor;
extern ULONG gOsMajorVersion;
extern ULONG gOsMinorVersion;

extern DYNAMIC_FUNCTION_POINTERS gDynamicFunctions;

//#define MAX_NTFS_METADATA_FILE 11
//WCHAR *NtfsMetadataFileNames[] = {
//	L"$Mft",
//	L"$MftMirr",
//	L"$LogFile",
//	L"$Volume",
//	L"$AttrDef",
//	L"$Root",
//	L"$Bitmap",
//	L"$Boot",
//	L"$BadClus",
//	L"$Secure",
//	L"$UpCase",
//	L"$Extend"
//}; //NTFS元数据不能加密

BOOLEAN IsConcernedProcess( PCFLT_RELATED_OBJECTS FltObjects,PNTSTATUS pStatus,PULONG ProcType)
{
	PEPROCESS Eprocess = NULL;
	HANDLE Pid;
	BOOLEAN bParentProcessLicense = FALSE;
	*pStatus = STATUS_SUCCESS;

	return IsTestProcess(pStatus,ProcType);

}

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationNetworkQueryOpen(
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
PtPreOperationNetworkQueryOpen(
							   __inout PFLT_CALLBACK_DATA Data,
							   __in PCFLT_RELATED_OBJECTS FltObjects,
							   __deref_out_opt PVOID *CompletionContext
							   )
{
	ULONG ProcType = 0; 
	NTSTATUS Status;

	if(IsMyFakeFcb(FltObjects->FileObject) || IsConcernedProcess(FltObjects,&Status,&ProcType)) 
	{
		return FLT_PREOP_DISALLOW_FASTIO;
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

BOOLEAN IsConcernedCreateOptions(__inout PFLT_CALLBACK_DATA Data)
{

	PFLT_IO_PARAMETER_BLOCK CONST  Iopb = Data->Iopb;

	ULONG Options = Iopb->Parameters.Create.Options;

	BOOLEAN DirectoryFile = BooleanFlagOn( Options, FILE_DIRECTORY_FILE ); //目录文件

	return !DirectoryFile;

}

#define FILE_OPEN_REQUIRING_OPLOCK              0x00010000

NTSTATUS CreateFileImitation(__inout PFLT_CALLBACK_DATA Data,
							 __in PCFLT_RELATED_OBJECTS FltObjects,
							 __in PUNICODE_STRING FileName,
							 __out PHANDLE phFile,
							 __out PFILE_OBJECT * pFileObject,
							 __out PIO_STATUS_BLOCK  IoStatus,
							 __in  BOOLEAN Network)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES	ob;
	PFLT_IO_PARAMETER_BLOCK CONST  Iopb = Data->Iopb;
	LARGE_INTEGER  AllocationSize ;
	ACCESS_MASK DesiredAccess ;
	ULONG	EaLength;
	PVOID	EaBuffer;
	ULONG	Options;
	ULONG	CreateDisposition;
	ULONG	FileAttributes;
	ULONG	ShareAccess;
	ULONG	Flags = 0;
	PSECURITY_DESCRIPTOR  SecurityDescriptor = NULL;

	UNREFERENCED_PARAMETER( FltObjects );

	SecurityDescriptor		   = Iopb->Parameters.Create.SecurityContext->AccessState->SecurityDescriptor;
	AllocationSize.QuadPart    = Iopb->Parameters.Create.AllocationSize.QuadPart; 

	EaBuffer          = Iopb->Parameters.Create.EaBuffer; 
	DesiredAccess     = Iopb->Parameters.Create.SecurityContext->DesiredAccess ; 
	Options           = Iopb->Parameters.Create.Options;
	FileAttributes    = Iopb->Parameters.Create.FileAttributes; 
	ShareAccess       = Iopb->Parameters.Create.ShareAccess;
	EaLength          = Iopb->Parameters.Create.EaLength;

	if(Network) 
	{
		//SetFlag (ShareAccess ,FILE_SHARE_READ); 
		//SetFlag (DesiredAccess ,FILE_READ_DATA  );

		//SetFlag (DesiredAccess , FILE_WRITE_DATA); //???
		ShareAccess = FILE_SHARE_READ;   //网络文件因为oplock，只能只读，要想解决去参考rdbss.sys
		ClearFlag(DesiredAccess,FILE_WRITE_DATA);
		ClearFlag(DesiredAccess,FILE_APPEND_DATA);

	}
#ifdef USE_CACHE_READWRITE

	SetFlag(Options,FILE_WRITE_THROUGH); //如果缓存写需要加上直接写入文件，否则cccaniwrite内部会导致等待pagingio产生死锁

#endif
	ClearFlag(Options,FILE_OPEN_BY_FILE_ID);
	ClearFlag(Options,FILE_OPEN_REQUIRING_OPLOCK); 

	CreateDisposition = (Options >> 24) & 0x000000ff; 

	InitializeObjectAttributes(&ob, FileName,OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE , NULL,SecurityDescriptor) ; 

	Status = FltCreateFile(FltObjects->Filter, //FltCreateFileEx
		FltObjects->Instance,
		phFile,
		DesiredAccess,
		&ob,
		IoStatus,
		&AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		Options,
		EaBuffer,
		EaLength,
		Flags 
		);
	if(NT_SUCCESS(Status))
	{
		Status = ObReferenceObjectByHandle(*phFile,
			0,
			*IoFileObjectType,
			KernelMode,
			pFileObject,
			NULL);
		if(!NT_SUCCESS(Status))
		{
			FltClose(*phFile);
			*pFileObject = NULL;
		}
	}

	if(!NT_SUCCESS(Status))
	{
		DbgPrint("create false filename %ws \n",FileName->Buffer);
	}

	return Status;
}

NTSTATUS CreateFileByNonExistFcb(__inout PFLT_CALLBACK_DATA Data,
								 __in PCFLT_RELATED_OBJECTS FltObjects,
								 __in PFCB Fcb,
								 __in PIRP_CONTEXT IrpContext,
								 __in PUCHAR	HashValue
								 )
{
	NTSTATUS Status = STATUS_SUCCESS;

	ULONG  Options;
	ULONG  CreateDisposition;

	BOOLEAN bDirectory = FALSE;
	BOOLEAN IsEnFile = FALSE;
	BOOLEAN IsDisEncryptFile = FALSE;

	BOOLEAN NeedOwnFcb = FALSE;
	BOOLEAN OrgEnFile = FALSE;
	BOOLEAN DeleteOnClose = FALSE;
	BOOLEAN NoIntermediateBuffering = FALSE;
	BOOLEAN OpenRequiringOplock;

	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	FLT_PREOP_CALLBACK_STATUS FltOplockStatus;
	PFLT_CALLBACK_DATA OrgData = NULL;

	ACCESS_MASK DesiredAccess ;
	ULONG	ShareAccess;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER FileBeginOffset;

	AllocationSize.QuadPart    = Iopb->Parameters.Create.AllocationSize.QuadPart;

	DesiredAccess     = Iopb->Parameters.Create.SecurityContext->DesiredAccess ; //创建权限加上读取文件的权限
	ShareAccess       = Iopb->Parameters.Create.ShareAccess; //共享权限
	Options           = Iopb->Parameters.Create.Options; //options
	CreateDisposition = (Options >> 24) & 0x000000ff; 

	OpenRequiringOplock     = BooleanFlagOn( Options, FILE_OPEN_REQUIRING_OPLOCK );
	DeleteOnClose = BooleanFlagOn(Options, FILE_DELETE_ON_CLOSE);
	NoIntermediateBuffering = BooleanFlagOn( Options, FILE_NO_INTERMEDIATE_BUFFERING );

	if(IrpContext->OriginatingData != NULL)
	{
		OrgData = IrpContext->OriginatingData;
	}
	else
	{
		OrgData = Data;
	}

	IrpContext->FltStatus = FLT_PREOP_COMPLETE;

	try{

		Status = CreateFileImitation(Data,
			FltObjects,
			&IrpContext->CreateInfo.nameInfo->Name,
			&IrpContext->CreateInfo.StreamHandle,
			&IrpContext->CreateInfo.StreamObject,
			&Data->IoStatus,
			IrpContext->CreateInfo.Network
			); //模仿上层打开这个文件

		if(!NT_SUCCESS(Status)) 
		{
			if(Status == STATUS_FILE_IS_A_DIRECTORY)
			{
				try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
			}
			else
			{
				Data->IoStatus.Status = Status;
				try_return(IrpContext->FltStatus = FLT_PREOP_COMPLETE);
			}
		}


		IrpContext->CreateInfo.Information = Data->IoStatus.Information;

		Status = MyGetFileStandardInfo(Data, 
			FltObjects,
			IrpContext->CreateInfo.StreamObject, 
			&IrpContext->CreateInfo.FileAllocationSize, 
			&IrpContext->CreateInfo.FileSize, 
			&bDirectory); //这里还不能用FltObject中的文件对象

		if (!NT_SUCCESS(Status) || bDirectory)//失败了返回失败
		{		
			try_return(IrpContext->FltStatus = (bDirectory ? FLT_PREOP_SUCCESS_NO_CALLBACK : FLT_PREOP_COMPLETE));
		}
		
		//这里可以通知应用层文件创建请求，应用层判断是否加密
		
		Status = CreatedFileHeaderInfo(IrpContext);

		if(!NT_SUCCESS(Status))
		{
			Data->IoStatus.Status = Status;
			try_return(IrpContext->FltStatus = FLT_PREOP_COMPLETE);
		}

		if( IrpContext->CreateInfo.FileAccess == FILE_NO_ACCESS )
		{
			Status = STATUS_ACCESS_DENIED;
			try_return(Status);
		}
		if( IrpContext->CreateInfo.FileAccess == FILE_ONLY_READ &&
			(BooleanFlagOn(DesiredAccess,FILE_WRITE_DATA) || 
			BooleanFlagOn(DesiredAccess,FILE_APPEND_DATA)))
		{
			Status = STATUS_ACCESS_DENIED;		
			try_return(Status);
		}
		IrpContext->CreateInfo.DeleteOnClose = DeleteOnClose;

		Status = CreateFcbAndCcb(Data,FltObjects,IrpContext,HashValue);

		if(NT_SUCCESS(Status))
		{
			PCCB  Ccb;
			Fcb = IrpContext->CreateInfo.Fcb;
			Ccb = IrpContext->CreateInfo.Ccb;

			if(IS_WINDOWS7() || IS_WINDOWS7_LATER())
			{
				FltOplockStatus = gDynamicFunctions.CheckOplockEx( &Fcb->Oplock,
					OrgData,
					OPLOCK_FLAG_OPLOCK_KEY_CHECK_ONLY,
					NULL,
					NULL,
					NULL );

				if(FltOplockStatus == FLT_PREOP_COMPLETE)
				{
					try_return( Status = OrgData->IoStatus.Status);
				}

				if (OpenRequiringOplock) 
				{

					FltOplockStatus = FltOplockFsctrl( &Fcb->Oplock,
						OrgData,
						(Fcb->OpenHandleCount) );

					if(OrgData->IoStatus.Status != STATUS_SUCCESS &&
						OrgData->IoStatus.Status != STATUS_OPLOCK_BREAK_IN_PROGRESS)
					{
						X70FsdRaiseStatus( IrpContext, OrgData->IoStatus.Status);
					}
				}

			}

			FileObject->FsContext = Fcb;
			FileObject->SectionObjectPointer = &Fcb->SectionObjectPointers;
			FileObject->Vpb = IrpContext->CreateInfo.StreamObject->Vpb;
			FileObject->FsContext2 = Ccb;
	
			SetFlag(FileObject->Flags,FO_WRITE_THROUGH);

			IoSetShareAccess(
				DesiredAccess,
				ShareAccess,
				FileObject,
				&Fcb->ShareAccess
				);

			InterlockedIncrement((PLONG)&Fcb->ReferenceCount);	

			InterlockedIncrement((PLONG)&Fcb->OpenHandleCount);	

			if ( FlagOn( FileObject->Flags, FO_NO_INTERMEDIATE_BUFFERING ) )
			{
				InterlockedIncrement((PLONG)&Fcb->NonCachedCleanupCount);	
			}


			if(IrpContext->CreateInfo.DeleteOnClose)
			{
				SetFlag(Fcb->FcbState,SCB_STATE_DELETE_ON_CLOSE);
			}

			if( CreateDisposition == FILE_SUPERSEDE ||
				CreateDisposition == FILE_OVERWRITE || 
				CreateDisposition == FILE_OVERWRITE_IF )
			{
				Status = X70FsdOverWriteFile(FileObject,Fcb,AllocationSize);
			}

			if(!NoIntermediateBuffering)
			{
				FileObject->Flags |= FO_CACHE_SUPPORTED;
			}

		}
		try_return(Status);

try_exit: NOTHING;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

		PFCB Fcb = FileObject->FsContext;
		PCCB Ccb = FileObject->FsContext2;

		Status = GetExceptionCode();
		IrpContext->CreateInfo.ReissueIo = FALSE; 
		IrpContext->FltStatus = FLT_PREOP_COMPLETE;

		if(Fcb != NULL)
		{
			X70FsdFreeFcb(Fcb,IrpContext);
			FileObject->FsContext = NULL;
		}
		if(Ccb != NULL)
		{
			if(Ccb->StreamFileInfo.FO_Resource != NULL)
			{
				ExDeleteResourceLite(Ccb->StreamFileInfo.FO_Resource);
				ExFreeToNPagedLookasideList(&G_EResourceLookasideList,Ccb->StreamFileInfo.FO_Resource);
				Ccb->StreamFileInfo.FO_Resource = NULL;
			}
			ExFreeToNPagedLookasideList(&G_CcbLookasideList,Ccb);
			FileObject->FsContext2 = NULL;
		}

	}

	return Status;
}

NTSTATUS CreateFileByExistFcb(__inout PFLT_CALLBACK_DATA Data,
							  __in PCFLT_RELATED_OBJECTS FltObjects,
							  __in PFCB Fcb,
							  __in PIRP_CONTEXT IrpContext)
{
	NTSTATUS Status = STATUS_SUCCESS;
	BOOLEAN Flag;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	PFLT_IO_PARAMETER_BLOCK CONST  Iopb = Data->Iopb;
	LARGE_INTEGER  AllocationSize ;
	FLT_PREOP_CALLBACK_STATUS FltOplockStatus;

	PCCB Ccb = NULL;

	ACCESS_MASK DesiredAccess ;
	ULONG  EaLength;
	PVOID  EaBuffer;
	ULONG  Options;
	ULONG  CreateDisposition;
	ULONG	FileAttributes;
	ULONG	ShareAccess;

	BOOLEAN NoEaKnowledge;
	BOOLEAN DeleteOnClose;
	BOOLEAN NoIntermediateBuffering;
	BOOLEAN TemporaryFile;
	BOOLEAN bDirectory = FALSE;
	BOOLEAN OpenRequiringOplock = FALSE;

	BOOLEAN DecrementFcbOpenCount = FALSE;
	BOOLEAN RemoveShareAccess = FALSE;
	BOOLEAN AcquiredPagingResource = FALSE;
	PACCESS_MASK DesiredAccessPtr;
	PIO_SECURITY_CONTEXT  SecurityContext;
	PFLT_CALLBACK_DATA OrgData = NULL;

	ACCESS_MASK PreDesiredAccess;

	BOOLEAN FcbAcquired = FALSE;
	BOOLEAN FsRtlHeaderLocked = TRUE;
	BOOLEAN EncryptResourceAcquired = FALSE;
	UNREFERENCED_PARAMETER( FltObjects );

	AllocationSize.QuadPart    = Iopb->Parameters.Create.AllocationSize.QuadPart;

	EaBuffer          = Iopb->Parameters.Create.EaBuffer;  
	DesiredAccess     = Iopb->Parameters.Create.SecurityContext->DesiredAccess ; 
	DesiredAccessPtr  = &Iopb->Parameters.Create.SecurityContext->DesiredAccess;
	SecurityContext	  = Iopb->Parameters.Create.SecurityContext;
	Options           = Iopb->Parameters.Create.Options;
	FileAttributes    = Iopb->Parameters.Create.FileAttributes; 
	ShareAccess       = Iopb->Parameters.Create.ShareAccess; 
	EaLength          = Iopb->Parameters.Create.EaLength;

	CreateDisposition = (Options >> 24) & 0x000000ff; 
	SecurityContext = Iopb->Parameters.Create.SecurityContext;
	PreDesiredAccess = DesiredAccess;

	OpenRequiringOplock = BooleanFlagOn( Options, FILE_OPEN_REQUIRING_OPLOCK );
	NoEaKnowledge = BooleanFlagOn(Options, FILE_NO_EA_KNOWLEDGE);
	DeleteOnClose = BooleanFlagOn(Options, FILE_DELETE_ON_CLOSE);
	NoIntermediateBuffering = BooleanFlagOn( Options, FILE_NO_INTERMEDIATE_BUFFERING );
	TemporaryFile = BooleanFlagOn(FileAttributes, FILE_ATTRIBUTE_TEMPORARY);

	IrpContext->FltStatus = FLT_PREOP_COMPLETE;

	if(IrpContext->OriginatingData != NULL)
	{
		OrgData = IrpContext->OriginatingData;
	}
	else
	{
		OrgData = Data;
	}

	try
	{
		(VOID)X70FsdAcquireExclusiveFcb( IrpContext, Fcb );
		FcbAcquired = TRUE;

		ExAcquireResourceExclusiveLite(Fcb->EncryptResource,TRUE);
		EncryptResourceAcquired = TRUE;

		if (FlagOn( Fcb->FcbState, SCB_STATE_DELETE_ON_CLOSE ) && Fcb->OpenHandleCount != 0) 
		{
			try_return( Status = STATUS_DELETE_PENDING );
		}

		IrpContext->CreateInfo.OplockPostIrp = FALSE;

		if(IS_WINDOWS7() || IS_WINDOWS7_LATER())
		{
			FltOplockStatus = gDynamicFunctions.CheckOplockEx( &Fcb->Oplock,
				OrgData,
				OPLOCK_FLAG_OPLOCK_KEY_CHECK_ONLY,
				NULL,
				NULL,
				NULL );

			if(FltOplockStatus == FLT_PREOP_COMPLETE)
			{
				try_return( Status = OrgData->IoStatus.Status);
			}
		}

		if (FltCurrentBatchOplock( &Fcb->Oplock )) 
		{

			Data->IoStatus.Information = FILE_OPBATCH_BREAK_UNDERWAY;

			FltOplockStatus = FltCheckOplock( &Fcb->Oplock,
				OrgData,
				IrpContext,
				X70FsdOplockComplete,
				X70FsdPrePostIrp );

			if (FLT_PREOP_PENDING == FltOplockStatus) 
			{
				Status = STATUS_PENDING;
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				IrpContext->CreateInfo.OplockPostIrp = TRUE;
				try_return( Status );
			}
			if(FltOplockStatus == FLT_PREOP_COMPLETE)
			{
				try_return( Status = OrgData->IoStatus.Status);
			}

		}
		if (CreateDisposition == FILE_CREATE && Fcb->OpenHandleCount != 0) 
		{
			Status = STATUS_OBJECT_NAME_COLLISION;
			try_return( Status );
		}
		else if (CreateDisposition == FILE_OVERWRITE || 
			CreateDisposition == FILE_OVERWRITE_IF )
		{

			SetFlag( DesiredAccess, FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_WRITE_DATA );

		}
		else if ( CreateDisposition == FILE_SUPERSEDE  )
		{
			SetFlag( DesiredAccess, DELETE );
		}

		if (!NT_SUCCESS(Status = IoCheckShareAccess( DesiredAccess,
			ShareAccess,
			FileObject,
			&Fcb->ShareAccess,
			FALSE ))) 
		{
			if(IS_WINDOWS7() || IS_WINDOWS7_LATER())
			{

				if ((Status == STATUS_SHARING_VIOLATION) &&
					!FlagOn( OrgData->Iopb->Parameters.Create.Options, FILE_COMPLETE_IF_OPLOCKED )) 
				{

					FltOplockStatus = gDynamicFunctions.OplockBreakH( &Fcb->Oplock,
						OrgData,
						0,
						IrpContext,
						X70FsdOplockComplete,
						X70FsdPrePostIrp );

					if (FltOplockStatus == FLT_PREOP_PENDING) {

						Status = STATUS_PENDING;
						IrpContext->FltStatus = FLT_PREOP_PENDING;
						IrpContext->CreateInfo.OplockPostIrp = TRUE;
						try_return( Status );

					}
					if(FltOplockStatus == FLT_PREOP_COMPLETE)
					{
						try_return( Status = OrgData->IoStatus.Status);
					}
					else 
					{
						try_return( Status = STATUS_SHARING_VIOLATION );
					}

				} 

			}
			try_return( Status );
		}
		if(IS_WINDOWS7() || IS_WINDOWS7_LATER())
		{
			if (Fcb->OpenHandleCount != 0) 
			{

				FltOplockStatus = FltCheckOplock( &Fcb->Oplock,
					OrgData,
					IrpContext,
					X70FsdOplockComplete,
					X70FsdPrePostIrp );

			}

			if (FltOplockStatus == FLT_PREOP_PENDING) 
			{
				Status = STATUS_PENDING;
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				IrpContext->CreateInfo.OplockPostIrp = TRUE;
				try_return( Status );

			}
			if(FltOplockStatus == FLT_PREOP_COMPLETE)
			{
				try_return( Status = OrgData->IoStatus.Status);
			}
			if (OpenRequiringOplock ) 
			{

				FltOplockStatus = FltOplockFsctrl( &Fcb->Oplock,
					OrgData,
					Fcb->OpenHandleCount );

				if(OrgData->IoStatus.Status != STATUS_SUCCESS &&
					OrgData->IoStatus.Status != STATUS_OPLOCK_BREAK_IN_PROGRESS)
				{
					try_return( Status = OrgData->IoStatus.Status );
				}
			}	
		}
		else
		{
			FltOplockStatus = FltCheckOplock( &Fcb->Oplock,
				OrgData,
				IrpContext,
				X70FsdOplockComplete,
				X70FsdPrePostIrp );

			if (FltOplockStatus == FLT_PREOP_PENDING) 
			{
				Status = STATUS_PENDING;
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				IrpContext->CreateInfo.OplockPostIrp = TRUE;
				try_return( Status );

			}
			if(FltOplockStatus == FLT_PREOP_COMPLETE)
			{
				try_return( Status = OrgData->IoStatus.Status);
			}
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

		Flag = FALSE;

		if (FlagOn(DesiredAccess, FILE_WRITE_DATA) || DeleteOnClose) 
		{

			InterlockedIncrement((PLONG)&Fcb->ReferenceCount);
			DecrementFcbOpenCount = TRUE;

			if (!MmFlushImageSection( &Fcb->SectionObjectPointers,
				MmFlushForWrite )) 
			{

				Status = ( DeleteOnClose ? STATUS_CANNOT_DELETE : STATUS_SHARING_VIOLATION );

				try_return( Status );
			}

		}

		if ( FlagOn(FileObject->Flags, FO_NO_INTERMEDIATE_BUFFERING) &&
			(Fcb->SectionObjectPointers.DataSectionObject != NULL))//先刷新缓存 //见fat create 2932
		{
			CcFlushCache(&Fcb->SectionObjectPointers, NULL, 0, NULL);
			ExAcquireResourceExclusiveLite(Fcb->Header.PagingIoResource, TRUE);
			ExReleaseResourceLite(Fcb->Header.PagingIoResource);
			CcPurgeCacheSection(&Fcb->SectionObjectPointers, NULL, 0, FALSE); 
		}

		if(DeleteOnClose)
		{
			SetFlag(Fcb->FcbState,SCB_STATE_DELETE_ON_CLOSE);
		}

		if ( CreateDisposition == FILE_SUPERSEDE || 
			CreateDisposition == FILE_OVERWRITE || 
			CreateDisposition == FILE_OVERWRITE_IF )
		{

			if(!MmCanFileBeTruncated(&Fcb->SectionObjectPointers, &Li0))
			{
				try_return( Status = STATUS_USER_MAPPED_FILE);
			}
		}

	
		Status = CreateFileImitation(Data,
			FltObjects,
			&IrpContext->CreateInfo.nameInfo->Name,
			&IrpContext->CreateInfo.StreamHandle,
			&IrpContext->CreateInfo.StreamObject,
			&Data->IoStatus,
			IrpContext->CreateInfo.Network
			);

		if(!NT_SUCCESS(Status)) /
		{
			if(Status == STATUS_FILE_IS_A_DIRECTORY)
			{
				try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
			}
			else
			{
				Data->IoStatus.Status = Status;
				try_return(IrpContext->FltStatus = FLT_PREOP_COMPLETE);
			}
		}

		IrpContext->CreateInfo.Information = Data->IoStatus.Information;

		Status = MyGetFileStandardInfo(Data, 
			FltObjects,
			IrpContext->CreateInfo.StreamObject, 
			&IrpContext->CreateInfo.FileAllocationSize, 
			&IrpContext->CreateInfo.FileSize, 
			&bDirectory); 

		if (!NT_SUCCESS(Status) || bDirectory)
		{		
			try_return(IrpContext->FltStatus = (bDirectory ? FLT_PREOP_SUCCESS_NO_CALLBACK : FLT_PREOP_COMPLETE));
		}

		Status = CreatedFileHeaderInfo(IrpContext);

		if(!NT_SUCCESS(Status))
		{
			Data->IoStatus.Status = Status;
			try_return(IrpContext->FltStatus = FLT_PREOP_COMPLETE);
		}

		if( IrpContext->CreateInfo.FileAccess == FILE_NO_ACCESS )
		{

			Status = STATUS_ACCESS_DENIED;
			try_return(Status);
		}
		if( IrpContext->CreateInfo.FileAccess == FILE_ONLY_READ &&
			(BooleanFlagOn(DesiredAccess,FILE_WRITE_DATA) || 
			BooleanFlagOn(DesiredAccess,FILE_APPEND_DATA)) )
		{

			Status = STATUS_ACCESS_DENIED;		
			try_return(Status);
		}

		//写过了加密头
		if(!Fcb->IsEnFile && IrpContext->CreateInfo.IsEnFile)
		{
			Fcb->IsEnFile = IrpContext->CreateInfo.IsEnFile;
			Fcb->FileHeaderLength = FILE_HEADER_LENGTH;
			SetFlag(Fcb->FcbState,SCB_STATE_FILEHEADER_WRITED);
		}
		

		Ccb = X70FsdCreateCcb(); 

		Ccb->StreamFileInfo.StreamHandle = IrpContext->CreateInfo.StreamHandle;
		Ccb->StreamFileInfo.StreamObject = IrpContext->CreateInfo.StreamObject;
		Ccb->StreamFileInfo.FO_Resource = X70FsdAllocateResource();
		Ccb->ProcType = IrpContext->CreateInfo.ProcType;
		Ccb->FileAccess = IrpContext->CreateInfo.FileAccess;
		RtlCopyMemory(Ccb->ProcessGuid,IrpContext->CreateInfo.ProcessGuid,GUID_SIZE);

		if(IrpContext->CreateInfo.Network)
		{
			SetFlag(Ccb->CcbState,CCB_FLAG_NETWORK_FILE);
		}

		ExInitializeFastMutex( &Ccb->StreamFileInfo.FileObjectMutex );

		FileObject->FsContext = Fcb;
		FileObject->SectionObjectPointer = &Fcb->SectionObjectPointers;
		FileObject->Vpb = IrpContext->CreateInfo.StreamObject->Vpb;
		FileObject->FsContext2 = Ccb;

		SetFlag(FileObject->Flags,FO_WRITE_THROUGH);

		if ( CreateDisposition == FILE_SUPERSEDE || 
			CreateDisposition == FILE_OVERWRITE  || 
			CreateDisposition == FILE_OVERWRITE_IF)
		{
			Status = X70FsdOverWriteFile(FileObject,Fcb,AllocationSize);
		}

		if(!NoIntermediateBuffering)
		{
			FileObject->Flags |= FO_CACHE_SUPPORTED;
		}

try_exit: NOTHING;
		if(IrpContext->FltStatus == FLT_PREOP_COMPLETE)
		{
			if ( NT_SUCCESS(Status) &&
				Status != STATUS_PENDING )
			{

				if(FlagOn(Ccb->CcbState,CCB_FLAG_NETWORK_FILE))
				{
					NetFileSetCacheProperty(FileObject,DesiredAccess);
				}

				if ( DesiredAccess != PreDesiredAccess )
				{
					DesiredAccess = PreDesiredAccess;
					Status = IoCheckShareAccess(
						DesiredAccess,
						ShareAccess,
						FileObject,
						&Fcb->ShareAccess,
						TRUE
						);
					ASSERT( Status == STATUS_SUCCESS );
				}
				else
				{
					IoUpdateShareAccess(
						FileObject,
						&Fcb->ShareAccess
						);
				}

				RemoveShareAccess = TRUE;

				if(DeleteOnClose)
				{
					SetFlag(Fcb->FcbState,SCB_STATE_DELETE_ON_CLOSE);
				}

				InterlockedIncrement((PLONG)&Fcb->ReferenceCount);	
				InterlockedIncrement((PLONG)&Fcb->OpenHandleCount);	

				if ( FlagOn( FileObject->Flags, FO_NO_INTERMEDIATE_BUFFERING ) )
				{
					InterlockedIncrement((PLONG)&Fcb->NonCachedCleanupCount);	
				}

			}
		}
	}
	finally 
	{

		if ( DecrementFcbOpenCount )
		{
			InterlockedDecrement((PLONG)&Fcb->ReferenceCount);
		}

		if (AbnormalTermination() )
		{	
			if(RemoveShareAccess )
			{
				IoRemoveShareAccess(
					FileObject,
					&Fcb->ShareAccess
					);
			}
			Status = STATUS_UNSUCCESSFUL;

			Ccb = FileObject->FsContext2;

			if(Ccb != NULL)
			{
				if(Ccb->StreamFileInfo.FO_Resource != NULL)
				{
					ExDeleteResourceLite(Ccb->StreamFileInfo.FO_Resource);
					ExFreeToNPagedLookasideList(&G_EResourceLookasideList,Ccb->StreamFileInfo.FO_Resource);
					Ccb->StreamFileInfo.FO_Resource = NULL;
				}
				ExFreeToNPagedLookasideList(&G_CcbLookasideList,Ccb);
				FileObject->FsContext2 = NULL;
			}
		}

		if(FcbAcquired)
		{
			X70FsdReleaseFcb( IrpContext, Fcb );
		}
		if(EncryptResourceAcquired)
		{
			ExReleaseResourceLite(Fcb->EncryptResource);
		}
	}
	return Status;
}


BOOLEAN IsNeedSelfFcb(__inout PFLT_CALLBACK_DATA Data,PFLT_FILE_NAME_INFORMATION * nameInfo ,PNTSTATUS pStatus)
{

	NTSTATUS Status;
	BOOLEAN IsDirectory = FALSE;
	if(!IsConcernedCreateOptions(Data))
	{
		*pStatus = STATUS_SUCCESS;
		return FALSE; 
	}
	Status = FltIsDirectory(Data->Iopb->TargetFileObject,Data->Iopb->TargetInstance,&IsDirectory);

	if(NT_SUCCESS(Status) && IsDirectory)
	{
		*pStatus = STATUS_SUCCESS;
		return FALSE; 
	}

	Status = FltGetFileNameInformation( Data,
		FLT_FILE_NAME_NORMALIZED |
		FLT_FILE_NAME_QUERY_DEFAULT,
		nameInfo );
	if (!NT_SUCCESS( Status )) 
	{
		Status = FltGetFileNameInformation( Data,
			FLT_FILE_NAME_OPENED |
			FLT_FILE_NAME_QUERY_DEFAULT,
			nameInfo );
		if(!NT_SUCCESS( Status ))
		{
			*pStatus = Status;
			return FALSE;
		}

	}

	Status = FltParseFileNameInformation(*nameInfo);

	if(!NT_SUCCESS( Status ))
	{
		*pStatus = Status;
		return FALSE; 
	}
	//根据得到的文件信息剔除掉打开盘符的操作

	if (0 == (*nameInfo)->Name.Length) 
	{
		*pStatus = STATUS_SUCCESS;
		return FALSE;
	}

	if((*nameInfo)->FinalComponent.Length == 0) //打开的是卷或者目录
	{
		*pStatus = STATUS_SUCCESS;
		return FALSE; 
	}
	if((*nameInfo)->Extension.Length == 0 && (*nameInfo)->Share.Length != 0)
	{
		if((*nameInfo)->Share.Length >= NAMED_PIPE_PREFIX_LENGTH)
		{
			UNICODE_STRING ShareName;

			Status = RtlUpcaseUnicodeString(&ShareName,&(*nameInfo)->Share,TRUE);

			if(!NT_SUCCESS( Status ))
			{
				*pStatus = Status;
				return FALSE; 
			}
			if(NAMED_PIPE_PREFIX_LENGTH == RtlCompareMemory(Add2Ptr(ShareName.Buffer,ShareName.Length - NAMED_PIPE_PREFIX_LENGTH),
				NAMED_PIPE_PREFIX,
				NAMED_PIPE_PREFIX_LENGTH))
			{
				RtlFreeUnicodeString(&ShareName);
				*pStatus = STATUS_SUCCESS;
				return FALSE;
			}

			RtlFreeUnicodeString(&ShareName);
		}
		if((*nameInfo)->Share.Length >= MAIL_SLOT_PREFIX_LENGTH)
		{
			UNICODE_STRING ShareName;

			Status = RtlUpcaseUnicodeString(&ShareName,&(*nameInfo)->Share,TRUE);

			if(!NT_SUCCESS( Status ))
			{
				*pStatus = Status;
				return FALSE; 
			}

			if(MAIL_SLOT_PREFIX_LENGTH == RtlCompareMemory(Add2Ptr(ShareName.Buffer,ShareName.Length - MAIL_SLOT_PREFIX_LENGTH),
				MAIL_SLOT_PREFIX,
				MAIL_SLOT_PREFIX_LENGTH))
			{
				RtlFreeUnicodeString(&ShareName);
				*pStatus = STATUS_SUCCESS;
				return FALSE;
			}

			RtlFreeUnicodeString(&ShareName);
		}
	}
	if((*nameInfo)->Stream.Length != 0) //file stream
	{
		ULONG i;
		for(i = 0 ; i<((*nameInfo)->Stream.Length-sizeof(WCHAR))/2 ; i++)
		{
			if(((*nameInfo)->Stream.Buffer[i] == L':') &&
				((*nameInfo)->Stream.Buffer[i+1] == L'$'))
			{
				DbgPrint("stream create!\n");
				*pStatus = STATUS_SUCCESS;
				return FALSE;
			}
		}
		
		*pStatus = STATUS_SUCCESS;
		return FALSE;  //TRUE?FALSE? 
	}

	return TRUE;	
}


FLT_POSTOP_CALLBACK_STATUS
PtPostOperationCreate (
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
PtPreOperationCreate (
					  __inout PFLT_CALLBACK_DATA Data,
					  __in PCFLT_RELATED_OBJECTS FltObjects,
					  __deref_out_opt PVOID *CompletionContext
					  )
{
	NTSTATUS Status = STATUS_SUCCESS;
	FLT_PREOP_CALLBACK_STATUS	FltStatus = FLT_PREOP_COMPLETE;
	BOOLEAN TopLevel;
	PIRP_CONTEXT IrpContext = NULL;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	ULONG ProcType = 0;
	UCHAR ProcessGuid[GUID_SIZE] = {0};
	PAGED_CODE();        

	if(!IsConcernedProcess(FltObjects,&Status,&ProcType)) 
	{
		if(NT_SUCCESS(Status))
		{
			if(FlagOn(ProcType,PROCESS_ACCESS_DISABLE_EXECUTE))
			{
				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				Data->IoStatus.Information = 0;
				return FLT_PREOP_COMPLETE;
			}
			if(IsMyFakeFcb(FileObject))
			{
				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				Data->IoStatus.Information = 0;
				return FLT_PREOP_COMPLETE;
			}
			else if(IsMyFakeFcb(FileObject->RelatedFileObject))
			{
				PCCB Ccb = NULL;

				Ccb = FileObject->RelatedFileObject->FsContext2;

				if(Ccb != NULL)
				{
					FileObject->RelatedFileObject = Ccb->StreamFileInfo.StreamObject;
				}
				else
				{
					Data->IoStatus.Status = STATUS_ACCESS_DENIED;
					Data->IoStatus.Information = 0;
					return FLT_PREOP_COMPLETE;
				}
			}
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		else
		{
			Data->IoStatus.Status = Status;
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;
		}
	}

	if(FlagOn(ProcType,PROCESS_ACCESS_DISABLE_EXECUTE))
	{
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}

	FsRtlEnterFileSystem();

	if(FLT_IS_IRP_OPERATION(Data)) //irp Write
	{

		TopLevel = X70FsdIsIrpTopLevel( Data );

		try
		{
			IrpContext = X70FsdCreateIrpContext( Data,FltObjects, CanFsdWait( Data ) );
			IrpContext->CreateInfo.ProcType = ProcType;
			FltStatus = X70FsdCommonCreate(Data, FltObjects,IrpContext); //

		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{

			DbgPrint("create exception! \n");
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
		DbgPrint("fastio Create nonsupport\n");
		FltStatus = FLT_PREOP_DISALLOW_FASTIO;

	}
	else
	{
		Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
		Data->IoStatus.Information = 0;
		FltStatus = FLT_PREOP_COMPLETE;
	}

	FsRtlExitFileSystem();
	return FltStatus;
}

FLT_PREOP_CALLBACK_STATUS
X70FsdCommonCreate(
					 __inout PFLT_CALLBACK_DATA Data,
					 __in PCFLT_RELATED_OBJECTS FltObjects,
					 __in PIRP_CONTEXT IrpContext
					 )
{

	NTSTATUS Status = STATUS_SUCCESS;
	IO_STATUS_BLOCK IoStatus = {0};

	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;

	LAYERFSD_FILE_ATTRIBUTES MyFileAttributes;

	BOOLEAN AcquireResource = FALSE;
	PVOLUME_CONTEXT volCtx = NULL;

	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	PFILE_OBJECT FileObject,RelatedFileObject;
	PUNICODE_STRING FileName;

	PERESOURCE FcbResource = NULL;
	BOOLEAN PostIrp = FALSE;
	BOOLEAN bDirectory = FALSE;
	BOOLEAN FOResourceAcquired =FALSE;

	UCHAR HashValue[MD5_LENGTH] = {0};
	PFCB Fcb = NULL;


	if(FltObjects == NULL)
	{
		FltObjects = &IrpContext->FltObjects;
	}

	FileObject = FltObjects->FileObject;

	FileName = &FileObject->FileName;

	RelatedFileObject = FileObject->RelatedFileObject;
	try{
		
		if(Data->RequestorMode == KernelMode) 
		{
			try_return(FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}

		if(FlagOn(Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) 
		{
			try_return(FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}
		if(FlagOn(Iopb->TargetFileObject->Flags, FO_VOLUME_OPEN )) 
		{
			try_return(FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}

		if (!FlagOn( IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT )) 
		{ 

			PostIrp = TRUE;

			DbgPrint("No asynchronous create \n");

			try_return (FltStatus);
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

		if(IsMyFakeFcb(RelatedFileObject)) 
		{
			PCCB Ccb = NULL;
			Ccb = RelatedFileObject->FsContext2;

			if(Ccb != NULL)
			{
				ExAcquireResourceSharedLite(Ccb->StreamFileInfo.FO_Resource,TRUE);
				FOResourceAcquired = TRUE;
				FileObject->RelatedFileObject = Ccb->StreamFileInfo.StreamObject;
			}
			else
			{
				Status = STATUS_ACCESS_DENIED;
				try_return(FltStatus = FLT_PREOP_COMPLETE);
			}
		}

		if(FlagOn(Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY))
		{

			if(IsMyFakeFcb(FileObject))
			{
				Status = STATUS_ACCESS_DENIED;
				try_return(FltStatus = FLT_PREOP_COMPLETE);
			}
			try_return(FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}

		if(!IsNeedSelfFcb( Data,&IrpContext->CreateInfo.nameInfo,&Status)) 
		{
			if(NT_SUCCESS(Status))
			{
				try_return(FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
			}
			else
			{
				Data->IoStatus.Status = Status;
				try_return(FltStatus = FLT_PREOP_COMPLETE);
			}
		}

		if ( FileName->Length > sizeof( WCHAR ) &&
			FileName->Buffer[1] == L'\\' &&
			FileName->Buffer[0] == L'\\' )
		{
			FileName->Length -= sizeof( WCHAR );

			RtlMoveMemory(
				&FileName->Buffer[0],
				&FileName->Buffer[1],
				FileName->Length
				);

			if ( FileName->Length > sizeof( WCHAR ) &&
				FileName->Buffer[1] == L'\\' &&
				FileName->Buffer[0] == L'\\')
			{
				Data->IoStatus.Status = STATUS_OBJECT_NAME_INVALID;
				try_return(FltStatus = FLT_PREOP_COMPLETE);
			}
		}

		ExAcquireResourceExclusiveLite(volCtx->VolResource, TRUE);
		AcquireResource = TRUE;

		if(volCtx->DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
		{
			IrpContext->CreateInfo.Network = TRUE;	//only read！！！！！！
		}

		IrpContext->SectorSize = volCtx->SectorSize;
		IrpContext->SectorsPerAllocationUnit = volCtx->SectorsPerAllocationUnit;

		Status = STATUS_SUCCESS;

		if(!HashFilePath(&IrpContext->CreateInfo.nameInfo->Name,HashValue)) 
		{	
			try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
		}

		if(IsMyFakeFcb(FileObject) || FindExistFcb(HashValue,&Fcb))
		{
			Status = CreateFileByExistFcb(Data, FltObjects,Fcb,IrpContext);

			if(Status == STATUS_PENDING)
			{
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				PostIrp = TRUE;
			}

			try_return(FltStatus = IrpContext->FltStatus);

		}
		else
		{
			Status = CreateFileByNonExistFcb(Data, FltObjects,Fcb,IrpContext,HashValue);

			if(Status == STATUS_PENDING)
			{
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				PostIrp = TRUE;
			}
			try_return(FltStatus = IrpContext->FltStatus);
		}

try_exit:NOTHING;

		if(IrpContext->CreateInfo.ReissueIo)
		{
			FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		else
		{	
			Data->IoStatus.Information = IrpContext->CreateInfo.Information;
		}
	}
	finally
	{

		if(IrpContext->CreateInfo.nameInfo != NULL)
		{
			FltReleaseFileNameInformation(IrpContext->CreateInfo.nameInfo);
		}
		if(FcbResource != NULL)
		{
			ExReleaseResourceLite(FcbResource);
		}
		if(AcquireResource)
		{
			ExReleaseResourceLite(volCtx->VolResource);
		}
		if(FOResourceAcquired)
		{
			PCCB Ccb = RelatedFileObject->FsContext2;

			ExReleaseResourceLite(Ccb->StreamFileInfo.FO_Resource);
		}
		if(volCtx != NULL)
		{
			FltReleaseContext(volCtx);
		}
		//完成上下文

		Data->IoStatus.Status = Status;

		if(!NT_SUCCESS(Status) || FltStatus != FLT_PREOP_COMPLETE )
		{
			if(!NT_SUCCESS(Status) && FltStatus == FLT_PREOP_COMPLETE)
			{

			}
			if(IrpContext->CreateInfo.StreamObject != NULL) //销毁对象跟句柄
			{

				ObDereferenceObject(IrpContext->CreateInfo.StreamObject);
				FltClose(IrpContext->CreateInfo.StreamHandle); 

			}
		}

		if(PostIrp && !IrpContext->CreateInfo.OplockPostIrp)
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

		}
		if(!PostIrp && !AbnormalTermination())
		{
			X70FsdCompleteRequest(&IrpContext,&Data,Data->IoStatus.Status,FALSE);
		}

	}

	return FltStatus;

}
