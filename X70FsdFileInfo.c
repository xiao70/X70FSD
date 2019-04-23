#include "X70FsdData.h"
#include "X70FsdFileInfo.h"
extern CACHE_MANAGER_CALLBACKS  G_CacheMgrCallbacks;
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//完成卷查询接口
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FLT_PREOP_CALLBACK_STATUS
PtPreOperationQueryVolumeInformation (
									  __inout PFLT_CALLBACK_DATA Data,
									  __in PCFLT_RELATED_OBJECTS FltObjects,
									  __deref_out_opt PVOID *CompletionContext
									  )
{
	//用自己的文件对象下发然后完成请求
	NTSTATUS Status;
	PFLT_CALLBACK_DATA RetNewCallbackData = NULL;
	PVOLUME_CONTEXT volCtx = NULL;
	PVOID VolumeBuffer;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	FS_INFORMATION_CLASS FsInformationClass;
	PFILE_OBJECT FileObject;
	PFCB Fcb;
	PCCB Ccb;
	BOOLEAN AcquireResource = FALSE;

	FsRtlEnterFileSystem();
	//
	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	Status = FltGetVolumeContext( FltObjects->Filter,
		FltObjects->Volume,
		&volCtx );

	if(!NT_SUCCESS(Status))
	{
		Data->IoStatus.Status = Status;
		Data->IoStatus.Information = 0;
		FsRtlExitFileSystem();
		return FLT_PREOP_COMPLETE;
	}

	VolumeBuffer = Iopb->Parameters.SetVolumeInformation.VolumeBuffer;
	FsInformationClass = Iopb->Parameters.SetVolumeInformation.FsInformationClass;
	FileObject = FltObjects->FileObject;

	Fcb = (PFCB)FileObject->FsContext;
	Ccb = (PCCB)FileObject->FsContext2;
	try{
		ExAcquireResourceSharedLite(volCtx->VolResource, TRUE);
		AcquireResource = TRUE;

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

			Status = RetNewCallbackData->IoStatus.Status;
			Data->IoStatus = RetNewCallbackData->IoStatus;

			if(NT_SUCCESS(Status))
			{	
				if(FsInformationClass == FileFsSizeInformation) //更新下扇区大小跟簇大小
				{
					volCtx->SectorsPerAllocationUnit = ((PFILE_FS_SIZE_INFORMATION)VolumeBuffer)->SectorsPerAllocationUnit;
					volCtx->SectorSize = ((PFILE_FS_SIZE_INFORMATION)VolumeBuffer)->BytesPerSector;
				}
				if(FsInformationClass == FileFsFullSizeInformation)
				{
					volCtx->SectorsPerAllocationUnit = ((PFILE_FS_FULL_SIZE_INFORMATION)VolumeBuffer)->SectorsPerAllocationUnit;
					volCtx->SectorSize = ((PFILE_FS_FULL_SIZE_INFORMATION)VolumeBuffer)->BytesPerSector;
				}
			}

		}
try_exit:NOTHING;
	}
	finally
	{
		if(RetNewCallbackData != NULL)
		{
			FltFreeCallbackData(RetNewCallbackData);
		}
		if(AcquireResource)
		{
			ExReleaseResourceLite(volCtx->VolResource);
		}

		if(volCtx != NULL)
		{
			FltReleaseContext(volCtx);
		}
	}
	FsRtlExitFileSystem();

	return FLT_PREOP_COMPLETE;
}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationSetVolumeInformation (
									__inout PFLT_CALLBACK_DATA Data,
									__in PCFLT_RELATED_OBJECTS FltObjects,
									__deref_out_opt PVOID *CompletionContext
									)
{
	//用自己的文件对象下发然后完成请求
	NTSTATUS Status;

	PFLT_CALLBACK_DATA RetNewCallbackData = NULL;
	PVOLUME_CONTEXT volCtx = NULL;

	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	PVOID VolumeBuffer;
	PFILE_OBJECT FileObject;
	PFCB Fcb;
	PCCB Ccb;
	BOOLEAN AcquireResource = FALSE;

	FsRtlEnterFileSystem();
	//
	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	Status = FltGetVolumeContext( FltObjects->Filter,
		FltObjects->Volume,
		&volCtx );

	if(!NT_SUCCESS(Status))
	{
		Data->IoStatus.Status = Status;
		Data->IoStatus.Information = 0;
		FsRtlExitFileSystem();
		return FLT_PREOP_COMPLETE;
	}

	FileObject = FltObjects->FileObject;

	Fcb = (PFCB)FileObject->FsContext;
	Ccb = (PCCB)FileObject->FsContext2;
	try
	{
		ExAcquireResourceExclusiveLite(volCtx->VolResource, TRUE);
		AcquireResource = TRUE;

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

			Status = RetNewCallbackData->IoStatus.Status;
			Data->IoStatus = RetNewCallbackData->IoStatus;

		}

try_exit: NOTHING;
	}
	finally
	{
		if(RetNewCallbackData != NULL)
		{
			FltFreeCallbackData(RetNewCallbackData);
		}
		if(AcquireResource)
		{
			ExReleaseResourceLite(volCtx->VolResource);
		}
		if(volCtx != NULL)
		{
			FltReleaseContext(volCtx);
		}
	}
	FsRtlExitFileSystem();
	return FLT_PREOP_COMPLETE;
}

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationQueryVolumeInformation  (
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
PtPostOperationSetVolumeInformation  (
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

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//文件查询接口
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationQueryInformation  (
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

//完成文件查询接口
FLT_PREOP_CALLBACK_STATUS
PtPreOperationQueryInformation (
								__inout PFLT_CALLBACK_DATA Data,
								__in PCFLT_RELATED_OBJECTS FltObjects,
								__deref_out_opt PVOID *CompletionContext
								)
{
	FLT_PREOP_CALLBACK_STATUS	FltStatus;

	PIRP_CONTEXT IrpContext = NULL;

	BOOLEAN TopLevel = FALSE;

	FsRtlEnterFileSystem();

	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if(FLT_IS_IRP_OPERATION(Data)) //irp query
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

			FltStatus = X70FsdCommonQueryInformation(Data, FltObjects,IrpContext);

		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			//出现异常直接返回
			DbgPrint("queryinfo出现异常直接返回 \n");
			X70FsdProcessException(&IrpContext,&Data,GetExceptionCode());
			FltStatus = FLT_PREOP_COMPLETE;
		}

		if (TopLevel) { IoSetTopLevelIrp( NULL ); }

	}
	else if(FLT_IS_FASTIO_OPERATION(Data)) //fastio read
	{
		//DbgPrint("FastIo queryinfo \n");
		FltStatus = FLT_PREOP_DISALLOW_FASTIO ;// X70FsdFastIoRead(Data, FltObjects); 
	}
	else
	{
		Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		Data->IoStatus.Information = 0;
		FltStatus = FLT_PREOP_COMPLETE;
		/*FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;*/
		DbgPrint("收到其他的queryinfo类型请求 \n");
	}

	FsRtlExitFileSystem();
	return FltStatus;
}


//
FLT_PREOP_CALLBACK_STATUS
X70FsdCommonQueryInformation(
							   __inout PFLT_CALLBACK_DATA Data,
							   __in    PCFLT_RELATED_OBJECTS FltObjects,
							   __in	  PIRP_CONTEXT IrpContext)
{
	//用原始文件对象进行文件的查询
	NTSTATUS Status = STATUS_SUCCESS;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	ULONG Length = 0 ,LengthReturned = 0;
	FILE_INFORMATION_CLASS FileInformationClass;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	PVOID InfoBuffer ;
	//PVOID QueryBuffer = NULL;
	PFILE_OBJECT FileObject;
	PFCB Fcb;
	PCCB Ccb;
	PFLT_CALLBACK_DATA RetNewCallbackData = NULL;
	BOOLEAN PostIrp = FALSE;

	PVOLUME_CONTEXT volCtx = NULL;
	BOOLEAN AcquireResource = FALSE;
	BOOLEAN AcquireVolResource = FALSE;
	BOOLEAN ReleaseScbPaging = FALSE;
	PDEVICE_OBJECT pVolumeDevObj,DeviceObject;
	BOOLEAN FcbAcquired = FALSE;
	BOOLEAN EncryptResourceAcquired = FALSE;
	BOOLEAN NonCachedIoPending = FALSE;

	if(FltObjects == NULL)
	{
		FltObjects = &IrpContext->FltObjects;
	}

	try{

		LengthReturned = Length = Iopb->Parameters.QueryFileInformation.Length;
		FileInformationClass = Iopb->Parameters.QueryFileInformation.FileInformationClass;
		InfoBuffer  = Iopb->Parameters.QueryFileInformation.InfoBuffer ;

		FileObject = FltObjects->FileObject;

		Fcb = (PFCB)FileObject->FsContext;
		Ccb = FileObject->FsContext2;

		if (!X70FsdAcquireSharedFcb( IrpContext, Fcb )) 
		{

			Status = X70FsdPostRequest(Data, IrpContext  );
			IrpContext = NULL;
			NonCachedIoPending = TRUE;

			try_return( Status );
		}
		FcbAcquired = TRUE;

		ExAcquireResourceSharedLite(Fcb->EncryptResource,TRUE);
		EncryptResourceAcquired = TRUE;
		//DbgPrint("查询文件信息 %d ,%ws \n",FileInformationClass,FileObject->FileName.Buffer);

		//QueryBuffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance,NonPagedPool,Length,'qfi');

		//if(QueryBuffer == NULL)
		//{
		//	try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
		//}

		//RtlZeroMemory(QueryBuffer,Length);
		//RtlCopyMemory(QueryBuffer,InfoBuffer,Length);
		if(Ccb->StreamFileInfo.StreamObject == NULL)
		{
			try_return(Status = STATUS_FILE_DELETED);
		}

		Status = FltAllocateCallbackData(FltObjects->Instance,Ccb->StreamFileInfo.StreamObject,&RetNewCallbackData);

		if(NT_SUCCESS(Status))
		{

			RtlCopyMemory(RetNewCallbackData->Iopb,Data->Iopb,sizeof(FLT_IO_PARAMETER_BLOCK));
			//RetNewCallbackData->Iopb->Parameters.QueryFileInformation.InfoBuffer = QueryBuffer;
			//RetNewCallbackData->Iopb->Parameters.QueryFileInformation.Length = Length;
			ClearFlag(RetNewCallbackData->Iopb->IrpFlags,IRP_PAGING_IO);
			RetNewCallbackData->Iopb->TargetFileObject = Ccb->StreamFileInfo.StreamObject;

			FltPerformSynchronousIo(RetNewCallbackData);

			Status = RetNewCallbackData->IoStatus.Status;
			Data->IoStatus = RetNewCallbackData->IoStatus;

			//RtlCopyMemory(InfoBuffer,QueryBuffer,Length);

			if(NT_SUCCESS(Status) || 
				(Status == STATUS_BUFFER_OVERFLOW))
			{
				//处理文件大小等参数

				switch(FileInformationClass)
				{
				case FileAllInformation:
					{
						// FileAllInformation
						PFILE_ALL_INFORMATION fai;

						fai = (PFILE_ALL_INFORMATION)InfoBuffer;

						if(Ccb->FileAccess == FILE_ONLY_READ && Length >= sizeof(FILE_BASIC_INFORMATION))
						{
							SetFlag(fai->BasicInformation.FileAttributes,FILE_ATTRIBUTE_READONLY);
						}
						if(Length >= (sizeof(FILE_BASIC_INFORMATION)+sizeof(FILE_STANDARD_INFORMATION)))
						{
							fai->StandardInformation.EndOfFile.QuadPart = Fcb->Header.FileSize.QuadPart;

							fai->StandardInformation.AllocationSize.QuadPart = Fcb->Header.AllocationSize.QuadPart;
						}
						if(Length >= (sizeof(FILE_BASIC_INFORMATION)
										+sizeof(FILE_STANDARD_INFORMATION)
										+sizeof(FILE_INTERNAL_INFORMATION)
										+sizeof(FILE_EA_INFORMATION)
										+sizeof(FILE_ACCESS_INFORMATION)
										+sizeof(FILE_POSITION_INFORMATION)))
						{
							fai->PositionInformation.CurrentByteOffset = FileObject->CurrentByteOffset;
						}

					}
					break;
				case FileBasicInformation:
					{
						PFILE_BASIC_INFORMATION fbi;

						fbi = (PFILE_BASIC_INFORMATION)InfoBuffer;
						
						if(Ccb->FileAccess == FILE_ONLY_READ)
						{
							SetFlag(fbi->FileAttributes,FILE_ATTRIBUTE_READONLY);
						}
					}
					break;
				case FileAttributeTagInformation:
					{
						PFILE_ATTRIBUTE_TAG_INFORMATION fati;

						fati = (PFILE_ATTRIBUTE_TAG_INFORMATION)InfoBuffer;
						
						if(Ccb->FileAccess == FILE_ONLY_READ)
						{
							SetFlag(fati->FileAttributes,FILE_ATTRIBUTE_READONLY);
						}
					}
					break;
				case FileStandardInformation:
					{
						PFILE_STANDARD_INFORMATION fsi;

						fsi = (PFILE_STANDARD_INFORMATION)InfoBuffer;

						fsi->EndOfFile.QuadPart = Fcb->Header.FileSize.QuadPart;

						// 保留文件标识部分
						fsi->AllocationSize.QuadPart = Fcb->Header.AllocationSize.QuadPart;

					}
					break;
				case FilePositionInformation:
					{
						PFILE_POSITION_INFORMATION fpi;

						fpi = (PFILE_POSITION_INFORMATION)InfoBuffer;

						fpi->CurrentByteOffset = FltObjects->FileObject->CurrentByteOffset;

					}
					break;
				case FileNetworkOpenInformation:
					{
						PFILE_NETWORK_OPEN_INFORMATION fnoi;

						fnoi = (PFILE_NETWORK_OPEN_INFORMATION)InfoBuffer;

						//DbgPrint("查询网络信息 \n");
						fnoi->EndOfFile.QuadPart = Fcb->Header.FileSize.QuadPart;

						// 保留文件标识部分
						fnoi->AllocationSize.QuadPart = Fcb->Header.AllocationSize.QuadPart;

					}
					break;

				case FileStreamInformation: //如果加密文件流的话，这里相关文件流的大小必须返回正确的数据，最好是访问一下设备然后去读一下加密头
					{

						WCHAR NtfsData[] = L"::$DATA";
						WCHAR StreamData[] = L":$DATA";

						PFILE_STREAM_INFORMATION fsi;
						ULONG offset = 0;
						fsi = (PFILE_STREAM_INFORMATION)InfoBuffer;
#ifdef CV
						VirtualizerStart();
#endif

						do
						{
							offset = fsi->NextEntryOffset;
							//默认流为文件本身
							if( (fsi->StreamNameLength == 0 ) || 
								((fsi->StreamNameLength == (sizeof(NtfsData)-sizeof(WCHAR))) &&
								(RtlCompareMemory(fsi->StreamName,NtfsData,fsi->StreamNameLength) == fsi->StreamNameLength)))
							{

								fsi->StreamSize.QuadPart = Fcb->Header.FileSize.QuadPart;

								// 保留文件标识部分
								fsi->StreamAllocationSize.QuadPart = Fcb->Header.AllocationSize.QuadPart;

							}
							//NTFS文件流暂时不考虑
							//else if(fsi->StreamNameLength >= sizeof(StreamData) &&
							//	(RtlCompareMemory(
							//	Add2Ptr(fsi->StreamName,fsi->StreamNameLength-sizeof(StreamData)+sizeof(WCHAR)),
							//	StreamData,
							//	sizeof(StreamData)-sizeof(WCHAR)
							//	) == sizeof(StreamData)-sizeof(WCHAR)))//修改跟这个文件关联流的大小
							//{

							//	BOOLEAN IsEnFile = FALSE;
							//	NTSTATUS StrStatus;
							//	//fsi->StreamSize.QuadPart -= Fcb->FileHeaderLength;
							//	StrStatus = GetFileStreamRealSize(  IrpContext,
							//		FltObjects,
							//		fsi->StreamName,
							//		fsi->StreamNameLength,
							//		&IsEnFile);
							//	if(NT_SUCCESS(StrStatus) && IsEnFile) 
							//	{
							//		fsi->StreamSize.QuadPart = IrpContext->CreateInfo.RealFileSize.QuadPart;
							//		fsi->StreamAllocationSize.QuadPart -= FILE_HEADER_LENGTH;
							//	}

							//}

							fsi = (PFILE_STREAM_INFORMATION)Add2Ptr(fsi,offset);

						}
						while(offset != 0);
#ifdef CV
						VirtualizerEnd();
#endif
					}
					break;

				default:
					//DbgPrint("收到其他查询请求 %d \n",FileInformationClass);
					break;

				}
			}

		}	

try_exit: NOTHING;
	}
	finally
	{
		if (FcbAcquired) 
		{
			X70FsdReleaseFcb( IrpContext, Fcb );
		}

		if(AcquireVolResource)
		{
			ExReleaseResourceLite(volCtx->VolResource);
		}

		if(volCtx != NULL)
		{
			FltReleaseContext(volCtx);
		}

		if(EncryptResourceAcquired)
		{
			ExReleaseResourceLite( Fcb->EncryptResource );
		}

		if(RetNewCallbackData != NULL)
		{
			FltFreeCallbackData(RetNewCallbackData);
		}

		//if(QueryBuffer != NULL)
		//{
		//	FltFreePoolAlignedWithTag(FltObjects->Instance,QueryBuffer,'qfi');
		//}

		if(!NT_SUCCESS(Status))
		{
			//DbgPrint("QueryInformation %ws 请求 %d 出错 ,%x \n ",FileObject->FileName.Buffer,FileInformationClass,Status);
		}


		if(Status == STATUS_PENDING)
		{
			FltStatus = FLT_PREOP_PENDING;
		}
		else
		{
			Data->IoStatus.Status = Status;
			FltStatus = FLT_PREOP_COMPLETE;
		}

		if(!AbnormalTermination())
		{
			X70FsdCompleteRequest( &IrpContext, &Data, Data->IoStatus.Status,FALSE );
		}

	}

	return FltStatus;
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//文件设置接口
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//对文件信息设置接口

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationSetInformation  (
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
PtPreOperationSetInformation (
							  __inout PFLT_CALLBACK_DATA Data,
							  __in PCFLT_RELATED_OBJECTS FltObjects,
							  __deref_out_opt PVOID *CompletionContext
							  )
{
	FLT_PREOP_CALLBACK_STATUS	FltStatus;

	PIRP_CONTEXT IrpContext = NULL;

	BOOLEAN TopLevel = FALSE;

	PAGED_CODE();

	FsRtlEnterFileSystem();

	if(!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if(FLT_IS_IRP_OPERATION(Data)) //irp query
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

			FltStatus = X70FsdCommonSetInformation(Data, FltObjects,IrpContext);

		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			//出现异常直接返回
			DbgPrint("setinfo出现异常直接返回 \n");
			X70FsdProcessException(&IrpContext,&Data,GetExceptionCode());
			FltStatus = FLT_PREOP_COMPLETE;
		}

		// 恢复Top-Level IRP
		if (TopLevel) { IoSetTopLevelIrp( NULL ); }

	}
	else if(FLT_IS_FASTIO_OPERATION(Data)) //fastio read
	{
		//DbgPrint("FastIo setinfo \n");
		FltStatus = FLT_PREOP_DISALLOW_FASTIO ;// 
	}
	else
	{
		Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		Data->IoStatus.Information = 0;
		FltStatus = FLT_PREOP_COMPLETE;
		/*FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;*/
		DbgPrint("收到其他的setinfo类型请求 \n");
	}

	FsRtlExitFileSystem();
	return FltStatus;
}
//对文件信息设置接口
FLT_PREOP_CALLBACK_STATUS
X70FsdCommonSetInformation(
							 __inout PFLT_CALLBACK_DATA Data,
							 __in    PCFLT_RELATED_OBJECTS FltObjects,
							 __in	  PIRP_CONTEXT IrpContext
							 )
{
	NTSTATUS Status;
	ULONG Length = 0 ;
	FILE_INFORMATION_CLASS FileInformationClass;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	PVOID InfoBuffer = NULL ;
	PFILE_OBJECT FileObject;
	PFCB Fcb;
	PCCB Ccb;
	PCCB TargetCcb;
	BOOLEAN PostIrp = FALSE;
	FLT_PREOP_CALLBACK_STATUS FltStatus;

	PFLT_CALLBACK_DATA RetNewCallbackData = NULL;
	PVOLUME_CONTEXT volCtx = NULL;
	BOOLEAN AcquireVolResource = FALSE;
	BOOLEAN ReleaseScbPaging = FALSE;
	BOOLEAN FsRtlHeaderLocked = FALSE;
	BOOLEAN FcbAcquired = FALSE;
	BOOLEAN PagingIoResourceAcquired = FALSE;
	BOOLEAN FileSizeChanged = FALSE;
	BOOLEAN NonCachedIoPending = FALSE;
	BOOLEAN FOResourceAcquired =FALSE;
	BOOLEAN EncryptResourceAcquired = FALSE;
	BOOLEAN Delete = FALSE;

	if(FltObjects == NULL)
	{
		FltObjects = &IrpContext->FltObjects;
	}

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

		Length = Iopb->Parameters.SetFileInformation.Length;
		FileInformationClass = Iopb->Parameters.SetFileInformation.FileInformationClass;
		InfoBuffer  = Iopb->Parameters.SetFileInformation.InfoBuffer ;

		FileObject = FltObjects->FileObject;

		Fcb = (PFCB)FileObject->FsContext;
		Ccb = FileObject->FsContext2;

		//DbgPrint("收到SetInfo %ws \n",FileObject->FileName.Buffer);

		if(FileInformationClass == FileEndOfFileInformation ||
			FileInformationClass == FileValidDataLengthInformation ||
			FileInformationClass == FileAllocationInformation)
		{
			FLT_PREOP_CALLBACK_STATUS FltOplockStatus;

			FltOplockStatus = FltCheckOplock( &Fcb->Oplock,
				Data,
				IrpContext,
				NULL,
				NULL );

			if (FltOplockStatus != FLT_PREOP_SUCCESS_WITH_CALLBACK ) 
			{
				try_return( Data->IoStatus.Status );
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


			if(!Fcb->IsEnFile && BooleanFlagOn(Fcb->FileType,FILE_ACCESS_WRITE_CHANGE_TO_ENCRYPTION)) //文件修改过需要转变成加密文件
			{	
				//对文件进行加密 
				DbgPrint("对非加密文件加密\n");
				Status = TransformFileToEncrypted(Data,FltObjects,Fcb,Ccb);

				if(!NT_SUCCESS(Status))
				{
					try_return( Status );
				}
			}

		}

		if ((FileInformationClass == FileDispositionInformation) ||
			(FileInformationClass == FileRenameInformation)) 
		{

			//互斥取得资源

			if (!ExAcquireResourceExclusiveLite( volCtx->VolResource, BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT)))
			{

				Status = X70FsdPostRequest( Data,IrpContext);

				NonCachedIoPending = TRUE;
				IrpContext = NULL;

				try_return( Status );
			}
			AcquireVolResource = TRUE;
		}
		if (!X70FsdAcquireExclusiveFcb( IrpContext, Fcb )) //
		{

			Status = X70FsdPostRequest( Data,IrpContext);

			NonCachedIoPending = TRUE;
			IrpContext = NULL;

			try_return( Status );
		}

		FcbAcquired = TRUE;

		ExAcquireResourceSharedLite(Fcb->EncryptResource,TRUE);
		EncryptResourceAcquired = TRUE;

		if(Ccb->StreamFileInfo.StreamObject == NULL)
		{
			try_return(Status = STATUS_FILE_DELETED);
		}
		//DbgPrint("收到SetInformation %ws \n",FileObject->FileName.Buffer);

		switch(FileInformationClass)
		{
		case FileAllocationInformation:
			{

				Status = X70FsdCommonSetAllocationInfo(Data,FltObjects,IrpContext);

			}
			break;
		case FileEndOfFileInformation:
			{

				Status = X70FsdCommonSetEndOfFileInfo(Data,FltObjects,IrpContext);


			}
			break;
		case FileValidDataLengthInformation:
			{

				Status = X70FsdCommonSetValidDataLengthInfo(Data,FltObjects,IrpContext);

			}
			break;
		case FilePositionInformation:
			{
				Status = X70FsdCommonFilePositionInfo(Data,FltObjects,IrpContext);

			}
			break;
		case FileRenameInformation:
			{
				Status = X70FsdCommonRenameInfo(Data,FltObjects,IrpContext);
			}
			break;
		case FileDispositionInformation:
			{

				PFILE_DISPOSITION_INFORMATION fdi;

				fdi =(PFILE_DISPOSITION_INFORMATION)InfoBuffer;

				if(fdi->DeleteFile )
				{
					if (!MmFlushImageSection( &Fcb->SectionObjectPointers,
						MmFlushForDelete )) 
					{
						Status = STATUS_CANNOT_DELETE;
						break;
					}
					SetFlag( Fcb->FcbState, SCB_STATE_DELETE_ON_CLOSE );
					FileObject->DeletePending = TRUE;
					Delete = TRUE;
				}
				else
				{
					ClearFlag( Fcb->FcbState, SCB_STATE_DELETE_ON_CLOSE );
					FileObject->DeletePending = FALSE;
				}

			}

		default:
			{
				//DbgPrint("收到请求 %d \n",FileInformationClass);

				Status = FltAllocateCallbackData(FltObjects->Instance,Ccb->StreamFileInfo.StreamObject,&RetNewCallbackData);

				if(NT_SUCCESS(Status))
				{

					RtlCopyMemory(RetNewCallbackData->Iopb,Data->Iopb,sizeof(FLT_IO_PARAMETER_BLOCK));

					ClearFlag(RetNewCallbackData->Iopb->IrpFlags,IRP_PAGING_IO);

					RetNewCallbackData->Iopb->TargetFileObject = Ccb->StreamFileInfo.StreamObject;

					if(IsMyFakeFcb(RetNewCallbackData->Iopb->Parameters.SetFileInformation.ParentOfTarget )) //如果是一个我们的对象换掉他
					{
						TargetCcb = RetNewCallbackData->Iopb->Parameters.SetFileInformation.ParentOfTarget->FsContext2;

						if(TargetCcb != NULL)
						{
							RetNewCallbackData->Iopb->Parameters.SetFileInformation.ParentOfTarget = TargetCcb->StreamFileInfo.StreamObject;
						}
						else
						{			
							try_return(Status = STATUS_ACCESS_DENIED;);
						}
					}

					FltPerformSynchronousIo(RetNewCallbackData);

					Data->IoStatus = RetNewCallbackData->IoStatus;
					Status = RetNewCallbackData->IoStatus.Status;
				}
			}
			break;

		}

try_exit:	NOTHING;

	}
	finally
	{

		if(RetNewCallbackData != NULL)
		{
			FltFreeCallbackData(RetNewCallbackData);
		}
		if(AcquireVolResource)
		{
			ExReleaseResourceLite(volCtx->VolResource);
		}
		if(FOResourceAcquired)
		{
			ExReleaseResourceLite(TargetCcb->StreamFileInfo.FO_Resource);
		}

		if(volCtx != NULL)
		{
			FltReleaseContext(volCtx);
		}

		if(FcbAcquired)
		{
			X70FsdReleaseFcb( IrpContext, Fcb );
		}
		if ( PagingIoResourceAcquired ) 
		{
			ExReleaseResourceLite( Fcb->Header.PagingIoResource );
		}
		if(EncryptResourceAcquired)
		{
			ExReleaseResourceLite( Fcb->EncryptResource );
		}

		if(!NT_SUCCESS(Status))
		{
			//DbgPrint("SetInformation %ws 请求 %d 出错 ,%x \n ",FileObject->FileName.Buffer,FileInformationClass,Status);
			if(Delete)
			{
				ClearFlag( Fcb->FcbState, SCB_STATE_DELETE_ON_CLOSE );
				FileObject->DeletePending = FALSE;
			}
		}
		if(Status == STATUS_PENDING)
		{
			FltStatus = FLT_PREOP_PENDING;
		}
		else
		{
			Data->IoStatus.Status = Status;
			FltStatus = FLT_PREOP_COMPLETE;
		}		

		if(!AbnormalTermination())
		{
			X70FsdCompleteRequest( &IrpContext, &Data, Data->IoStatus.Status,FALSE );
		}

	}
	return FltStatus;
}


//重命名后更新hash表，根据重命名替换文件头信息。
NTSTATUS
X70FsdCommonRenameInfo(__inout PFLT_CALLBACK_DATA Data,
						 __in    PCFLT_RELATED_OBJECTS FltObjects,
						 __in	 PIRP_CONTEXT IrpContext)
{
	//更新fcb中的文件名字符串
	PFILE_OBJECT FileObject;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;

	PFCB Fcb;
	PCCB Ccb;
	PCCB TargetCcb;
	NTSTATUS Status;

	PFLT_CALLBACK_DATA RetNewCallbackData = NULL;

	FILE_INFORMATION_CLASS FileInformationClass;
	ULONG Length;
	PVOID InfoBuffer;

	UNICODE_STRING VolumeName = {0};

	PFILE_NAME_INFORMATION fni = NULL;

	ULONG LengthReturned = 0 ;

	UNICODE_STRING RenameFile = {0};
	UCHAR HashValue[MD5_LENGTH] = {0};

	FileObject = FltObjects->FileObject;

	Fcb = (PFCB)FileObject->FsContext;
	Ccb = FileObject->FsContext2;

	try{

		//先发重命名下去
		Length = Iopb->Parameters.SetFileInformation.Length;
		InfoBuffer  = Iopb->Parameters.SetFileInformation.InfoBuffer ;
		FileInformationClass = Iopb->Parameters.SetFileInformation.FileInformationClass;

		Status = FltAllocateCallbackData(FltObjects->Instance,Ccb->StreamFileInfo.StreamObject,&RetNewCallbackData);

		if(NT_SUCCESS(Status))
		{

			RtlCopyMemory(RetNewCallbackData->Iopb,Data->Iopb,sizeof(FLT_IO_PARAMETER_BLOCK));

			RetNewCallbackData->Iopb->TargetFileObject = Ccb->StreamFileInfo.StreamObject;

			ClearFlag(RetNewCallbackData->Iopb->IrpFlags,IRP_PAGING_IO);
			if(IsMyFakeFcb(RetNewCallbackData->Iopb->Parameters.SetFileInformation.ParentOfTarget )) //如果是一个我们的对象换掉他
			{
				TargetCcb = RetNewCallbackData->Iopb->Parameters.SetFileInformation.ParentOfTarget->FsContext2;

				if(TargetCcb != NULL)
				{
					RetNewCallbackData->Iopb->Parameters.SetFileInformation.ParentOfTarget = TargetCcb->StreamFileInfo.StreamObject;
				}
				else
				{			
					try_return(Status = STATUS_ACCESS_DENIED;);
				}
			}

			FltPerformSynchronousIo(RetNewCallbackData);

			Data->IoStatus = RetNewCallbackData->IoStatus;
			Status = RetNewCallbackData->IoStatus.Status;
		}
		if(!NT_SUCCESS(Status))
		{
			try_return(Status);
		}

		//更新fcb中信息
		//先获取卷名
		Status = FltGetVolumeName(FltObjects->Volume,NULL,&LengthReturned);

		if(STATUS_BUFFER_TOO_SMALL == Status)
		{
			VolumeName.Buffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance,PagedPool,LengthReturned,'von');

			if(VolumeName.Buffer == NULL)
			{
				try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
			}

			RtlZeroMemory(VolumeName.Buffer,LengthReturned);

			VolumeName.MaximumLength = (USHORT)LengthReturned;

			VolumeName.Length = (USHORT)LengthReturned;		

			Status = FltGetVolumeName(FltObjects->Volume,&VolumeName,&LengthReturned);

		}
		if(!NT_SUCCESS(Status))
		{
			try_return(Status);
		}
		//获取文件名
		Length = MAX_PATH;

		fni = FltAllocatePoolAlignedWithTag(FltObjects->Instance,PagedPool,Length,'fni');

		if(fni == NULL)
		{
			try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
		}

		RtlZeroMemory(fni,Length);

		Status =  FltQueryInformationFile(
			FltObjects->Instance,
			Ccb->StreamFileInfo.StreamObject,
			fni,
			Length,
			FileNameInformation,
			&LengthReturned 
			); 

		if(Status == STATUS_BUFFER_OVERFLOW)
		{
			//重新设置大小再发一次
			Length = fni->FileNameLength + sizeof(FILE_NAME_INFORMATION);

			FltFreePoolAlignedWithTag(FltObjects->Instance,fni,'fni');

			fni = NULL;

			fni = FltAllocatePoolAlignedWithTag(FltObjects->Instance,PagedPool,Length ,'fni');

			if(fni == NULL)
			{
				try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
			}

			RtlZeroMemory(fni,Length);

			Status =  FltQueryInformationFile(
				FltObjects->Instance,
				Ccb->StreamFileInfo.StreamObject,
				fni,
				Length,
				FileNameInformation,
				&LengthReturned 
				); 			

		}
		if(NT_SUCCESS(Status))
		{
			Length = fni->FileNameLength + VolumeName.Length + sizeof(WCHAR);

			RenameFile.Buffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance,PagedPool,Length ,'hash');

			if(RenameFile.Buffer == NULL)
			{
				try_return(Status = STATUS_INSUFFICIENT_RESOURCES;);
			}

			RtlZeroMemory(RenameFile.Buffer,Length);

			RenameFile.Length = (USHORT)(Length - sizeof(WCHAR));
			RenameFile.MaximumLength = (USHORT)Length;

			RtlCopyMemory(RenameFile.Buffer,VolumeName.Buffer,VolumeName.Length);

			RtlCopyMemory(Add2Ptr(RenameFile.Buffer,VolumeName.Length),fni->FileName,fni->FileNameLength);

			if(!HashFilePath(&RenameFile,HashValue)) //hash失败了直接完成
			{	
				DbgPrint("Hash路径出错\n");
				try_return(Status = STATUS_INSUFFICIENT_RESOURCES;);
			}
			if(!UpdateHashValue(Fcb->HashValue,HashValue,&Fcb))
			{
				DbgPrint("更新Hash出错\n");
				try_return(Status = STATUS_INSUFFICIENT_RESOURCES;);
			}
			Fcb->FileFullName.Length = RenameFile.Length;
			Fcb->FileFullName.MaximumLength  = RenameFile.MaximumLength ;
			Fcb->FileFullName.Buffer = FsRtlAllocatePoolWithTag(NonPagedPool,Fcb->FileFullName.MaximumLength,'ffn');
			RtlCopyMemory(Fcb->FileFullName.Buffer,RenameFile.Buffer,Fcb->FileFullName.MaximumLength);

		}
try_exit:	NOTHING;
	}
	finally
	{

		SetFlag( FileObject->Flags, FO_FILE_MODIFIED);

		if(VolumeName.Buffer != NULL)
		{
			FltFreePoolAlignedWithTag(FltObjects->Instance,VolumeName.Buffer,'von');
		}
		if(fni != NULL)
		{
			FltFreePoolAlignedWithTag(FltObjects->Instance,fni,'fni');
		}
		if(RenameFile.Buffer != NULL)
		{
			FltFreePoolAlignedWithTag(FltObjects->Instance,RenameFile.Buffer,'hash');
		}
		if(RetNewCallbackData != NULL)
		{
			FltFreeCallbackData(RetNewCallbackData);
		}
	}
	return Status;
}

NTSTATUS
X70FsdCommonSetAllocationInfo (
								 __inout PFLT_CALLBACK_DATA Data,
								 __in    PCFLT_RELATED_OBJECTS FltObjects,
								 __in	PIRP_CONTEXT IrpContext
								 )
{
	NTSTATUS Status = STATUS_SUCCESS;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	PFILE_ALLOCATION_INFORMATION fai;

	PFLT_CALLBACK_DATA RetNewCallbackData = NULL;

	LARGE_INTEGER NewAllocationSize;
	LARGE_INTEGER OriginalFileSize;
	LARGE_INTEGER OriginalValidDataLength;
	LARGE_INTEGER OriginalValidDataToDisk;

	FILE_INFORMATION_CLASS FileInformationClass;
	ULONG Length;
	PVOID InfoBuffer;

	PFCB Fcb;
	PCCB Ccb;
	PFILE_OBJECT FileObject;

	BOOLEAN CacheMapInitialized = FALSE;
	BOOLEAN ResourceAcquired = FALSE;
	BOOLEAN FileSizeTruncated = FALSE;
	try{	

		Length = Iopb->Parameters.SetFileInformation.Length;
		InfoBuffer  = Iopb->Parameters.SetFileInformation.InfoBuffer ;
		FileInformationClass = Iopb->Parameters.SetFileInformation.FileInformationClass;
		FileObject = FltObjects->FileObject;

		Fcb = (PFCB)FileObject->FsContext;
		Ccb = FileObject->FsContext2;

		fai = FltAllocatePoolAlignedWithTag(FltObjects->Instance,NonPagedPool,Length,'fai');

		if(fai == NULL)
		{
			try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
		}

		RtlZeroMemory(fai,Length);

		RtlCopyMemory(fai,InfoBuffer,Length);

		NewAllocationSize = fai->AllocationSize;

		if (Fcb->Header.AllocationSize.QuadPart == FCB_LOOKUP_ALLOCATIONSIZE_HINT) {

			X70FsdLookupFileAllocationSize( IrpContext, Fcb,Ccb);
		}

		if ((FileObject->SectionObjectPointer->DataSectionObject != NULL) &&
			(FileObject->SectionObjectPointer->SharedCacheMap == NULL) &&
			!FlagOn(Iopb->IrpFlags, IRP_PAGING_IO) &&
			!BooleanFlagOn(Ccb->CcbState,CCB_FLAG_NETWORK_FILE)) 
		{

			ASSERT( !FlagOn( FileObject->Flags, FO_CLEANUP_COMPLETE ) );

			CcInitializeCacheMap( FileObject,
				(PCC_FILE_SIZES)&Fcb->Header.AllocationSize,
				FALSE,
				&G_CacheMgrCallbacks,
				Fcb );

			CacheMapInitialized = TRUE;

			Fcb->CacheObject = FileObject;

		}

		SetFlag( FileObject->Flags, FO_FILE_MODIFIED );

		fai->AllocationSize.QuadPart += Fcb->FileHeaderLength;

		if(FlagOn(Fcb->FcbState,SCB_STATE_FILEHEADER_WRITED)) //写过文件头的拓展文件大小方便加密
		{
			LARGE_INTEGER TempLI;
			ULONG UnitSize = CRYPT_UNIT;

			//DbgPrint("加密扩展文件 \n");

			TempLI.QuadPart = fai->AllocationSize.QuadPart;//占用大小
			TempLI.QuadPart += UnitSize;
			TempLI.HighPart += (ULONG)( (LONGLONG)UnitSize >> 32 );

			if ( TempLI.LowPart == 0 ) //不需要进位 
			{
				TempLI.HighPart -= 1;
			}

			fai->AllocationSize.LowPart  = ( (ULONG)fai->AllocationSize.LowPart + (UnitSize - 1) ) & ( ~(UnitSize - 1) );

			fai->AllocationSize.HighPart = TempLI.HighPart;
		}

		if ( Fcb->Header.FileSize.QuadPart > NewAllocationSize.QuadPart ) 
		{

			if (!MmCanFileBeTruncated( FileObject->SectionObjectPointer,
				&NewAllocationSize )) {

					try_return( Status = STATUS_USER_MAPPED_FILE );
			}


			OriginalFileSize.QuadPart = Fcb->Header.FileSize.QuadPart;
			OriginalValidDataLength.QuadPart = Fcb->Header.ValidDataLength.QuadPart;
			OriginalValidDataToDisk.QuadPart= Fcb->ValidDataToDisk.QuadPart;
			FileSizeTruncated = TRUE;

			(VOID)ExAcquireResourceExclusiveLite( Fcb->Header.PagingIoResource, TRUE );
			ResourceAcquired = TRUE;

			Fcb->Header.FileSize.QuadPart = NewAllocationSize.QuadPart;

			if (Fcb->Header.ValidDataLength.QuadPart > Fcb->Header.FileSize.QuadPart) 
			{
				Fcb->Header.ValidDataLength.QuadPart = Fcb->Header.FileSize.QuadPart;
			}

			Fcb->ValidDataToDisk.QuadPart = fai->AllocationSize.QuadPart;

		}

		Status = FltAllocateCallbackData(FltObjects->Instance,Ccb->StreamFileInfo.StreamObject,&RetNewCallbackData);

		if(NT_SUCCESS(Status))
		{
			RtlCopyMemory(RetNewCallbackData->Iopb,Data->Iopb,sizeof(FLT_IO_PARAMETER_BLOCK));

			ClearFlag(RetNewCallbackData->Iopb->IrpFlags,IRP_PAGING_IO);
			RetNewCallbackData->Iopb->Parameters.SetFileInformation.InfoBuffer = fai;
			RetNewCallbackData->Iopb->Parameters.SetFileInformation.Length = Length;
			RetNewCallbackData->Iopb->TargetFileObject = Ccb->StreamFileInfo.StreamObject;

			FltPerformSynchronousIo(RetNewCallbackData);

			Data->IoStatus = RetNewCallbackData->IoStatus;
			Status = RetNewCallbackData->IoStatus.Status;

		}
		if(!NT_SUCCESS(Status))
		{
			//DbgPrint("FltSetInformationFile 调用失败 %x\n",Status);
			X70FsdRaiseStatus(IrpContext,Status);
		}

		X70FsdLookupFileAllocationSize(IrpContext,Fcb,Ccb);

		if (CcIsFileCached(FileObject)) 
		{
			CcSetFileSizes( FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize );
		}
		Status = STATUS_SUCCESS;
try_exit: NOTHING;
	}
	finally
	{
		if ( AbnormalTermination() && FileSizeTruncated ) 
		{

			Fcb->Header.FileSize.QuadPart = OriginalFileSize.QuadPart;
			Fcb->Header.ValidDataLength.QuadPart = OriginalValidDataLength.QuadPart;
			Fcb->ValidDataToDisk.QuadPart = OriginalValidDataToDisk.QuadPart;

			if (FileObject->SectionObjectPointer->SharedCacheMap != NULL) 
			{
				CcGetFileSizePointer(FileObject)->QuadPart = Fcb->Header.FileSize.QuadPart;
			}

		}

		if (CacheMapInitialized) 
		{
			CcUninitializeCacheMap( FileObject, NULL, NULL );
		}

		if (ResourceAcquired) 
		{
			ExReleaseResourceLite( Fcb->Header.PagingIoResource );

		}
		if(RetNewCallbackData != NULL)
		{
			FltFreeCallbackData(RetNewCallbackData);
		}
		if(fai != NULL)
		{
			FltFreePoolAlignedWithTag(FltObjects->Instance,fai,'fai');
		}
	}

	return Status;
}



NTSTATUS
X70FsdCommonSetEndOfFileInfo (
								__inout PFLT_CALLBACK_DATA Data,
								__in    PCFLT_RELATED_OBJECTS FltObjects,
								__in	PIRP_CONTEXT IrpContext
								)
{
	NTSTATUS Status;
	FILE_END_OF_FILE_INFORMATION * fei = NULL;
	PVOID InfoBuffer = NULL ;
	ULONG Length;
	PFCB Fcb;
	PCCB Ccb;
	PFILE_OBJECT FileObject;
	FILE_INFORMATION_CLASS FileInformationClass;
	PFLT_CALLBACK_DATA RetNewCallbackData = NULL;

	LARGE_INTEGER NewFileSize;
	LARGE_INTEGER InitialFileSize;
	LARGE_INTEGER InitialValidDataLength;
	LARGE_INTEGER InitialValidDataToDisk;

	BOOLEAN LazyWriterCallback = FALSE;
	BOOLEAN CacheMapInitialized = FALSE;
	BOOLEAN UnwindFileSizes = FALSE;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	BOOLEAN ResourceAcquired = FALSE;

	try {

		Length = Iopb->Parameters.SetFileInformation.Length;
		InfoBuffer  = Iopb->Parameters.SetFileInformation.InfoBuffer ;
		FileInformationClass = Iopb->Parameters.SetFileInformation.FileInformationClass;
		FileObject = FltObjects->FileObject;

		Fcb = (PFCB)FileObject->FsContext;
		Ccb = FileObject->FsContext2;

		fei = FltAllocatePoolAlignedWithTag(FltObjects->Instance,NonPagedPool,Length,'fei');

		if(fei == NULL)
		{
			try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
		}

		RtlZeroMemory(fei,Length);

		RtlCopyMemory(fei,InfoBuffer,Length);

		NewFileSize.QuadPart = fei->EndOfFile.QuadPart;

		LazyWriterCallback = Iopb->Parameters.SetFileInformation.AdvanceOnly;

		if (Fcb->Header.AllocationSize.QuadPart == FCB_LOOKUP_ALLOCATIONSIZE_HINT) 
		{
			X70FsdLookupFileAllocationSize( IrpContext, Fcb ,Ccb);
		}

		if ((FileObject->SectionObjectPointer->DataSectionObject != NULL) &&
			(FileObject->SectionObjectPointer->SharedCacheMap == NULL) &&
			!FlagOn(Iopb->IrpFlags, IRP_PAGING_IO) &&
			!BooleanFlagOn(Ccb->CcbState,CCB_FLAG_NETWORK_FILE)) 
		{

			if (FlagOn( FileObject->Flags, FO_CLEANUP_COMPLETE ))  
			{
				X70FsdRaiseStatus( IrpContext, STATUS_FILE_CLOSED);
			}

			CcInitializeCacheMap( FileObject,
				(PCC_FILE_SIZES)&Fcb->Header.AllocationSize,
				FALSE,
				&G_CacheMgrCallbacks,
				Fcb );

			CacheMapInitialized = TRUE;

			Fcb->CacheObject = FileObject;

		}

		if ( LazyWriterCallback )
		{

			if(NewFileSize.QuadPart <= Fcb->Header.FileSize.QuadPart)
			{
				try_return( Status = STATUS_SUCCESS ); //如果小于文件大小直接设置成功。
			}
			else //延迟写不能改变文件大小
			{
				NewFileSize.QuadPart = Fcb->Header.FileSize.QuadPart;
				fei->EndOfFile = NewFileSize;
			}

			fei->EndOfFile.QuadPart += Fcb->FileHeaderLength; //先加上文件头大小

			if(FlagOn(Fcb->FcbState,SCB_STATE_FILEHEADER_WRITED)) //写过文件头的拓展文件大小方便加密
			{

				LARGE_INTEGER TempLI;
				ULONG UnitSize = CRYPT_UNIT;

				//DbgPrint("加密扩展文件 \n");

				TempLI.QuadPart = fei->EndOfFile.QuadPart;//占用大小
				TempLI.QuadPart += UnitSize;
				TempLI.HighPart += (ULONG)( (LONGLONG)UnitSize >> 32 );

				if ( TempLI.LowPart == 0 ) //不需要进位 
				{
					TempLI.HighPart -= 1;
				}

				fei->EndOfFile.LowPart  = ( (ULONG)fei->EndOfFile.LowPart + (UnitSize - 1) ) & ( ~(UnitSize - 1) );

				fei->EndOfFile.HighPart = TempLI.HighPart;

				Fcb->ValidDataToDisk.QuadPart = fei->EndOfFile.QuadPart;
			}

			Status = FltAllocateCallbackData(FltObjects->Instance,Ccb->StreamFileInfo.StreamObject,&RetNewCallbackData);

			if(NT_SUCCESS(Status))
			{
				RtlCopyMemory(RetNewCallbackData->Iopb,Data->Iopb,sizeof(FLT_IO_PARAMETER_BLOCK));

				ClearFlag(RetNewCallbackData->Iopb->IrpFlags,IRP_PAGING_IO);
				RetNewCallbackData->Iopb->Parameters.SetFileInformation.InfoBuffer = fei;
				RetNewCallbackData->Iopb->Parameters.SetFileInformation.Length = Length;
				RetNewCallbackData->Iopb->TargetFileObject = Ccb->StreamFileInfo.StreamObject;

				FltPerformSynchronousIo(RetNewCallbackData);

				Data->IoStatus = RetNewCallbackData->IoStatus;
				Status = RetNewCallbackData->IoStatus.Status;

			}

			if(!NT_SUCCESS(Status))
			{
				//DbgPrint("FltSetInformationFile 调用失败 %x\n",Status);
			}

			try_return( Status );
		}

		if (Fcb->Header.FileSize.QuadPart != NewFileSize.QuadPart) 
		{

			if ( NewFileSize.QuadPart < Fcb->Header.FileSize.QuadPart ) 
			{

				if (!MmCanFileBeTruncated( FileObject->SectionObjectPointer,
					&NewFileSize)) 
				{

					try_return( Status = STATUS_USER_MAPPED_FILE );
				}

				ResourceAcquired =
					ExAcquireResourceExclusiveLite( Fcb->Header.PagingIoResource, TRUE );
			}

			InitialFileSize.QuadPart = Fcb->Header.FileSize.QuadPart;
			InitialValidDataLength.QuadPart = Fcb->Header.ValidDataLength.QuadPart;
			InitialValidDataToDisk.QuadPart = Fcb->ValidDataToDisk.QuadPart;
			UnwindFileSizes = TRUE;

			Fcb->Header.FileSize.QuadPart = NewFileSize.QuadPart;

			if (Fcb->Header.ValidDataLength.QuadPart > NewFileSize.QuadPart) 
			{
				Fcb->Header.ValidDataLength.QuadPart = NewFileSize.QuadPart;
			}

			//扩展文件大小然后设置
			fei->EndOfFile.QuadPart += Fcb->FileHeaderLength; //先加上文件头大小

			if(FlagOn(Fcb->FcbState,SCB_STATE_FILEHEADER_WRITED)) //写过文件头的拓展文件大小方便加密
			{

				LARGE_INTEGER TempLI;
				ULONG UnitSize = CRYPT_UNIT;

				//DbgPrint("加密扩展文件 \n");

				TempLI.QuadPart = fei->EndOfFile.QuadPart;//占用大小
				TempLI.QuadPart += UnitSize;
				TempLI.HighPart += (ULONG)( (LONGLONG)UnitSize >> 32 );

				if ( TempLI.LowPart == 0 ) //不需要进位 
				{
					TempLI.HighPart -= 1;
				}

				fei->EndOfFile.LowPart  = ( (ULONG)fei->EndOfFile.LowPart + (UnitSize - 1) ) & ( ~(UnitSize - 1) );

				fei->EndOfFile.HighPart = TempLI.HighPart;

				Fcb->ValidDataToDisk.QuadPart = fei->EndOfFile.QuadPart;
			}

			Status = FltAllocateCallbackData(FltObjects->Instance,Ccb->StreamFileInfo.StreamObject,&RetNewCallbackData);

			if(NT_SUCCESS(Status))
			{

				RtlCopyMemory(RetNewCallbackData->Iopb,Data->Iopb,sizeof(FLT_IO_PARAMETER_BLOCK));

				ClearFlag(RetNewCallbackData->Iopb->IrpFlags,IRP_PAGING_IO);
				RetNewCallbackData->Iopb->Parameters.SetFileInformation.InfoBuffer = fei;
				RetNewCallbackData->Iopb->Parameters.SetFileInformation.Length = Length;
				RetNewCallbackData->Iopb->TargetFileObject = Ccb->StreamFileInfo.StreamObject;

				FltPerformSynchronousIo(RetNewCallbackData);

				Data->IoStatus = RetNewCallbackData->IoStatus;
				Status = RetNewCallbackData->IoStatus.Status;

			}
			if(!NT_SUCCESS(Status))
			{
				//DbgPrint("FltSetInformationFile 调用失败 %x\n",Status);
				X70FsdRaiseStatus(IrpContext,Status);
			}

			X70FsdLookupFileAllocationSize(IrpContext,Fcb,Ccb);

			if (CcIsFileCached(FileObject)) 
			{
				CcSetFileSizes( FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize );
			}

		}

		FileObject->Flags |= FO_FILE_MODIFIED;
		SetFlag(Ccb->CcbState,CCB_FLAG_FILE_CHANGED);

		Status = STATUS_SUCCESS;
try_exit: NOTHING;
	}
	finally {

		if (AbnormalTermination() && UnwindFileSizes) 
		{

			Fcb->Header.FileSize.QuadPart = InitialFileSize.QuadPart;
			Fcb->Header.ValidDataLength.QuadPart = InitialValidDataLength.QuadPart;
			Fcb->ValidDataToDisk.QuadPart = InitialValidDataToDisk.QuadPart;

			if (FileObject->SectionObjectPointer->SharedCacheMap != NULL) 
			{

				CcGetFileSizePointer(FileObject)->QuadPart = Fcb->Header.FileSize.QuadPart;
			}
		}

		if (CacheMapInitialized) {

			CcUninitializeCacheMap( FileObject, NULL, NULL );
		}

		if ( ResourceAcquired ) {

			ExReleaseResourceLite( Fcb->Header.PagingIoResource );
		}
		if(RetNewCallbackData != NULL)
		{
			FltFreeCallbackData(RetNewCallbackData);
		}
		if(fei != NULL)
		{
			FltFreePoolAlignedWithTag(FltObjects->Instance,fei,'fei');
		}
	}
	return Status;
}


NTSTATUS
X70FsdCommonSetValidDataLengthInfo (
									  __inout PFLT_CALLBACK_DATA Data,
									  __in    PCFLT_RELATED_OBJECTS FltObjects,
									  __in	PIRP_CONTEXT IrpContext
									  )
{
	NTSTATUS Status;
	FILE_VALID_DATA_LENGTH_INFORMATION * fvi = NULL;
	PVOID InfoBuffer = NULL ;
	ULONG Length;
	PFCB Fcb;
	PCCB Ccb;
	PFILE_OBJECT FileObject;
	PFLT_CALLBACK_DATA RetNewCallbackData = NULL;

	LARGE_INTEGER NewFileSize;
	LARGE_INTEGER InitialFileSize;
	LARGE_INTEGER InitialValidDataLength;
	LARGE_INTEGER InitialValidDataToDisk;

	BOOLEAN LazyWriterCallback = FALSE;
	BOOLEAN CacheMapInitialized = FALSE;
	BOOLEAN UnwindFileSizes = FALSE;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	BOOLEAN ResourceAcquired = FALSE;
	FILE_INFORMATION_CLASS FileInformationClass;

	try {

		Length = Iopb->Parameters.SetFileInformation.Length;
		InfoBuffer  = Iopb->Parameters.SetFileInformation.InfoBuffer ;
		FileInformationClass = Iopb->Parameters.SetFileInformation.FileInformationClass;
		FileObject = FltObjects->FileObject;

		Fcb = (PFCB)FileObject->FsContext;
		Ccb = FileObject->FsContext2;

		fvi = FltAllocatePoolAlignedWithTag(FltObjects->Instance,NonPagedPool,Length,'fvi');

		if(fvi == NULL)
		{
			try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
		}

		RtlZeroMemory(fvi,Length);

		RtlCopyMemory(fvi,InfoBuffer,Length);

		NewFileSize.QuadPart = fvi->ValidDataLength.QuadPart;

		LazyWriterCallback = Iopb->Parameters.SetFileInformation.AdvanceOnly;

		if (Fcb->Header.AllocationSize.QuadPart == FCB_LOOKUP_ALLOCATIONSIZE_HINT) 
		{
			X70FsdLookupFileAllocationSize( IrpContext, Fcb ,Ccb);
		}

		if ((FileObject->SectionObjectPointer->DataSectionObject != NULL) &&
			(FileObject->SectionObjectPointer->SharedCacheMap == NULL) &&
			!FlagOn(Iopb->IrpFlags, IRP_PAGING_IO) &&
			!BooleanFlagOn(Ccb->CcbState,CCB_FLAG_NETWORK_FILE)) 
		{

			if (FlagOn( FileObject->Flags, FO_CLEANUP_COMPLETE ))  
			{
				X70FsdRaiseStatus( IrpContext, STATUS_FILE_CLOSED);
			}

			CcInitializeCacheMap( FileObject,
				(PCC_FILE_SIZES)&Fcb->Header.AllocationSize,
				FALSE,
				&G_CacheMgrCallbacks,
				Fcb );

			CacheMapInitialized = TRUE;

			Fcb->CacheObject = FileObject;

		}

		if ( LazyWriterCallback )
		{

			if(NewFileSize.QuadPart <= Fcb->Header.ValidDataLength.QuadPart)
			{
				try_return( Status = STATUS_SUCCESS ); //如果小于文件大小直接设置成功。
			}
			else //延迟写不能改变文件大小
			{
				NewFileSize.QuadPart = Fcb->Header.ValidDataLength.QuadPart;
				fvi->ValidDataLength.QuadPart = NewFileSize.QuadPart;
			}

			fvi->ValidDataLength.QuadPart += Fcb->FileHeaderLength; //先加上文件头大小

			if(FlagOn(Fcb->FcbState,SCB_STATE_FILEHEADER_WRITED)) //写过文件头的拓展文件大小方便加密
			{

				LARGE_INTEGER TempLI;
				ULONG UnitSize = CRYPT_UNIT;

				//DbgPrint("加密扩展文件 \n");

				TempLI.QuadPart = fvi->ValidDataLength.QuadPart;//占用大小
				TempLI.QuadPart += UnitSize;
				TempLI.HighPart += (ULONG)( (LONGLONG)UnitSize >> 32 );

				if ( TempLI.LowPart == 0 ) //不需要进位 
				{
					TempLI.HighPart -= 1;
				}

				fvi->ValidDataLength.LowPart  = ( (ULONG)fvi->ValidDataLength.LowPart + (UnitSize - 1) ) & ( ~(UnitSize - 1) );

				fvi->ValidDataLength.HighPart = TempLI.HighPart;

				Fcb->ValidDataToDisk.QuadPart = fvi->ValidDataLength.QuadPart;
			}

			Status = FltAllocateCallbackData(FltObjects->Instance,Ccb->StreamFileInfo.StreamObject,&RetNewCallbackData);

			if(NT_SUCCESS(Status))
			{

				RtlCopyMemory(RetNewCallbackData->Iopb,Data->Iopb,sizeof(FLT_IO_PARAMETER_BLOCK));

				ClearFlag(RetNewCallbackData->Iopb->IrpFlags,IRP_PAGING_IO);
				RetNewCallbackData->Iopb->Parameters.SetFileInformation.InfoBuffer = fvi;
				RetNewCallbackData->Iopb->Parameters.SetFileInformation.Length = Length;
				RetNewCallbackData->Iopb->TargetFileObject = Ccb->StreamFileInfo.StreamObject;

				FltPerformSynchronousIo(RetNewCallbackData);

				Data->IoStatus = RetNewCallbackData->IoStatus;
				Status = RetNewCallbackData->IoStatus.Status;

			}

			if(!NT_SUCCESS(Status))
			{
				//DbgPrint("FltSetInformationFile 调用失败 %x\n",Status);
			}

			try_return( Status );
		}

		//if (Fcb->Header.ValidDataLength.QuadPart != NewFileSize.QuadPart) 
		//{

		if ( NewFileSize.QuadPart < Fcb->Header.ValidDataLength.QuadPart ) 
		{

			if (!MmCanFileBeTruncated( FileObject->SectionObjectPointer,
				&NewFileSize)) 
			{

				try_return( Status = STATUS_USER_MAPPED_FILE );
			}

			ResourceAcquired =
				ExAcquireResourceExclusiveLite( Fcb->Header.PagingIoResource, TRUE );
		}

		InitialFileSize.QuadPart = Fcb->Header.FileSize.QuadPart;
		InitialValidDataLength.QuadPart = Fcb->Header.ValidDataLength.QuadPart;
		InitialValidDataToDisk.QuadPart = Fcb->ValidDataToDisk.QuadPart;
		UnwindFileSizes = TRUE;

		Fcb->Header.ValidDataLength.QuadPart = NewFileSize.QuadPart;

		//扩展文件大小然后设置
		fvi->ValidDataLength .QuadPart += Fcb->FileHeaderLength; //先加上文件头大小

		if(FlagOn(Fcb->FcbState,SCB_STATE_FILEHEADER_WRITED)) //写过文件头的拓展文件大小方便加密
		{

			LARGE_INTEGER TempLI;
			ULONG UnitSize = CRYPT_UNIT;

			//DbgPrint("加密扩展文件 \n");

			TempLI.QuadPart = fvi->ValidDataLength .QuadPart;//占用大小
			TempLI.QuadPart += UnitSize;
			TempLI.HighPart += (ULONG)( (LONGLONG)UnitSize >> 32 );

			if ( TempLI.LowPart == 0 ) //不需要进位 
			{
				TempLI.HighPart -= 1;
			}

			fvi->ValidDataLength .LowPart  = ( (ULONG)fvi->ValidDataLength .LowPart + (UnitSize - 1) ) & ( ~(UnitSize - 1) );

			fvi->ValidDataLength .HighPart = TempLI.HighPart;

			Fcb->ValidDataToDisk.QuadPart = fvi->ValidDataLength.QuadPart ;
		}

		Status = FltAllocateCallbackData(FltObjects->Instance,Ccb->StreamFileInfo.StreamObject,&RetNewCallbackData);

		if(NT_SUCCESS(Status))
		{
			RtlCopyMemory(RetNewCallbackData->Iopb,Data->Iopb,sizeof(FLT_IO_PARAMETER_BLOCK));

			ClearFlag(RetNewCallbackData->Iopb->IrpFlags,IRP_PAGING_IO);
			RetNewCallbackData->Iopb->Parameters.SetFileInformation.InfoBuffer = fvi;
			RetNewCallbackData->Iopb->Parameters.SetFileInformation.Length = Length;
			RetNewCallbackData->Iopb->TargetFileObject = Ccb->StreamFileInfo.StreamObject;

			FltPerformSynchronousIo(RetNewCallbackData);

			Data->IoStatus = RetNewCallbackData->IoStatus;
			Status = RetNewCallbackData->IoStatus.Status;

		}

		if(!NT_SUCCESS(Status))
		{
			//DbgPrint("FltSetInformationFile 调用失败 %x\n",Status);
			X70FsdRaiseStatus(IrpContext,Status);
		}

		X70FsdLookupFileAllocationSize(IrpContext,Fcb,Ccb);

		if (CcIsFileCached(FileObject)) 
		{
			CcSetFileSizes( FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize );
		}

		FileObject->Flags |= FO_FILE_MODIFIED;
		SetFlag(Ccb->CcbState,CCB_FLAG_FILE_CHANGED);
		Status = STATUS_SUCCESS;
try_exit: NOTHING;
	}
	finally {

		if (AbnormalTermination() && UnwindFileSizes) 
		{

			Fcb->Header.FileSize.QuadPart = InitialFileSize.QuadPart;
			Fcb->Header.ValidDataLength.QuadPart = InitialValidDataLength.QuadPart;
			Fcb->ValidDataToDisk.QuadPart = InitialValidDataToDisk.QuadPart;

			if (FileObject->SectionObjectPointer->SharedCacheMap != NULL) 
			{

				CcGetFileSizePointer(FileObject)->QuadPart = Fcb->Header.FileSize.QuadPart;
			}
		}

		if (CacheMapInitialized) {

			CcUninitializeCacheMap( FileObject, NULL, NULL );
		}

		if ( ResourceAcquired ) {

			ExReleaseResourceLite( Fcb->Header.PagingIoResource );
		}
		if(fvi != NULL)
		{
			FltFreePoolAlignedWithTag(FltObjects->Instance,fvi,'fvi');
		}
		if(RetNewCallbackData != NULL)
		{
			FltFreeCallbackData(RetNewCallbackData);
		}
	}
	return Status;
}

NTSTATUS
X70FsdCommonFilePositionInfo (
								__inout PFLT_CALLBACK_DATA Data,
								__in    PCFLT_RELATED_OBJECTS FltObjects,
								__in	PIRP_CONTEXT IrpContext
								)

{
	PFLT_CALLBACK_DATA RetNewCallbackData = NULL;
	PFILE_POSITION_INFORMATION fpi = NULL;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	PVOID InfoBuffer;
	ULONG Length;
	LARGE_INTEGER OriginalByteOffset;
	NTSTATUS Status;
	BOOLEAN UnwindByteOffset = FALSE;
	PFCB Fcb;
	PCCB Ccb;
	PFILE_OBJECT FileObject;
	FILE_INFORMATION_CLASS FileInformationClass;

	try{

		Length = Iopb->Parameters.SetFileInformation.Length;
		InfoBuffer  = Iopb->Parameters.SetFileInformation.InfoBuffer ;
		FileInformationClass = Iopb->Parameters.SetFileInformation.FileInformationClass;
		FileObject = FltObjects->FileObject;

		Fcb = (PFCB)FileObject->FsContext;
		Ccb = FileObject->FsContext2;

		fpi = FltAllocatePoolAlignedWithTag(FltObjects->Instance,NonPagedPool,Length,'fpi');

		if(fpi == NULL)
		{
			try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
		}

		OriginalByteOffset = FileObject->CurrentByteOffset;
		UnwindByteOffset = TRUE;

		FileObject->CurrentByteOffset = fpi->CurrentByteOffset;

		fpi->CurrentByteOffset.QuadPart += Fcb->FileHeaderLength;

		Status = FltAllocateCallbackData(FltObjects->Instance,Ccb->StreamFileInfo.StreamObject,&RetNewCallbackData);

		if(NT_SUCCESS(Status))
		{
			RtlCopyMemory(RetNewCallbackData->Iopb,Data->Iopb,sizeof(FLT_IO_PARAMETER_BLOCK));

			ClearFlag(RetNewCallbackData->Iopb->IrpFlags,IRP_PAGING_IO);
			RetNewCallbackData->Iopb->Parameters.SetFileInformation.InfoBuffer = fpi;
			RetNewCallbackData->Iopb->Parameters.SetFileInformation.Length = Length;
			RetNewCallbackData->Iopb->TargetFileObject = Ccb->StreamFileInfo.StreamObject;

			FltPerformSynchronousIo(RetNewCallbackData);

			Data->IoStatus = RetNewCallbackData->IoStatus;
			Status = RetNewCallbackData->IoStatus.Status;

		}

		if(!NT_SUCCESS(Status))
		{
			//DbgPrint("FltSetInformationFile 调用失败 %x\n",Status);
			X70FsdRaiseStatus(IrpContext,Status);
		}

		Status = STATUS_SUCCESS;

try_exit: NOTHING;
	}
	finally
	{
		if (AbnormalTermination() && UnwindByteOffset) 
		{
			FileObject->CurrentByteOffset = OriginalByteOffset;
		}

		if(fpi != NULL)		
		{
			FltFreePoolAlignedWithTag(FltObjects->Instance,fpi,'fpi');
		}
		if(RetNewCallbackData != NULL)
		{
			FltFreeCallbackData(RetNewCallbackData);
		}
	}

	return Status;
}
