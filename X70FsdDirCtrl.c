#include "X70FsdData.h"
#include "X70FsdDirCtrl.h"
#include "X70FsdCreate.h"

//extern symmetric_key *skey;

extern UCHAR FileBegin[FILEBEGIN];

extern UCHAR Flag[OVERFLAG];

extern BOOLEAN	bDriverStarting;

FLT_PREOP_CALLBACK_STATUS
PtPreOperationDirCtrl(
					  __inout PFLT_CALLBACK_DATA Data,
					  __in PCFLT_RELATED_OBJECTS FltObjects,
					  __deref_out_opt PVOID *CompletionContext
					  )
{
	ULONG ProcType = 0;
	NTSTATUS Status;

	if(!bDriverStarting || !IsConcernedProcess(FltObjects,&Status,&ProcType)) 
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	//这里怎么处理合适呢
	//加密进程查询文件的函数要过滤大小
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;

}

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationDirCtrl(
					   __inout PFLT_CALLBACK_DATA Data,
					   __in PCFLT_RELATED_OBJECTS FltObjects,
					   __in_opt PVOID CompletionContext,
					   __in FLT_POST_OPERATION_FLAGS Flags
					   )
{
	FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;

	if (!NT_SUCCESS(Data->IoStatus.Status) || (Data->IoStatus.Information == 0)) 
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	if(IRP_MN_QUERY_DIRECTORY != Data->Iopb->MinorFunction )
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	if(FltDoCompletionProcessingWhenSafe(Data,
		FltObjects,
		CompletionContext,
		Flags,
		X70FsdPostDirCtrlWhenSafe,
		&retValue ))
	{
		return retValue;
	}
	else
	{
		Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
		Data->IoStatus.Information = 0;
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
X70FsdPostDirCtrlWhenSafe (
							 __inout PFLT_CALLBACK_DATA Data,
							 __in PCFLT_RELATED_OBJECTS FltObjects,
							 __in PVOID CompletionContext,
							 __in FLT_POST_OPERATION_FLAGS Flags
							 )
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PVOID origBuf;
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG_PTR RetLength = Data->IoStatus.Information;
	UNICODE_STRING FileFullName = {0};

	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( Flags );
	ASSERT(Data->IoStatus.Information != 0);

	if(iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress == NULL)
	{
		Status = FltLockUserBuffer( Data );

		if (!NT_SUCCESS(Status)) 
		{
			Data->IoStatus.Status = Status;
			Data->IoStatus.Information = 0;
			return FLT_POSTOP_FINISHED_PROCESSING;
		}
	}
	try
	{
		origBuf = MmGetSystemAddressForMdlSafe( iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
			NormalPagePriority );
		if (origBuf == NULL) 
		{
			Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			Data->IoStatus.Information = 0;
		} 
		else 
		{
			PFCB Fcb = NULL;
			UCHAR HashValue[MD5_LENGTH] = {0};

			switch(iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass)
			{
			case FileBothDirectoryInformation:
				{
					PFILE_BOTH_DIR_INFORMATION fbdi = origBuf;
					ULONG offset = 0;
					do
					{
						offset = fbdi->NextEntryOffset;

						if((fbdi->EndOfFile.QuadPart > FILE_HEADER_LENGTH )&&
							(fbdi->EndOfFile.QuadPart % CRYPT_UNIT == 0 ))
						{
							Status = GetFileFullName(Data,FltObjects,fbdi->FileName,fbdi->FileNameLength,&FileFullName);

							if(!NT_SUCCESS(Status))
							{
								try_return(Status);
							}
							if(!HashFilePath(&FileFullName,HashValue)) //hash失败了直接完成
							{	
								try_return(Status = STATUS_INSUFFICIENT_RESOURCES;);
							}
							if(FindExistFcb(HashValue,&Fcb))
							{
								fbdi->EndOfFile.QuadPart = Fcb->Header.FileSize.QuadPart;
								fbdi->AllocationSize.QuadPart = Fcb->Header.AllocationSize.QuadPart;
							}
							else //打开文件读取下是不是加密文件
							{
								LARGE_INTEGER RealFileSize = {0};
								BOOLEAN IsEnFile = FALSE;

								Status = GetFileRealSize(&FileFullName,FltObjects,&RealFileSize,&IsEnFile);

								if(NT_SUCCESS(Status) && IsEnFile)
								{
									fbdi->EndOfFile.QuadPart = RealFileSize.QuadPart;
									fbdi->AllocationSize.QuadPart -= FILE_HEADER_LENGTH;
								}
							}
						}
						fbdi = (PFILE_BOTH_DIR_INFORMATION)Add2Ptr(fbdi,offset);

					}
					while(offset != 0);
				}
				break;
			case FileDirectoryInformation:
				{
					PFILE_DIRECTORY_INFORMATION fdi = origBuf;
					ULONG offset = 0;
					do
					{
						offset = fdi->NextEntryOffset;

						if((fdi->EndOfFile.QuadPart > FILE_HEADER_LENGTH) && 
							(fdi->EndOfFile.QuadPart % CRYPT_UNIT == 0 ))
						{
							Status = GetFileFullName(Data,FltObjects,fdi->FileName,fdi->FileNameLength,&FileFullName);

							if(!NT_SUCCESS(Status))
							{
								try_return(Status);
							}
							if(!HashFilePath(&FileFullName,HashValue)) //hash失败了直接完成
							{	
								try_return(Status = STATUS_INSUFFICIENT_RESOURCES;);
							}
							if(FindExistFcb(HashValue,&Fcb))
							{
								fdi->EndOfFile.QuadPart = Fcb->Header.FileSize.QuadPart;
								fdi->AllocationSize.QuadPart = Fcb->Header.AllocationSize.QuadPart;
							}
							else //打开文件读取下是不是加密文件
							{
								LARGE_INTEGER RealFileSize = {0};
								BOOLEAN IsEnFile = FALSE;

								Status = GetFileRealSize(&FileFullName,FltObjects,&RealFileSize,&IsEnFile);

								if(NT_SUCCESS(Status) && IsEnFile)
								{
									fdi->EndOfFile.QuadPart = RealFileSize.QuadPart;
									fdi->AllocationSize.QuadPart -= FILE_HEADER_LENGTH;
								}
							}
						}
						fdi = (PFILE_DIRECTORY_INFORMATION)Add2Ptr(fdi,offset);

					}
					while(offset != 0);
				}
				break;
			case FileFullDirectoryInformation:
				{
					PFILE_FULL_DIR_INFORMATION ffdi = origBuf;
					ULONG offset = 0;
					do
					{
						offset = ffdi->NextEntryOffset;

						if((ffdi->EndOfFile.QuadPart > FILE_HEADER_LENGTH) &&
							(ffdi->EndOfFile.QuadPart % CRYPT_UNIT == 0 ))
						{
							Status = GetFileFullName(Data,FltObjects,ffdi->FileName,ffdi->FileNameLength,&FileFullName);

							if(!NT_SUCCESS(Status))
							{
								try_return(Status);
							}
							if(!HashFilePath(&FileFullName,HashValue)) //hash失败了直接完成
							{	
								try_return(Status = STATUS_INSUFFICIENT_RESOURCES;);
							}
							if(FindExistFcb(HashValue,&Fcb))
							{
								ffdi->EndOfFile.QuadPart = Fcb->Header.FileSize.QuadPart;
								ffdi->AllocationSize.QuadPart = Fcb->Header.AllocationSize.QuadPart;
							}
							else //打开文件读取下是不是加密文件
							{
								LARGE_INTEGER RealFileSize = {0};
								BOOLEAN IsEnFile = FALSE;

								Status = GetFileRealSize(&FileFullName,FltObjects,&RealFileSize,&IsEnFile);

								if(NT_SUCCESS(Status) && IsEnFile)
								{
									ffdi->EndOfFile.QuadPart = RealFileSize.QuadPart;
									ffdi->AllocationSize.QuadPart -= FILE_HEADER_LENGTH;
								}
							}
						}
						ffdi = (PFILE_FULL_DIR_INFORMATION)Add2Ptr(ffdi,offset);

					}
					while(offset != 0);
				}
				break;
			case FileIdBothDirectoryInformation:
				{
					PFILE_ID_BOTH_DIR_INFORMATION fibdi = origBuf;
					ULONG offset = 0;
					do
					{
						offset = fibdi->NextEntryOffset;
						if((fibdi->EndOfFile.QuadPart > FILE_HEADER_LENGTH) &&
							(fibdi->EndOfFile.QuadPart % CRYPT_UNIT == 0))
						{
							Status = GetFileFullName(Data,FltObjects,fibdi->FileName,fibdi->FileNameLength,&FileFullName);

							if(!NT_SUCCESS(Status))
							{
								try_return(Status);
							}
							if(!HashFilePath(&FileFullName,HashValue)) //hash失败了直接完成
							{	
								try_return(Status = STATUS_INSUFFICIENT_RESOURCES;);
							}
							if(FindExistFcb(HashValue,&Fcb))
							{
								fibdi->EndOfFile.QuadPart = Fcb->Header.FileSize.QuadPart;
								fibdi->AllocationSize.QuadPart = Fcb->Header.AllocationSize.QuadPart;
							}
							else //打开文件读取下是不是加密文件
							{
								LARGE_INTEGER RealFileSize = {0};
								BOOLEAN IsEnFile = FALSE;

								Status = GetFileRealSize(&FileFullName,FltObjects,&RealFileSize,&IsEnFile);

								if(NT_SUCCESS(Status) && IsEnFile)
								{
									fibdi->EndOfFile.QuadPart = RealFileSize.QuadPart;
									fibdi->AllocationSize.QuadPart -= FILE_HEADER_LENGTH;
								}
							}
						}

						fibdi = (PFILE_ID_BOTH_DIR_INFORMATION)Add2Ptr(fibdi,offset);
						
					}
					while(offset != 0);
				}
				break;
			case FileIdFullDirectoryInformation:
				{
					PFILE_ID_FULL_DIR_INFORMATION fifdi = origBuf;
					ULONG offset = 0;
					do
					{
						offset = fifdi->NextEntryOffset;
						if((fifdi->EndOfFile.QuadPart > FILE_HEADER_LENGTH) && 
							(fifdi->EndOfFile.QuadPart % CRYPT_UNIT == 0))
						{
							Status = GetFileFullName(Data,FltObjects,fifdi->FileName,fifdi->FileNameLength,&FileFullName);

							if(!NT_SUCCESS(Status))
							{
								try_return(Status);
							}
							if(!HashFilePath(&FileFullName,HashValue)) //hash失败了直接完成
							{	
								try_return(Status = STATUS_INSUFFICIENT_RESOURCES;);
							}
							if(FindExistFcb(HashValue,&Fcb))
							{
								fifdi->EndOfFile.QuadPart = Fcb->Header.FileSize.QuadPart;
								fifdi->AllocationSize.QuadPart = Fcb->Header.AllocationSize.QuadPart;
							}
							else //打开文件读取下是不是加密文件
							{

								LARGE_INTEGER RealFileSize = {0};
								BOOLEAN IsEnFile = FALSE;

								Status = GetFileRealSize(&FileFullName,FltObjects,&RealFileSize,&IsEnFile);

								if(NT_SUCCESS(Status) && IsEnFile)
								{
									fifdi->EndOfFile.QuadPart = RealFileSize.QuadPart;
									fifdi->AllocationSize.QuadPart -= FILE_HEADER_LENGTH;
								}
							}
						}

						fifdi = (PFILE_ID_FULL_DIR_INFORMATION)Add2Ptr(fifdi,offset);

					}
					while(offset != 0);
				}
				break;
			default:
				break;
			}
			Status = Data->IoStatus.Status;
		}
try_exit:	NOTHING;
		if(!NT_SUCCESS(Status))
		{
			DbgPrint("目录查询失败 \n");
			Data->IoStatus.Status = Status;
		}
	}
	finally
	{
		if(AbnormalTermination())
		{
			Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		}
		if(FileFullName.Buffer != NULL)
		{
			FltFreePoolAlignedWithTag(FltObjects->Instance,FileFullName.Buffer,'hash');
			FileFullName.Buffer = NULL;
		}
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS GetFileFullName(PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS FltObjects,PWCHAR FileName,ULONG FileNameLength,PUNICODE_STRING pFileFullName)
{
	NTSTATUS Status = STATUS_SUCCESS;

	UNICODE_STRING VolumeName = {0};
	PFILE_NAME_INFORMATION fni = NULL;

	ULONG LengthReturned = 0;
	ULONG Length = 0;
	try{
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
			try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
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
			Data->Iopb->TargetFileObject,
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
				Data->Iopb->TargetFileObject,
				fni,
				Length,
				FileNameInformation,
				&LengthReturned 
				); 			

		}
		if(NT_SUCCESS(Status))
		{
			WCHAR Link = L'\\';

			Length = fni->FileNameLength + VolumeName.Length +FileNameLength + 2*sizeof(WCHAR);

			if(pFileFullName->Buffer != NULL)
			{
				FltFreePoolAlignedWithTag(FltObjects->Instance,pFileFullName->Buffer,'hash');
				pFileFullName->Buffer = NULL;
			}

			pFileFullName->Buffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance,PagedPool,Length ,'hash');

			if(pFileFullName->Buffer == NULL)
			{
				try_return(Status = STATUS_INSUFFICIENT_RESOURCES;);
			}
			RtlZeroMemory(pFileFullName->Buffer,Length);

			pFileFullName->Length = (USHORT)(Length - sizeof(WCHAR));
			pFileFullName->MaximumLength = (USHORT)Length;

			RtlCopyMemory(pFileFullName->Buffer,VolumeName.Buffer,VolumeName.Length);
			RtlCopyMemory(Add2Ptr(pFileFullName->Buffer,VolumeName.Length),fni->FileName,fni->FileNameLength);
			if(fni->FileName[fni->FileNameLength/sizeof(WCHAR)-1] != Link)
			{
				RtlCopyMemory(Add2Ptr(pFileFullName->Buffer,(VolumeName.Length+fni->FileNameLength)),&Link,sizeof(WCHAR));
				RtlCopyMemory(Add2Ptr(pFileFullName->Buffer,(VolumeName.Length+fni->FileNameLength+sizeof(WCHAR))),FileName,FileNameLength);
			}
			else
			{
				RtlCopyMemory(Add2Ptr(pFileFullName->Buffer,(VolumeName.Length+fni->FileNameLength)),FileName,FileNameLength);
			}

		}
try_exit:	NOTHING;
	}
	finally
	{
		if(VolumeName.Buffer != NULL)
		{
			FltFreePoolAlignedWithTag(FltObjects->Instance,VolumeName.Buffer,'von');
		}
		if(fni != NULL)
		{
			FltFreePoolAlignedWithTag(FltObjects->Instance,fni,'fni');
		}
	}
	return Status;
}

NTSTATUS GetFileRealSize(PUNICODE_STRING pFileFullName,PCFLT_RELATED_OBJECTS FltObjects,PLARGE_INTEGER pRealFileSize,PBOOLEAN IsEnFile)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES ob;
	HANDLE FileHandle;
	PFILE_OBJECT FileObject = NULL;
	PFILE_HEADER_CRYPTION pFileHeader = NULL;
	LARGE_INTEGER ByteOffset;
	IO_STATUS_BLOCK IoStatus;
	try
	{
		InitializeObjectAttributes(&ob, pFileFullName, OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE, NULL,NULL) ;

		Status = FltCreateFile (FltObjects->Filter,
			FltObjects->Instance,
			&FileHandle,
			FILE_READ_DATA,
			&ob,
			&IoStatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_VALID_FLAGS,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE,
			NULL,
			0,
			IO_IGNORE_SHARE_ACCESS_CHECK
			); 

		if(!NT_SUCCESS(Status))
		{
			try_return( Status );
		}

		Status = ObReferenceObjectByHandle(FileHandle,
			0,
			*IoFileObjectType,
			KernelMode,
			&FileObject,
			NULL);

		if(!NT_SUCCESS(Status))
		{
			FltClose(FileHandle);
			try_return( Status );
		}

		//首先创建一个加密头
		pFileHeader = FltAllocatePoolAlignedWithTag(FltObjects->Instance,PagedPool,FILE_HEADER_LENGTH,'rh');  //文件头已经跟扇区大小对齐了，所以肯定打开可以成功

		if(pFileHeader == NULL)
		{
			DbgPrint("加密头读取失败 \n");
			try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
		}

		RtlZeroMemory(pFileHeader,FILE_HEADER_LENGTH);

		ByteOffset.QuadPart = 0;
		//读取加密文件
		Status = FltReadFile(
			FltObjects->Instance,
			FileObject,
			&ByteOffset,
			FILE_HEADER_LENGTH,
			pFileHeader,
			/*FLTFL_IO_OPERATION_NON_CACHED |*/ FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, //非缓存的打开
			NULL,
			NULL,
			NULL
			);

		if(NT_SUCCESS(Status))
		{
			ULONG i;

			//for(i = 0 ; i < FILE_HEADER_LENGTH/CRYPT_UNIT ; i++)
			//{
			//	aes_ecb_decrypt(Add2Ptr(pFileHeader,i*CRYPT_UNIT),Add2Ptr(pFileHeader,i*CRYPT_UNIT),skey);
			//}
			if((RtlCompareMemory(pFileHeader->FileBegin,FileBegin,sizeof(FileBegin)) == sizeof(FileBegin))
				&& (RtlCompareMemory(pFileHeader->Flag,Flag,sizeof(Flag)) == sizeof(Flag)))
			{
				*IsEnFile = TRUE;

				RtlCopyMemory(pRealFileSize,pFileHeader->RealFileSize,sizeof(LARGE_INTEGER));	
			
			}
			else
			{
				*IsEnFile = FALSE;
			}
		}
try_exit: NOTHING;
	}
	finally
	{
		if(pFileHeader != NULL)
		{
			FltFreePoolAlignedWithTag(FltObjects->Instance,pFileHeader,'rh');
		}
		if(FileObject != NULL)
		{
			FltClose(FileHandle);
			ObDereferenceObject(FileObject);
		}
	}
	return Status;
}