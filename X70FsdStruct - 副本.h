#ifndef __LAYERFSDSTRUCT_H__
#define __LAYERFSDSTRUCT_H__
#pragma warning(disable : 4995)
//#pragma warning(error:4100)   // Unreferenced formal parameter
//#pragma warning(error:4101)   // Unreferenced local variable
//只做参考就可以了
#include "ntifs.h"
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include  "fltkernel.h"
#include "tomcrypt.h"

//驱动配置
//#define CV

#ifdef CV
__declspec(dllimport) void VirtualizerStart(void);
__declspec(dllimport) void VirtualizerEnd(void);
#endif

#define TEST //调试模式
#define ALL_OWN_FCB 

#define USE_CACHE_READWRITE
//#define CHANGE_PAGINGIO  //改变pagingio的方式,只保留非分页跟pagingio标志
#define CHANGE_TOP_IRP
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define GUID_SIZE		36
#define LICENSING_SIZE	1024  

#define MAX_ZERO_THRESHOLD     (0x00400000)
#define NUMHASH 70 //no prime :)

#define MAX_KEY_LENGTH 128
#define AES_KEY_LENGTH 16
static const CHAR   TestKey[AES_KEY_LENGTH] = "driver by xiao70";
static const CHAR	DefaultKey[AES_KEY_LENGTH]	={0x12,0xff,0x77,0x17,0xfd,0xB4,0xcf,0xE9,0x99,0x39,0x4D,0xfb,0x1B,0x8a,0xce,0x5B};


#define SESSION_DEF_DATA			 L"DefaultSessionData"
#define	PROC_CONFIG_DATA		 L"ProcConfigData"

#define NAMED_PIPE_PREFIX                L"\\PIPE"
#define NAMED_PIPE_PREFIX_LENGTH         (sizeof(NAMED_PIPE_PREFIX)-sizeof(WCHAR))

#define MAIL_SLOT_PREFIX                L"\\MAILSLOT"
#define MAIL_SLOT_PREFIX_LENGTH         (sizeof(MAIL_SLOT_PREFIX)-sizeof(WCHAR))

#define MAX_PATH 260
#define MD5_LENGTH	16
#define SHA256_LENGTH 32
#define NT_PROCNAMELEN  16

#define FILE_HASH_LENGTH 1024*4
#define CRYPT_UNIT 16

#define STORAGE_SECTOR_SIZE 512 //自动获得

typedef CSHORT	NODE_BYTE_SIZE;
typedef CSHORT	NODE_TYPE_CODE;
typedef NODE_TYPE_CODE *PNODE_TYPE_CODE;

#define LAYER_NTC_FCB                      ((NODE_TYPE_CODE)0x7070)	

#define FCB_LOOKUP_ALLOCATIONSIZE_HINT   ((LONGLONG) -1)

#define X70FsdNormalizeAndRaiseStatus(IRPCONTEXT,STATUS) {                         \
    (IRPCONTEXT)->ExceptionStatus = (STATUS);                                   \
    ExRaiseStatus(FsRtlNormalizeNtstatus((STATUS),STATUS_UNEXPECTED_IO_ERROR)); \
}

//#define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))

//#define PtrOffset(B,O) ((ULONG)((ULONG)(O) - (ULONG)(B)))

#define try_return(S) { S; goto try_exit; }

#define IsFileDeleted(IRPCONTEXT,FCB)                      \
    (FlagOn((FCB)->FcbState, SCB_STATE_DELETE_ON_CLOSE) && \
     ((FCB)->OpenHandleCount == 0))

#define X70FsdRestoreTopLevelIrp(TLC) {                   \
	(TLC)->X70Fsd = 0;                                    \
	IoSetTopLevelIrp( (PIRP) (TLC)->SavedTopLevelIrp ); \
}

#define CanFsdWait(DATA) FltIsOperationSynchronous(DATA)

#define X70FsdUpdateIrpContextWithTopLevel(IC,TLC) {          \
	if ((TLC)->TopLevelIrpContext == NULL) {                \
	(TLC)->TopLevelIrpContext = (IC);                   \
	}                                                       \
	(IC)->TopLevelIrpContext = (TLC)->TopLevelIrpContext;   \
}
#define X70FsdIsTopLevelRequest(IC) (                                 \
	((BOOLEAN) (((PTOP_LEVEL_CONTEXT)IoGetTopLevelIrp())->TopLevelRequest) &&     \
	(((IC) == (IC)->TopLevelIrpContext)))               \
	)


#define X70FsdReleaseFcb(IRPCONTEXT,Fcb) {             \
	ExReleaseResourceLite( (Fcb)->Header.Resource );    \
}

#define X70FsdResetExceptionState( IRPCONTEXT ) {          \
	(IRPCONTEXT)->ExceptionStatus = STATUS_SUCCESS;     \
}

typedef struct _VS_FIXEDFILEINFO { 
  ULONG dwSignature; 
  ULONG dwStrucVersion; 
  ULONG dwFileVersionMS; 
  ULONG dwFileVersionLS; 
  ULONG dwProductVersionMS; 
  ULONG dwProductVersionLS; 
  ULONG dwFileFlagsMask; 
  ULONG dwFileFlags; 
  ULONG dwFileOS; 
  ULONG dwFileType; 
  ULONG dwFileSubtype; 
  ULONG dwFileDateMS; 
  ULONG dwFileDateLS; 
} VS_FIXEDFILEINFO,*PVS_FIXEDFILEINFO; 

typedef struct _VS_VERSIONINFO{ 
  USHORT wLength; 
  USHORT wValueLength; 
  USHORT wType; 
  WCHAR szKey[1]; 
  USHORT Padding1[1]; 
} VS_VERSIONINFO,*PVS_VERSIONINFO;

typedef struct _BASE_VERSION_STRUCT {
  USHORT        wLength; 
  USHORT        wValueLength; 
  USHORT        wType; 
  WCHAR         szKey[1]; 
  USHORT        Padding[1];
}BASE_VERSION_STRUCT,*PBASE_VERSION_STRUCT;

////////////////////////////////////OPLOCK////////////////////////////////////////////////////////////

#define IOCTL_LMR_DISABLE_LOCAL_BUFFERING 0x00140390

#if (NTDDI_VERSION < NTDDI_WIN7)

#define OPLOCK_FLAG_OPLOCK_KEY_CHECK_ONLY   0x00000002
#define OPLOCK_FLAG_BACK_OUT_ATOMIC_OPLOCK  0x00000004
#define OPLOCK_FLAG_IGNORE_OPLOCK_KEYS      0x00000008

#define OPLOCK_FSCTRL_FLAG_ALL_KEYS_MATCH   0x00000001

#define FSCTL_REQUEST_OPLOCK                CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 144, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_READ_FILE_USN_DATA            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 58,  METHOD_NEITHER, FILE_ANY_ACCESS) 
//
//  Structures for FSCTL_REQUEST_OPLOCK
//

#define OPLOCK_LEVEL_CACHE_READ         (0x00000001)
#define OPLOCK_LEVEL_CACHE_HANDLE       (0x00000002)
#define OPLOCK_LEVEL_CACHE_WRITE        (0x00000004)

#define REQUEST_OPLOCK_INPUT_FLAG_REQUEST               (0x00000001)
#define REQUEST_OPLOCK_INPUT_FLAG_ACK                   (0x00000002)
#define REQUEST_OPLOCK_INPUT_FLAG_COMPLETE_ACK_ON_CLOSE (0x00000004)

#define REQUEST_OPLOCK_CURRENT_VERSION          1

typedef struct _REQUEST_OPLOCK_INPUT_BUFFER 
{

    USHORT StructureVersion;

    USHORT StructureLength;


    ULONG RequestedOplockLevel;

    ULONG Flags;

} REQUEST_OPLOCK_INPUT_BUFFER, *PREQUEST_OPLOCK_INPUT_BUFFER;

#define REQUEST_OPLOCK_OUTPUT_FLAG_ACK_REQUIRED     (0x00000001)
#define REQUEST_OPLOCK_OUTPUT_FLAG_MODES_PROVIDED   (0x00000002)


typedef struct _REQUEST_OPLOCK_OUTPUT_BUFFER {

    USHORT StructureVersion;

    USHORT StructureLength;

    ULONG OriginalOplockLevel;

    ULONG NewOplockLevel;

    ULONG Flags;

    ACCESS_MASK AccessMode;

    USHORT ShareMode;

} REQUEST_OPLOCK_OUTPUT_BUFFER, *PREQUEST_OPLOCK_OUTPUT_BUFFER;

#endif
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef
NTSTATUS
(*PGET_VERSION) (
				 __inout PRTL_OSVERSIONINFOEXW VersionInformation
				 );

typedef 
FLT_PREOP_CALLBACK_STATUS 
(*PFLT_CHECK_OPLOCK_EX)(
  __in      POPLOCK Oplock,
  __in      PFLT_CALLBACK_DATA CallbackData,
  __in      ULONG Flags,
  __in_opt  PVOID Context,
  __in_opt  PFLTOPLOCK_WAIT_COMPLETE_ROUTINE WaitCompletionRoutine,
  __in_opt  PFLTOPLOCK_PREPOST_CALLBACKDATA_ROUTINE PrePostCallbackDataRoutine
);

typedef 
FLT_PREOP_CALLBACK_STATUS
(*PFLT_OPLOCK_BREAK_H)
(
  __in      POPLOCK Oplock,
  __in      PFLT_CALLBACK_DATA CallbackData,
  __in      ULONG Flags,
  __in_opt  PVOID Context,
  __in_opt  PFLTOPLOCK_WAIT_COMPLETE_ROUTINE WaitCompletionRoutine,
  __in_opt  PFLTOPLOCK_PREPOST_CALLBACKDATA_ROUTINE PrePostCallbackDataRoutine
	
);

typedef 
NTSTATUS 
(*PFsRtlChangeBackingFileObject)(
    PFILE_OBJECT CurrentFileObject,
    PFILE_OBJECT NewFileObject,
    FSRTL_CHANGE_BACKING_TYPE ChangeBackingType,
    ULONG Flags
);

typedef
ULONG
  (*PMmDoesFileHaveUserWritableReferences) (
    __in PSECTION_OBJECT_POINTERS  SectionPointer
	);

typedef struct _DYNAMIC_FUNCTION_POINTERS {

	PGET_VERSION GetVersion;

	PFLT_CHECK_OPLOCK_EX	CheckOplockEx;
	PFLT_OPLOCK_BREAK_H		OplockBreakH;
	PMmDoesFileHaveUserWritableReferences pMmDoesFileHaveUserWritableReferences;
	PFsRtlChangeBackingFileObject	pFsRtlChangeBackingFileObject;

} DYNAMIC_FUNCTION_POINTERS, *PDYNAMIC_FUNCTION_POINTERS;

#define IS_FLT_FILE_LOCK() ((gOsMajorVersion > 5) || \
	(gOsMajorVersion == 5 && gOsMinorVersion == 1 && gOsServicePackMajor >=2 ) ||\
	(gOsMajorVersion == 5 && gOsMinorVersion == 2 && gOsServicePackMajor >=1 )) 

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define MAX_SCB_ASYNC_ACQUIRE               (0xf000)


#define BugCheckFileId                   (NTFS_BUG_CHECK_ATTRSUP)

#define NTFS_BUG_CHECK_ALLOCSUP          (0x00010000)
#define NTFS_BUG_CHECK_ATTRDATA          (0x00020000)
#define NTFS_BUG_CHECK_ATTRSUP           (0x00030000)
#define NTFS_BUG_CHECK_BITMPSUP          (0x00040000)
#define NTFS_BUG_CHECK_CACHESUP          (0x00050000)
#define NTFS_BUG_CHECK_CHECKSUP          (0x00060000)
#define NTFS_BUG_CHECK_CLEANUP           (0x00070000)
#define NTFS_BUG_CHECK_CLOST             (0x00080000)
#define NTFS_BUG_CHECK_COLATSUP          (0x00090000)
#define NTFS_BUG_CHECK_CREATE            (0x000a0000)
#define NTFS_BUG_CHECK_DEVCTRL           (0x000b0000)
#define NTFS_BUG_CHECK_DEVIOSUP          (0x000c0000)
#define NTFS_BUG_CHECK_DIRCTRL           (0x000d0000)
#define NTFS_BUG_CHECK_EA                (0x000e0000)
#define NTFS_BUG_CHECK_FILEINFO          (0x000f0000)
#define NTFS_BUG_CHECK_FILOBSUP          (0x00100000)
#define NTFS_BUG_CHECK_FLUSH             (0x00110000)
#define NTFS_BUG_CHECK_FSCTRL            (0x00120000)
#define NTFS_BUG_CHECK_FSPDISP           (0x00130000)
#define NTFS_BUG_CHECK_INDEXSUP          (0x00140000)
#define NTFS_BUG_CHECK_LOCKCTRL          (0x00150000)
#define NTFS_BUG_CHECK_LOGSUP            (0x00160000)
#define NTFS_BUG_CHECK_MFTSUP            (0x00170000)
#define NTFS_BUG_CHECK_NAMESUP           (0x00180000)
#define NTFS_BUG_CHECK_NTFSDATA          (0x00190000)
#define NTFS_BUG_CHECK_NTFSINIT          (0x001a0000)
#define NTFS_BUG_CHECK_PREFXSUP          (0x001b0000)
#define NTFS_BUG_CHECK_READ              (0x001c0000)
#define NTFS_BUG_CHECK_RESRCSUP          (0x001d0000)
#define NTFS_BUG_CHECK_RESTRSUP          (0x001e0000)
#define NTFS_BUG_CHECK_SECURSUP          (0x001f0000)
#define NTFS_BUG_CHECK_SEINFO            (0x00200000)
#define NTFS_BUG_CHECK_SHUTDOWN          (0x00210000)
#define NTFS_BUG_CHECK_STRUCSUP          (0x00220000)
#define NTFS_BUG_CHECK_VERFYSUP          (0x00230000)
#define NTFS_BUG_CHECK_VOLINFO           (0x00240000)
#define NTFS_BUG_CHECK_WORKQUE           (0x00250000)
#define NTFS_BUG_CHECK_WRITE             (0x00260000)

#define X70FsdBugCheck(A,B,C) { KeBugCheckEx(NTFS_FILE_SYSTEM, BugCheckFileId | __LINE__, A, B, C ); }

//////////////////////////////////////////////////////////////////////////接口控制定义//////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////r3回调相关/////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////进程回调////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////进程相关///////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////文件头的定义////////////////////////////////////////////////////////////////


#define FILE_HEADER_LENGTH	1024*4

#define KEY_MAX_SIZE	MAX_KEY_LENGTH
#define OVERFLAG		6
#define VERSION_INFO	12
#define READFILESIZE	sizeof(LARGE_INTEGER)
#define FILEBEGIN		8

#define CHKSUM_SIZE	16
#define AUTOCMP_SIZE    	4
#define ZERO_SIZE		FILE_HEADER_LENGTH - (FILEBEGIN + VERSION_INFO + READFILESIZE + CHKSUM_SIZE + LICENSING_SIZE + OVERFLAG)

typedef union _FILE_HEADER_CRYPTION //注意结构对齐
{
	struct 
	{
		UCHAR	FileBegin[FILEBEGIN];
		UCHAR	ZeroSize[ZERO_SIZE];
		UCHAR	VersionInfo[VERSION_INFO];
		UCHAR   RealFileSize[READFILESIZE];

		UCHAR	PublicKey[KEY_MAX_SIZE];
		UCHAR	FileGuid[GUID_SIZE];

		UCHAR	LicensingChkSum[CHKSUM_SIZE];
		UCHAR	LicensingInfo[LICENSING_SIZE];		
		UCHAR	Flag[OVERFLAG];
	};
	UCHAR Text[FILE_HEADER_LENGTH];

}FILE_HEADER_CRYPTION,*PFILE_HEADER_CRYPTION;


#define	GuidLen						37
#define	NameLen						41
typedef struct	_UserInfo_Ver001
{
	UCHAR	sUserSN[GuidLen];
	UCHAR	sUserName[NameLen];
	UCHAR	sGroupSN[GuidLen];
	UCHAR	sGroupName[NameLen];

}UserInfo_Ver001,*PUserInfo_Ver001;

#define USERINFOLEN sizeof(UserInfo_Ver001)


///////////////////////////////////////////////////////////////////驱动使用结构的定义///////////////////////////////////////////////////////////////////////////////////

#define MAX_SECTOR_SIZE    FILE_HEADER_LENGTH //磁盘最大扇区大小

typedef enum _MODIFY_TYPE
{
	FILE_MODIFY_SIZE = 0,
	FILE_MODIFY_CLEANUP,

}MODIFY_TYPE,*PMODIFY_TYPE;

typedef enum _CACHE_TYPE
{
	CACHE_ALLOW = 0,
	CACHE_READ,
	CACHE_READWRITE,
	CACHE_DISABLE

}CACHE_TYPE,*PCACHE_TYPE;

typedef enum _CREATE_ACCESS_TYPE
{
	CREATE_ACCESS_INVALID = 0,
	CREATE_ACCESS_READ,
	CREATE_ACCESS_WRITE,
	CREATE_ACCESS_READWRITE,

}CREATE_ACCESS_TYPE,*PCREATE_ACCESS_TYPE;

#define FILE_NAME_LENGTH	1024

typedef struct _VOLUME_CONTEXT {

	ULONG SectorSize; //扇区大小

	ULONG SectorsPerAllocationUnit; //一个簇几个扇区

	PERESOURCE VolResource;

	DEVICE_TYPE	DeviceType; 

	BOOLEAN IsWritable;

} VOLUME_CONTEXT, *PVOLUME_CONTEXT;

#define MIN_SECTOR_SIZE 0x200

#define FCB_STATE_FILE_DELETED              (0x00000001)
#define FCB_STATE_NOTIFY_RESIZE_STREAM      (0x00000002)

typedef struct _FCB *PFCB;

typedef struct _STREAM_FILE_INFO{

	PFILE_OBJECT StreamObject;

	HANDLE StreamHandle;

	PFCB orgFcb;

	PERESOURCE FO_Resource;

	FAST_MUTEX FileObjectMutex;

}STREAM_FILE_INFO,*PSTREAM_FILE_INFO;

typedef struct _FCB {

	FSRTL_ADVANCED_FCB_HEADER Header;

	FAST_MUTEX	AdvancedFcbHeaderMutex;

	SECTION_OBJECT_POINTERS SectionObjectPointers;

	LARGE_INTEGER	ValidDataToDisk; //涵义有所不同,这里为真实的文件大小

	PKEVENT MoveFileEvent;

	CACHE_UNINITIALIZE_EVENT	UninitializeCompleteEvent;

	BOOLEAN IsEnFile;

	ULONG FileType;

	//后面暂时忽略
	ULONG FcbState;

	CACHE_TYPE CacheType;

	PFILE_OBJECT CacheObject; //创建缓存的对象

	PERESOURCE  EncryptResource;

	PVOID LazyWriteThread[2];

	ULONG FileHeaderLength;

	OPLOCK Oplock;

	ULONG ReferenceCount; //引用计数

	ULONG OpenHandleCount; //句柄计数

	ULONG NonCachedCleanupCount;

	ULONG OutstandingAsyncWrites;

	PKEVENT OutstandingAsyncEvent;

	SHARE_ACCESS ShareAccess; //共享权限

	UCHAR HashValue[MD5_LENGTH];

	UNICODE_STRING FileFullName;

	HANDLE CcFileHandle;
	PFILE_OBJECT CcFileObject; //下层缓存对象

	PFILE_LOCK FileLock;

	FILE_ACCESS FileAccess;

	//FLT_CALLBACK_DATA_QUEUE Cbdq;
 //   LIST_ENTRY QueueHead;
 //   FAST_MUTEX Lock;
	//KEVENT TeardownEvent;
	CHAR FileKey[AES_KEY_LENGTH];
	symmetric_key CryptionKey;

	STREAM_FILE_INFO SwapFileInfo;
}FCB ;

typedef struct _CCB{

	ULONG CcbState;

	ULONG ProcType;
	
	FILE_ACCESS FileAccess;

	UCHAR ProcessGuid[GUID_SIZE];

	STREAM_FILE_INFO StreamFileInfo;//保存交换数据用的文件信息

}CCB,*PCCB;

typedef struct _LAYERFSD_FILE_ATTRIBUTES 
{
	BOOLEAN FileExist;

	ULONG FileAttributes;

}LAYERFSD_FILE_ATTRIBUTES,*PLAYERFSD_FILE_ATTRIBUTES;



typedef struct _LAYERFSD_IO_CONTEXT{

	PFLT_CALLBACK_DATA Data;

	PVOID SwapBuffer;
	
	PVOID SwapMdl;

	BOOLEAN	PagingIo;

	PIRP TopLevelIrp;

	BOOLEAN	AllocatedIoContext;

	ULONG FileHeaderLength;

	BOOLEAN IsEnFile;

	PCFLT_RELATED_OBJECTS FltObjects;

	PFLT_INSTANCE Instance;

	PVOLUME_CONTEXT volCtx;

    PVOID SystemBuffer;

	LARGE_INTEGER ByteOffset;

	ULONG ByteCount;
	
	ULONG_PTR RetBytes;

	NTSTATUS Status;

	symmetric_key * pCryptionKey;

	union
	{
		struct {
			PERESOURCE Resource;
			PERESOURCE Resource2;
			PERESOURCE FO_Resource;
			ERESOURCE_THREAD ResourceThreadId;
			ULONG RequestedByteCount;
			ULONG ByteCount;
			PFILE_OBJECT FileObject;
			PFAST_MUTEX pFileObjectMutex;
			PKEVENT OutstandingAsyncEvent;
			PULONG OutstandingAsyncWrites;

		} Async;

		KEVENT SyncEvent;

	} Wait;

}LAYERFSD_IO_CONTEXT,*PLAYERFSD_IO_CONTEXT;

typedef struct _CREATE_INFO
{
	PFCB Fcb;
	
	PCCB Ccb;

	ULONG FileType;

	ULONG_PTR Information;

	PFLT_FILE_NAME_INFORMATION nameInfo;
	
	PFILE_OBJECT StreamObject;

	HANDLE StreamHandle;

	LARGE_INTEGER  FileSize;

	LARGE_INTEGER  FileAllocationSize;

	LARGE_INTEGER  RealFileSize;

	PFILE_HEADER_CRYPTION	pFileHeader;

	CHAR	FileKey[AES_KEY_LENGTH];

	PERESOURCE Resource;

	ULONG ProcType;

	BOOLEAN ReissueIo;

	BOOLEAN Network;

	BOOLEAN RealSize;

	BOOLEAN DeleteOnClose;

	BOOLEAN DecrementHeader; //需要减去头部大小

	BOOLEAN IsWriteHeader;

	BOOLEAN OplockPostIrp;

	BOOLEAN IsEnFile;

	BOOLEAN Other; //其他人的文档

	FILE_ACCESS FileAccess;

	ACCESS_MASK	DesiredAccess;
	
	UCHAR ProcessGuid[GUID_SIZE];

}CREATE_INFO,*PCREATE_INFO;

typedef struct _IRP_CONTEXT {

	NODE_TYPE_CODE NodeTypeCode;
	NODE_BYTE_SIZE NodeByteSize;

	ULONG Flags;

	PFLT_CALLBACK_DATA OriginatingData;

	PDEVICE_OBJECT DeviceObject; 

	PFILE_OBJECT FileObject;

	UCHAR MajorFunction; //

	UCHAR MinorFunction; //

	HANDLE ProcessId;

	//struct _IRP_CONTEXT *TopLevelIrpContext; //大都数指向自己 保存顶层irp

	PIO_WORKITEM WorkItem; //工作项

	PFCB FcbWithPagingExclusive;

	PLAYERFSD_IO_CONTEXT X70FsdIoContext;

	NTSTATUS	ExceptionStatus;

	FLT_PREOP_CALLBACK_STATUS FltStatus;

	PMDL	AllocateMdl;

	FLT_RELATED_OBJECTS FltObjects;

	PCFLT_RELATED_OBJECTS OriginatingFltObjects;

	ULONG SectorSize;
	
	ULONG SectorsPerAllocationUnit;

	CREATE_INFO CreateInfo;

}IRP_CONTEXT,*PIRP_CONTEXT;

//定义上下文标志

#define IRP_CONTEXT_FLAG_RECURSIVE_CALL				(0x00000001)
#define IRP_CONTEXT_FLAG_WAIT						(0x00000002)
#define IRP_CONTEXT_FLAG_WRITE_THROUGH				(0x00000004)
#define IRP_CONTEXT_FLAG_DISABLE_WRITE_THROUGH      (0x00000008)
#define IRP_CONTEXT_DISABLE_LOCAL_BUFFERING			(0x00000010)
#define IRP_CONTEXT_DEFERRED_WRITE					(0x00000020)
#define IRP_CONTEXT_FLAG_ALLOC_CONTEXT				(0x00000040)
#define IRP_CONTEXT_FLAG_ALLOC_SECURITY				(0x00000080)
#define IRP_CONTEXT_NETWORK_FILE					(0x00000100)


#define IRP_CONTEXT_MFT_RECORD_RESERVED     (0x00000200)
#define IRP_CONTEXT_FLAG_IN_FSP             (0x00000400)
#define IRP_CONTEXT_FLAG_RAISED_STATUS      (0x00000800)
#define IRP_CONTEXT_FLAG_IN_TEARDOWN        (0x00001000)
#define IRP_CONTEXT_FLAG_ACQUIRE_VCB_EX     (0x00002000)
#define IRP_CONTEXT_FLAG_CALL_SELF          (0x00004000)
#define IRP_CONTEXT_FLAG_DONT_DELETE        (0x00008000)
#define IRP_CONTEXT_FLAG_HOTFIX_UNDERWAY    (0x00010000)
#define IRP_CONTEXT_FLAG_FORCE_POST         (0X00020000)
#define IRP_CONTEXT_FLAG_WRITE_SEEN         (0X00040000)
#define IRP_CONTEXT_FLAG_MODIFIED_BITMAP    (0x00080000)
#define IRP_CONTEXT_FLAG_DASD_OPEN          (0x00100000)
#define IRP_CONTEXT_FLAG_QUOTA_DISABLE      (0x00200000)
#define IRP_CONTEXT_FLAG_CHECKPOINT_ACTIVE  (0x01000000)

#define IRP_CONTEXT_STACK_IO_CONTEXT		(0x02000000)

#define IRP_CONTEXT_FLAG_PARENT_BY_CHILD    (0x80000000)

//ccb的标志
#define CCB_FLAG_NETWORK_FILE               (0x00000001)
#define CCB_FLAG_FILE_CHANGED               (0x00000002)
#define CCB_FLAG_WILDCARD_IN_EXPRESSION     (0x00000004)
#define CCB_FLAG_OPEN_BY_FILE_ID            (0x00000008)
#define CCB_FLAG_USER_SET_LAST_MOD_TIME     (0x00000010)
#define CCB_FLAG_USER_SET_LAST_CHANGE_TIME  (0x00000020)
#define CCB_FLAG_USER_SET_LAST_ACCESS_TIME  (0x00000040)
#define CCB_FLAG_TRAVERSE_CHECK             (0x00000080)

#define CCB_FLAG_RETURN_DOT                 (0x00000100)
#define CCB_FLAG_RETURN_DOTDOT              (0x00000200)
#define CCB_FLAG_DOT_RETURNED               (0x00000400)
#define CCB_FLAG_DOTDOT_RETURNED            (0x00000800)

#define CCB_FLAG_DELETE_FILE                (0x00001000)
#define CCB_FLAG_DENY_DELETE                (0x00002000)

#define CCB_FLAG_ALLOCATED_FILE_NAME        (0x00004000)
#define CCB_FLAG_CLEANUP                    (0x00008000)
#define CCB_FLAG_SYSTEM_HIVE                (0x00010000)

#define CCB_FLAG_PARENT_HAS_DOS_COMPONENT   (0x00020000)
#define CCB_FLAG_DELETE_ON_CLOSE            (0x00040000)
#define CCB_FLAG_CLOSE                      (0x00080000)

#define CCB_FLAG_UPDATE_LAST_MODIFY         (0x00100000)
#define CCB_FLAG_UPDATE_LAST_CHANGE         (0x00200000)
#define CCB_FLAG_SET_ARCHIVE                (0x00400000)

#define CCB_FLAG_DIR_NOTIFY                 (0x00800000)
#define CCB_FLAG_ALLOW_XTENDED_DASD_IO      (0x01000000)

//fcb状态
#define SCB_STATE_DISABLE_LOCAL_BUFFERING   (0x00000001)
#define SCB_STATE_DELETE_ON_CLOSE           (0x00000002)
#define SCB_STATE_FILEHEADER_WRITED	        (0x00000004)
#define SCB_STATE_FILE_CHANGED              (0x00000008)
#define SCB_STATE_DISCRYPTED_TYPE           (0x00000010)
#define SCB_STATE_HEADER_INITIALIZED        (0x00000020)
#define SCB_STATE_SHADOW_CLOSE              (0x00000040)
#define SCB_STATE_USA_PRESENT               (0x00000080)
#define SCB_STATE_ATTRIBUTE_DELETED         (0x00000100)
#define SCB_STATE_FILE_SIZE_LOADED          (0x00000200)
#define SCB_STATE_MODIFIED_NO_WRITE         (0x00000400)
#define SCB_STATE_QUOTA_ENLARGED            (0x00000800)
#define SCB_STATE_SUBJECT_TO_QUOTA          (0x00001000)
#define SCB_STATE_UNINITIALIZE_ON_RESTORE   (0x00002000)
#define SCB_STATE_CHANGE_BACKING	        (0x00004000)
#define SCB_STATE_NOTIFY_ADD_STREAM         (0x00008000)
#define SCB_STATE_NOTIFY_REMOVE_STREAM      (0x00010000)
#define SCB_STATE_NOTIFY_RESIZE_STREAM      (0x00020000)
#define SCB_STATE_NOTIFY_MODIFY_STREAM      (0x00040000)
#define SCB_STATE_TEMPORARY                 (0x00080000)
#define SCB_STATE_COMPRESSED                (0x00100000)
#define SCB_STATE_REALLOCATE_ON_WRITE       (0x00200000)
#define SCB_STATE_DELAY_CLOSE               (0x00400000)
#define SCB_STATE_WRITE_ACCESS_SEEN         (0x00800000)
#define SCB_STATE_CONVERT_UNDERWAY          (0x01000000)
#define SCB_STATE_VIEW_INDEX                (0x02000000)
#define SCB_STATE_DELETE_COLLATION_DATA     (0x04000000)
#define SCB_STATE_VOLUME_DISMOUNTED         (0x08000000)
		

typedef struct _TOP_LEVEL_CONTEXT {

	BOOLEAN TopLevelRequest;
	BOOLEAN ValidSavedTopLevel;
	BOOLEAN OverflowReadThread;

	UCHAR	X70Fsd;

	PIRP    SavedTopLevelIrp;

	struct _IRP_CONTEXT * TopLevelIrpContext;

} TOP_LEVEL_CONTEXT, *PTOP_LEVEL_CONTEXT;



#define READ_AHEAD_GRANULARITY           (0x10000)


#endif