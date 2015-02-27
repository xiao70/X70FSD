#ifndef __X70FSDCREATE_H__
#define __X70FSDCREATE_H__

#include "X70FsdStruct.h"

BOOLEAN IsConcernedProcess( PCFLT_RELATED_OBJECTS FltObjects,PNTSTATUS pStatus,PULONG ProcType);

FLT_PREOP_CALLBACK_STATUS
PtPreOperationCreate (
					  __inout PFLT_CALLBACK_DATA Data,
					  __in PCFLT_RELATED_OBJECTS FltObjects,
					  __deref_out_opt PVOID *CompletionContext
					  );

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationCreate (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

NTSTATUS CreateFileImitation(__inout PFLT_CALLBACK_DATA Data,
							 __in PCFLT_RELATED_OBJECTS FltObjects,
							 __in PUNICODE_STRING FileName,
							 __out PHANDLE phFile,
							 __out PFILE_OBJECT *pFileObject,
							 __out PIO_STATUS_BLOCK  IoStatus,
							 __in  BOOLEAN Network);

NTSTATUS CreateFileByExistFcb(__inout PFLT_CALLBACK_DATA Data,
							  __in PCFLT_RELATED_OBJECTS FltObjects,
							  __in PFCB Fcb,
							  __in PIRP_CONTEXT IrpContext);

FLT_PREOP_CALLBACK_STATUS
X70FsdCommonCreate(
					__inout PFLT_CALLBACK_DATA Data,
					__in PCFLT_RELATED_OBJECTS FltObjects,
					__in PIRP_CONTEXT IrpContext);


NTSTATUS 
CreateFileByNonExistFcb(__inout PFLT_CALLBACK_DATA Data,
								 __in PCFLT_RELATED_OBJECTS FltObjects,
								 __in PFCB Fcb,
								 __in PIRP_CONTEXT IrpContext,
								 __in PUCHAR	HashValue
								 );


FLT_PREOP_CALLBACK_STATUS
PtPreOperationNetworkQueryOpen(
								 __inout PFLT_CALLBACK_DATA Data,
								 __in PCFLT_RELATED_OBJECTS FltObjects,
								 __deref_out_opt PVOID *CompletionContext
								 );

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationNetworkQueryOpen(
								  __inout PFLT_CALLBACK_DATA Data,
								  __in PCFLT_RELATED_OBJECTS FltObjects,
								  __in_opt PVOID CompletionContext,
								  __in FLT_POST_OPERATION_FLAGS Flags
								  );
#endif