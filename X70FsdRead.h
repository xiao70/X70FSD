#ifndef __X70FSDREAD_H__
#define __X70FSDREAD_H__

#include "X70FsdStruct.h"

FLT_PREOP_CALLBACK_STATUS
X70FsdCommonRead(
					 __inout PFLT_CALLBACK_DATA Data,
					 __in PCFLT_RELATED_OBJECTS FltObjects,
					 __in PIRP_CONTEXT IrpContext);

FLT_PREOP_CALLBACK_STATUS
PtPreOperationRead (
					  __inout PFLT_CALLBACK_DATA Data,
					  __in PCFLT_RELATED_OBJECTS FltObjects,
					  __deref_out_opt PVOID *CompletionContext
					  );

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationRead  (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );


FLT_PREOP_CALLBACK_STATUS
X70FsdFastIoRead(__inout PFLT_CALLBACK_DATA Data,
				   __in PCFLT_RELATED_OBJECTS FltObjects);

NTSTATUS RealReadFile(
				  IN PCFLT_RELATED_OBJECTS FltObjects,
				  IN PIRP_CONTEXT IrpContext,
				  IN PVOID SystemBuffer,
				  IN LARGE_INTEGER ByteOffset,
				  IN ULONG ByteCount,
				  OUT PULONG_PTR RetBytes
				  );



#endif