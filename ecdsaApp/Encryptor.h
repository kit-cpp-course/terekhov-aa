#pragma once

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <sal.h>
#include <string>

class Encryptor
{
protected: 
	NTSTATUS privateKey;
	NTSTATUS publicKey;
	SECURITY_STATUS         secStatus;

	DWORD                   KeyBlobLength = 0;
	DWORD                   SignatureBlobLength = 0;

	PBYTE                   KeyBlob = NULL;
	PBYTE                   SignatureBlob = NULL;

	NCRYPT_KEY_HANDLE       NcryptKeyHandle = 0;
	BCRYPT_KEY_HANDLE       BcryptKeyHandle = NULL;
public:
	Encryptor();
	~Encryptor();

	void ReportError(_In_    DWORD       dwErrCode);
	NTSTATUS ComputeHash(
		_In_reads_bytes_(DataLength)
		PBYTE           Data,
		_In_        DWORD           DataLength,
		_Outptr_result_bytebuffer_maybenull_(*DataDigestLengthPointer)
		PBYTE           *DataDigestPointer,
		_Out_       DWORD           *DataDigestLengthPointer);
	bool CreateKeys(std::string key);
	PBYTE SignHash(
		_In_reads_bytes_(MessageLength)
		PBYTE           MessageToSign,
		_In_        DWORD           MessageLength,
		_Outptr_result_bytebuffer_maybenull_(*SignatureBlobLengthPointer)
		PBYTE               *SignatureBlobPointer,
		_Out_       DWORD               *SignatureBlobLengthPointer,
		_Outptr_result_bytebuffer_maybenull_(*KeyBlobLengthPointer)
		PBYTE               *KeyBlobPointer,
		_Out_       DWORD               *KeyBlobLengthPointer
	);
	SECURITY_STATUS
		VerifySignature(
			_In_reads_bytes_(MessageLength)
			PBYTE           MessageToVerify,
			_In_       DWORD           MessageLength,
			_In_reads_bytes_(SignatureBlobLength)
			PBYTE           SignatureBlob,
			_In_       DWORD           SignatureBlobLength,
			_In_reads_bytes_(KeyBlobLength)
			PBYTE           KeyBlob,
			_In_       DWORD           KeyBlobLength
		);
};

