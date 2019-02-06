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
	/*
		Ключ обработчика необходимый для подписи
	*/
	NCRYPT_KEY_HANDLE       NcryptKeyHandle = 0;
	/*
		Ключ обработчика необходимый для подтверждения подписи
	*/
	BCRYPT_KEY_HANDLE       BcryptKeyHandle = NULL;
public:
	/*
		Выводит сообщение об ошибке на экран
	*/
	void ReportError(_In_    DWORD       dwErrCode);

	/*
		Подсчет хэша сообщения
	*/
	NTSTATUS ComputeHash(
		_In_reads_bytes_(DataLength)
		PBYTE           Data,
		_In_        DWORD           DataLength,
		_Outptr_result_bytebuffer_maybenull_(*DataDigestLengthPointer)
		PBYTE           *DataDigestPointer,
		_Out_       DWORD           *DataDigestLengthPointer);
	/*
		Создание и запись ключей в буфер памяти
	*/
	bool CreateKeys(std::string key);
	/*
		Подпись сообщения
	*/
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
	/*
		Проверка подписи сообщения
	*/
	SECURITY_STATUS VerifySignature(
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

