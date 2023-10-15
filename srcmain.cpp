#include "StdAfx.h"

/*#define _DEBUG*/
#define ENCRYPT_BLOCK_SIZE 8 //每次加密数据块的最小单位长度
#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4 
#define TEST_AES256_ALG  CALG_AES_256
#define DATAMAXLEN 500


/////////////////////////////////////////////////////////////////////
////////////////////////////To Define Function///////////////////////
/////////////////////////////////////////////////////////////////////
DWORD ShowMenue();
void Enum(BYTE pbData[1000]);
void MyDecrypt(BYTE *pbKeyBlob,DWORD dwBlobLen,BYTE *pOut);
void MyVerify();
void MyConnect();
DWORD AESencrypt(BYTE *AESkeyBlob,DWORD AESKeyBloblen,BYTE *pOut);



int main(){
	//////////////////////////////////////////////////////
	///////////////////ShowMenu///////////////////////////
	//////////////////////////////////////////////////////
	
	printf("Welcome!\n");
	while(1){
	if(ShowMenue()==2)
	{
		break;
	}
	else
		continue;
	}
}



DWORD ShowMenue(){
	int ichoice;
	printf("***************************************************\n");
	printf("/////////////////////Menu//////////////////////////\n");
	printf("1:EnumProvider\n");
	printf("2:GenKey&SignTheInfo\n");
	printf("3:VerifyInfo\n");
	printf("4:ConnectServer\n");
	printf("5:ReciveTheRequest\n");
	printf("0:Exit\n");
	printf("//////////////////////////////////////////////////\n");
	printf("**************************************************\n");
	printf("Please Enter An No. To Use the System:");
	scanf("%d",&ichoice);
	printf("\n");
	switch (ichoice)
	{
	case 1:
		printf("Your Choice: Enum \n");
		//Enum();
		break;
	case 2:
		printf("Your Choice: GenKey \n");
		//MyTest();
		break;
	case 3:
		printf("Your Choice: Verify \n");
		MyVerify();
		break;
	case 4:
		printf("Your Choice: Connect\n");
		MyConnect();
		break;


	case 0:
		printf("Exit The System \n");
		return 2;
	default:
		printf("Please Enter An Legal No. \n");
		return 1;
	}
	return 0;
}

void Enum(BYTE *pbData){
	DWORD	cbName;
	DWORD	dwType;
	DWORD	dwIndex=0;
	char	*pszName;
	HCRYPTPROV	hCryptProv;
	//BYTE		pbData[1000];

	DWORD		cbData;

	dwIndex =0;
	BeginAction("CryptEnumProviders()");
	while(CryptEnumProviders(
		dwIndex,
		NULL,
		0,
		&dwType,
		NULL,
		&cbName
		))
	{
		if(!(pszName=(LPTSTR)LocalAlloc(LMEM_ZEROINIT,cbName)))
		{
			ActionFailed(GetLastError(),__LINE__);
			return;
		}


		if(CryptEnumProviders(
			dwIndex++,
			NULL,
			0,
			&dwType,
			pszName,
			&cbName
			))
		{
			ActionSuccess();
			printf("%4.0d %s\n",dwType,pszName);
		}
		else
		{
			ActionFailed(GetLastError(),__LINE__);
			return;
		}
		LocalFree(pszName);
		
	}
	hCryptProv=NULL;
	cbData=1000;
	printf("------------------------------------\n");


	if (CryptAcquireContext(
		&hCryptProv, 
		NULL,
		TEST_CSP_NAME,
		PROV_RSA_FULL, 
		0)) 
	{
		printf("CSP context acquired.\n");
	}
	else
	{
		ActionFailed(GetLastError(),__LINE__);
		return;
	}

	BeginAction("CryptGetProvParam()");
	if(CryptGetProvParam(
		hCryptProv,
		PP_NAME,
		pbData,
		&cbData,
		0))
	{
		
		printf("Provider name:%s\n",pbData);
	}
	else
	{
		ActionFailed(GetLastError(),__LINE__);
		return;
	}

	cbData=1000;

	if (CryptGetProvParam(
		hCryptProv,
		PP_CONTAINER,
		pbData,
		&cbData,
		0))
	{
		printf("Key Container name:%s\n",pbData);
	}
	else
	{
		ActionFailed(GetLastError(),__LINE__);
		return;
	}

}

void MyDecrypt(BYTE *byEncryptFile,DWORD EncryptFileLen,BYTE *pOut){
	//-------------------------------------------------------------
	// Declare and initialize variables.

	HCRYPTPROV		hProv;
	HCRYPTHASH		hHash;
	HCRYPTKEY		hKey;

	BYTE			*pbKeyBlob;			
	BYTE			*pbSignature;		
	/*BYTE			*byEncryptFile;*/

	DWORD			dwSigLen;
	DWORD			dwBlobLen;
	DWORD			dwCount;
	/*DWORD			EncryptFileLen;*/
	time_t myt_Dec_2=time(NULL);


	//--------------------------------------------------------------------
	// get the CSP handle
	printf("The following phase of this program is Decrypt.\n\n");
	BeginAction("CryptAcquireContext()");
	if (CryptAcquireContext(
		&hProv, 
		"A60D9314-553C-4C4D-9D4B-380B7E49E29E",
		TEST_CSP_NAME,
		PROV_RSA_FULL, 
		0)) 
	{
		printf("CSP context acquired.\n");
	}
	else	
	{
		ActionFailed(GetLastError(),__LINE__);
		printf("An Error has been occurred\n");
		goto exit0;
	}
	ActionSuccess();

	//--------------------------------------------------------------------
	// get the sigkey from the container
	BeginAction("CryptGetUserKey()");

	if(!CryptGetUserKey(
		hProv,
		AT_KEYEXCHANGE,
		&hKey))
	{
		ActionFailed(GetLastError(),__LINE__);
		goto exit0;
	}
	else
	{
		ActionSuccess();
	}

	//--------------------------------------------------------------------
	// Read File
// 	HANDLE hex_Decrypt_file =  INVALID_HANDLE_VALUE;
// 	LPTSTR Decrypt_File="D:\\testSecurity\\testencrypt.txt";
// 	BeginAction("CreateFile(Decrypt_File):");
// 	hex_Decrypt_file=CreateFile(
// 		Decrypt_File,
// 		FILE_READ_DATA,
// 		FILE_SHARE_READ,
// 		NULL,
// 		OPEN_EXISTING,
// 		FILE_ATTRIBUTE_NORMAL,
// 		NULL);
// 	if(hex_Decrypt_file != INVALID_HANDLE_VALUE){
// 		ActionSuccess();
// 		printf("The decrypt file, %s, is open. \n",Decrypt_File);
// 	}
// 	else{
// 		ActionFailed(GetLastError(),__LINE__);
// 		goto exit0;
// 	}
// 	
// 
// 
// 	//---------------------------------------
// 	//Read The EncryptFileLen------------------------
// 	BeginAction("ReadFile()");
// 	if (!ReadFile(
// 		hex_Decrypt_file,
// 		&EncryptFileLen,
// 		sizeof(DWORD),
// 		&dwCount,
// 		NULL))
// 	{
// 		ActionFailed(GetLastError(),__LINE__);
// 		goto exit0;
// 	}
// 	ActionSuccess();
// 
// 	dwBlobLen = dwBlobLen & 0x000000FF;
// 	if (!(byEncryptFile = (PBYTE)malloc(EncryptFileLen)))
// 	{
// 		ActionFailed(GetLastError(),__LINE__);
// 	}
// 
// 	//------------------------------------
// 	//Read The EncryptFile------------------------
// 
// 	BeginAction("ReadFile()");
// 	if (!ReadFile(
// 		hex_Decrypt_file,
// 		byEncryptFile,
// 		EncryptFileLen,
// 		&dwCount,
// 		NULL))
// 	{
// 		ActionFailed(GetLastError(),__LINE__);
// 		goto exit0;
// 	}
// 	ActionSuccess();

#ifdef _DEBUG
	ShowData(byEncryptFile,EncryptFileLen);
#endif // _DEBUG


// #ifdef _DEBUG
// 
// 	//----------------------------------------------
// 	//-------------Show PublicKey-------------------
// 	//----------------------------------------------
// 	// Export pubkey since the reciever need it to verify the signature
// 	BeginAction("CryptExportKey()");
// 	if (CryptExportKey(   
// 		hKey,    
// 		NULL,    
// 		PUBLICKEYBLOB,
// 		0,    
// 		NULL, 
// 		&dwBlobLen))  //size
// 	{
// 		ActionSuccess();
// 		printf("Size of the BLOB for the public key determined. \n");
// 	}
// 	else
// 
// 	{
// 		ActionFailed(GetLastError(),__LINE__);
// 		goto exit0;
// 	}
// 
// 
// 	//--------------------------------------------------------------------
// 	// buffer for pubkey
// 	if (pbKeyBlob = (BYTE*)malloc(dwBlobLen)) 
// 	{
// 		printf("Memory has been allocated for the BLOB. \n");
// 	}
// 	else
// 	{
// 		ActionFailed(GetLastError(),__LINE__);
// 		goto exit0;
// 	}
// 
// 	//--------------------------------------------------------------------
// 	// export it
// 	BeginAction("CryptExportKey()");
// 	if (CryptExportKey(   
// 		hKey, 
// 		NULL,    
// 		PUBLICKEYBLOB,    
// 		0,    
// 		pbKeyBlob,    
// 		&dwBlobLen))
// 	{
// 		ActionSuccess();
// 		printf("Contents have been written to the BLOB. \n");
// 	}
// 	else
// 	{
// 		ActionFailed(GetLastError(),__LINE__);
// 		goto exit0;
// 	}
// #ifdef _DEBUG
// 	printf("The Public Key is:\n");
// 	ShowData(pbKeyBlob,dwBlobLen);
// #endif // _DEBUG
// #endif

BOOL FLAG;
	//--------------------------------------
	//DecryptFile
	BeginAction("CryptDecrypt()");
	if(!CryptDecrypt(
		hKey,
		0,
		TRUE,

		0,
		byEncryptFile,
		&EncryptFileLen))
	{
		ActionFailed(GetLastError(),__LINE__);
		goto exit0;  
	}
	else
	{
		ActionSuccess();
		printf("Decrypt Done.");
		FLAG = TRUE;
	}


#ifdef _DEBUG
	ShowData(byEncryptFile,EncryptFileLen);
#endif
	
	BYTE AES_KEY[128]={'\0'};
	memcpy(AES_KEY,byEncryptFile,EncryptFileLen);
	for(int i=0;AES_KEY[i]!='\0';i++)
	{
		printf("%c",AES_KEY[i]);
	}
	printf("\n\n");
	
	
exit0:
// 	if(hex_Decrypt_file){
// 		if(CloseHandle(hex_Decrypt_file))
// 			printf("TThe File Handle has been released.\n");
// 		else
// 			ActionFailed(GetLastError(),__LINE__);
// 	}
	if(hKey){
		if(CryptDestroyKey(hKey))
			printf("The Key Handle has been released.\n");
		else
			ActionFailed(GetLastError(),__LINE__);
	}
	if(hProv){
		if(CryptReleaseContext(hProv,0))
			printf("The Context Handle has been released.\n");
		else
			ActionFailed(GetLastError(),__LINE__);

	}
	if (FLAG)
	{
		printf("---------------------------\n");
		printf("Start AES Encrypt Function.\n");
		
		AESencrypt(AES_KEY,EncryptFileLen,pOut);
		printf("****************************\n");
		ShowData(pOut,112);
		return;
	}
	else
		return;
}

DWORD AESencrypt(BYTE *AESkeyBlob,DWORD AESKeyBloblen,BYTE *pOut){
#ifdef _DEBUG
	printf("The key Receive is:\n");
	ShowData(AESkeyBlob,AESKeyBloblen);
#endif
	
	HCRYPTPROV		hProv;
	HCRYPTKEY		ImpKey=0;
	BOOL			FLAG=FALSE;
	BeginAction("CryptAcquireContext()");
	if (CryptAcquireContext(
		&hProv, 
		NULL, 
		NULL,
		PROV_RSA_AES, 
		0)) 
	{
		ActionSuccess();
		printf("CSP context acquired.\n");
	}
	else
	{
		ActionFailed(GetLastError(),__LINE__);
		goto exit0;
	}
	BeginAction("CryptImportKey()");
	if(CryptImportKey(
		hProv,
		AESkeyBlob,
		AESKeyBloblen,
		0,
		0,
		&ImpKey))
	{
		ActionSuccess();
		printf("The AES Key has been Imported.\n");
	}
	else
	{
		ActionFailed(GetLastError(),__LINE__);
		goto exit0;
	}

	char text_test[100]={"DDDDDDDDDDDDDDDDLogin With Admin."};
	DWORD text_len = strlen(text_test);
	DWORD ulDataLen = 100;
	DWORD ulEncryptedLen=ulDataLen;


#ifdef _DEBUG
	printf("Text to be encrypt is: %s\n",text_test);
	printf("Text len is :%d\n",text_len);
#endif
	BeginAction("CryptEncrypt()");
	if(!CryptEncrypt(
		ImpKey, 
		0, 
		TRUE, 
		0, 
		NULL, 
		&ulEncryptedLen, 
		ulDataLen))
	{
		ActionFailed(GetLastError(),__LINE__);
		goto exit0;
	}
	else
	{
		ActionSuccess();
	}
 	/*pOut = new BYTE[ulEncryptedLen];*/

 	memset(pOut, 0, ulEncryptedLen);
	memcpy(pOut, text_test, ulDataLen);
	DWORD ulTemp = ulDataLen;
	ulDataLen = ulEncryptedLen;
	ulEncryptedLen = ulTemp;
	BeginAction("CryptEncrypt()");
	if(!CryptEncrypt(
		ImpKey, 
		0, 
		TRUE, 
		0, 
		pOut, 
		&ulEncryptedLen, 
		ulDataLen))
	{
		delete[] pOut;
		pOut = NULL;
		ActionFailed(GetLastError(),__LINE__);
		goto exit0;
	}
	else
	{
		ActionSuccess();
		printf( "Data encrypted:\n");
	}

#ifdef _DEBUG
	ShowData(pOut, ulEncryptedLen);
#endif // _DEBUG

	printf("%s\n",pOut);

	printf("pOut dizhi:%x\n",&pOut);

// 	HANDLE handle_AESEN_file=INVALID_HANDLE_VALUE;
// 	LPTSTR AESEN_path=(LPSTR)"D:\\testSecurity\\AESen.txt";
// 	DWORD dwCount;
// 	handle_AESEN_file=CreateFile(
// 		AESEN_path,
// 		FILE_WRITE_DATA,
// 		FILE_SHARE_READ,
// 		NULL,
// 		OPEN_ALWAYS,
// 		FILE_ATTRIBUTE_NORMAL,
// 		NULL);
// 	if(handle_AESEN_file!=INVALID_HANDLE_VALUE){
// 		ActionSuccess();
// 		printf("TheThe destination file, %s, is open. \n",AESEN_path);
// 	}
// 	else
// 	{
// 		ActionFailed(GetLastError(),__LINE__);
// 		goto exit0;
// 	}
// 
// 	if(!WriteFile(
// 		handle_AESEN_file,
// 		&ulEncryptedLen,
// 		sizeof(DWORD),
// 		&dwCount,
// 		NULL
// 		))
// 	{
// 		ActionFailed(GetLastError(),__LINE__);
// 		goto exit0;
// 	}
// 	else
// 	{
// 		ActionSuccess();
// 		printf("A file header has been written. \n.");
// 	}
// 
// 	if(!WriteFile(
// 		handle_AESEN_file,
// 		pOut,
// 		ulEncryptedLen,
// 		&dwCount,
// 		NULL))
// 	{
// 		ActionFailed(GetLastError(),__LINE__);
// 		goto exit0;
// 	}
// 	else
// 	{
// 		ActionSuccess();
// 		printf("The AES Encrypt file has been written to the %s.\n",AESEN_path);
// 		FLAG=TRUE;
// 	}
// 	free (pOut);


exit0:
// 	if(handle_AESEN_file){
// 		if(CloseHandle(handle_AESEN_file))
// 			printf("The File Handle has been released.\n");
// 		else
// 			ActionFailed(GetLastError(),__LINE__);
// 	}
	if(ImpKey){
		if(CryptDestroyKey(ImpKey))
			printf("The Key Handle has been released.\n");
		else
			ActionFailed(GetLastError(),__LINE__);
	}
	if(hProv){
		if(CryptReleaseContext(hProv,0))
			printf("The Context Handle has been released.\n");
		else
			ActionFailed(GetLastError(),__LINE__);
	}

	ShowData(pOut, ulEncryptedLen);
	printf("dizhi:%x",&pOut);
	if(FLAG !=TRUE)
	{
		return 0;	
	}
	 
}




void MyVerify(){
	HCRYPTPROV		hProv;
	HCRYPTHASH		hHash;
	HCRYPTKEY		hKey;
	HCRYPTKEY		hPubKey;
	LPTSTR			szDescription = "Test Data Description";
	BYTE			*pbKeyBlob;			//pubkey of signer
	BYTE			*pbSignature;
	BYTE			*pbBuffer= (BYTE *)"The data that is to be hashed and signed.";//data to be signed

	
	DWORD			dwBufferLen = strlen((char *)pbBuffer);
	DWORD			dwSigLen=0x00;
	DWORD			dwBlobLen=0x00;
	DWORD			dwCount;
	HANDLE			PublicKeyFile=INVALID_HANDLE_VALUE;
	HANDLE			SignatureFile=INVALID_HANDLE_VALUE;

	LPTSTR publickeyfile = (LPTSTR)"D:\\testSecurity\\publickey.txt";
	LPTSTR signaturefile = (LPTSTR)"D:\\testSecurity\\sginature.txt";


	BeginAction("CryptAcquireContext()");
	if (CryptAcquireContext(
		&hProv, 
		NULL, 
		NULL,
		PROV_RSA_FULL, 
		0)) 
	{
		ActionSuccess();
		printf("CSP context acquired.\n");
	}
	else	//create if not exist
	{
		if (CryptAcquireContext(
			&hProv, 
			NULL, 
			TEST_CSP_NAME, 
			PROV_RSA_FULL, 
			CRYPT_NEWKEYSET)) 
		{
			ActionSuccess();
			printf("A new key container has been created.\n");
		}
		else
		{
			ActionFailed(GetLastError(),__LINE__);
			printf("Error during CryptAcquireContext.\n");
			printf("ErroNo is:%d\n",GetLastError());
			return;
		}
	}
	
	//-----------------------------------
	//Read PublicKey
	BeginAction("CreateFile()");
	PublicKeyFile = CreateFile(
		publickeyfile,
		FILE_READ_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE != PublicKeyFile)
	{
		ActionSuccess();
		printf("The source encrypted file, %s, is open. \n", publickeyfile);
	}
	else
	{
		ActionFailed(GetLastError(),__LINE__);
		return;
	}
	
	//------------------------------------
	//Read The KeyLen------------------------
	BeginAction("ReadFile()");
	if (!ReadFile(
		PublicKeyFile,
		&dwBlobLen,
		sizeof(DWORD),
		&dwCount,
		NULL))
	{
		ActionFailed(GetLastError(),__LINE__);
		return;
	}
	ActionSuccess();
	
	dwBlobLen = dwBlobLen & 0x000000FF;
	if (!(pbKeyBlob = (PBYTE)malloc(dwBlobLen)))
	{
		ActionFailed(GetLastError(),__LINE__);
	}
	
	//------------------------------------
	//Read The Key------------------------
	BeginAction("ReadFile()");
	if (!ReadFile(
		PublicKeyFile,
		pbKeyBlob,
		dwBlobLen,
		&dwCount,
		NULL))
	{
		ActionFailed(GetLastError(),__LINE__);
		return;
	}
	ActionSuccess();

#ifdef _DEBUG
	ShowData(pbKeyBlob,dwBlobLen);
#endif

	//--------------------------------------
	//ImportPublicKey-----------------------
	BeginAction("CryptImportKey()");
	if(CryptImportKey(
		hProv,
		pbKeyBlob,
		dwBlobLen,
		0,
		0,
		&hPubKey))
	{
		ActionSuccess();
		printf("The key has been imported.\n");
	}
	else
	{
		ActionFailed(GetLastError(),__LINE__);
	}

	if(PublicKeyFile)
		CloseHandle(PublicKeyFile);

//*********************************************************

	//-----------------------------------
	//Read Signature---------------------
	BeginAction("CreateFile");
	SignatureFile = CreateFile(
		signaturefile,
		FILE_READ_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE != SignatureFile)
	{
		ActionSuccess();
		printf("The source encrypted file, %s, is open. \n", signaturefile);
	}
	else
	{
		ActionFailed(GetLastError(),__LINE__);
		return;
	}

	//------------------------------------
	//Read The SignLen--------------------
	BeginAction("ReadFile()");
	if (!ReadFile(
		SignatureFile,
		&dwSigLen,
		sizeof(DWORD),
		&dwCount,
		NULL))
	{
		ActionFailed(GetLastError(),__LINE__);
		return;
	}
	ActionSuccess();

	dwSigLen = dwSigLen & 0x000000FF;
	if (!(pbSignature = (PBYTE)malloc(dwSigLen)))
	{
		ActionFailed(GetLastError(),__LINE__);
	}

	//------------------------------------
	//Read The Sign-----------------------
	BeginAction("ReadFile()");
	if (!ReadFile(
		SignatureFile,
		pbSignature,
		dwSigLen,
		&dwCount,
		NULL))
	{
		ActionFailed(GetLastError(),__LINE__);
		return;
	}
	ActionSuccess();

#ifdef _DEBUG
	ShowData(pbSignature,dwSigLen);
#endif


	//--------------------------------------------------------------------
	// create hash object
	BeginAction("CryptCreateHash()");
	if(CryptCreateHash(
		hProv,
		CALG_MD5,
		0, 
		0, 
		&hHash)) 
	{
		ActionSuccess();
		printf("The hash object has been recreated. \n");
	}
	else
	{
		ActionFailed(GetLastError(),__LINE__);
		return;
	}

	//--------------------------------------------------------------------
	// hash the data
	BeginAction("CryptHashData()");
	if(CryptHashData(
		hHash,
		pbBuffer,
		dwBufferLen,
		0)) 
	{
		ActionSuccess();
		printf("The new hash has been created.\n");

	}
	else
	{
		ActionFailed(GetLastError(),__LINE__);
	}

	DWORD hhsize;
	DWORD hhlen=sizeof(hhsize);
	BeginAction("CryptGetHashParam()");
	if (!CryptGetHashParam(
		hHash,
		HP_HASHSIZE,
		(BYTE*)(&hhsize),
		&hhlen,
		0))
	{
		ActionFailed(GetLastError(),__LINE__);
	}
	else
	{
		ActionSuccess();
	}
	
	BYTE* phash=new BYTE[hhsize];
	hhlen=hhsize;

	if(!CryptGetHashParam(
		hHash,
		HP_HASHVAL,
		phash,
		&hhlen,
		0
		))
	{
		ActionFailed(GetLastError(),__LINE__);
	}
	else
	{
		ActionSuccess();
	}
#ifdef _DEBUG
	
	printf("**************Test****************\n");
// 	for(int i=0;phash[i]!=NULL;i++)
// 		printf("The Hans Data is:%x\n",phash[i]);
	ShowData((unsigned char *)phash,hhlen);
#endif



	BeginAction("CryptVerifySignature()");
	if(CryptVerifySignature(
		hHash, 
		pbSignature,
		dwSigLen, 
		hPubKey,
		NULL, 
		0)) 
	{
		ActionSuccess();
		printf("The signature has been verified.\n");
	}
	else
	{
		ActionFailed(GetLastError(),__LINE__);
	}

}
 

void initializeSocket(WSADATA& wsaData) {
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		int error_code = WSAGetLastError();
		fprintf(stderr, "Winsock initial failed, erro code: %d\n", error_code);
		exit(1);  
	}
}

SOCKET createSocket() {
	return socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
}

void setupSocketAddress(sockaddr_in& sockAddr) {
	memset(&sockAddr, 0, sizeof(sockAddr));
	sockAddr.sin_family = PF_INET;
	sockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	sockAddr.sin_port = htons(17891);
}

bool connectToServer(SOCKET& sock, sockaddr_in& sockAddr) {
	while (true) {
		BeginAction("connect()"); 
		if (!connect(sock, (SOCKADDR*)&sockAddr, sizeof(SOCKADDR))) {
			ActionSuccess();
			printf("Has been connected to the Server.\n");
			return true;
		}
		else {
			ActionFailed(GetLastError(), __LINE__);
			system("pause");
		}
	}
	return false;  
}

void sendMessageToServer(SOCKET& sock, const char* message) {
	send(sock, message, strlen(message), 0);
}

char* receiveMessageFromServer(SOCKET& sock) {
	static BYTE bufRecv[DATAMAXLEN] = { 0 };
	while (true) {
		recv(sock, (char*)bufRecv, DATAMAXLEN, 0);
		if (*bufRecv != NULL) {
			break;
		}
	}
	return (char*)bufRecv;
}

void closeSocketAndCleanup(SOCKET& sock, WSADATA& wsaData) {
	closesocket(sock);
	WSACleanup();
}

int myconnect() {
	WSADATA wsaData;
	initializeSocket(wsaData);

	SOCKET sock = createSocket();

	sockaddr_in sockAddr;
	setupSocketAddress(sockAddr);

	if (!connectToServer(sock, sockAddr)) {
		int error_code = WSAGetLastError();
		fprintf(stderr, "Failed to connect to the server. Error code: %d\n", error_code);
		closesocket(sock);
		WSACleanup();  // 清理 Winsock句柄
		exit(1);  //错误退出
	}


	closeSocketAndCleanup(sock, wsaData);

	system("pause");
	return 0;
}