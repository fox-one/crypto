// SADK.h : Defines the exported functions for the DLL application.
//
#ifndef _SADK_H__
#define _SADK_H__

#ifdef _WIN32
#ifdef DLL_EXPORTS
#define DLL_API(T) __declspec(dllexport) T __cdecl
#else
#define DLL_API(T) __declspec(dllimport) T __cdecl
#endif
#else
#define DLL_API(T) __attribute__ ((visibility ("default"))) T
#endif

#ifdef __cplusplus
extern "C" {
#endif 

DLL_API(int) GenerateActivationRequset(const char* pszActivationFilePath);

DLL_API(int) ImportLicenseFile(const char* pszLicenseFilePath);

DLL_API(int) Initialize();

DLL_API(int) Uninitialize();

DLL_API(int) SM2SignData(unsigned char*  pbySourceData,
                         int             nSourceData,
                         unsigned char*  pbySM2PublicKey,
                         int             nSM2PublicKey,
                         unsigned char*  pbySM2PrivateKey,
                         int             nSM2PrivateKey,
                         unsigned char** ppbySignature,
                         int*            pnSignature);

DLL_API(int) SM2VerifySignature(unsigned char*  pbySignature,
                                int             nSignature,
                                unsigned char*  pbySourceData,
                                int             nSourceData,
                                unsigned char*  pbySM2PublicKey,
                                int             nSM2PublicKey);

DLL_API(int) SM2EncryptData(unsigned char*  pbyPlainData,
                            int             nPlainData,
                            unsigned char*  pbySM2PublicKey,
                            int             nSM2PublicKey,
                            unsigned char** ppbyEncryptedData,
                            int*            pnEncryptedData);

DLL_API(int) SM2DecryptData(unsigned char*  pbyEncryptedData,
                            int             nEncryptedData,
                            unsigned char*  pbySM2PrivateKey,
                            int             nSM2PrivateKey,
                            unsigned char** ppbyDecryptedData,
                            int*            pnDecryptedData);

DLL_API(int) SM3HashData(unsigned char*  pbySourceData,
                         int             nSourceData,
                         unsigned char** ppbySM3Hash,
                         int*            pnSM3Hash);

DLL_API(int) CreateSM4Key(unsigned char** ppbySymKey,
                          int*            pnSymKey);

DLL_API(int) SM4EncryptData(unsigned char*  pbyPlainData,
                            int             nPlainData,
                            unsigned char*  pbySymKey,
                            int             nSymKey,
                            unsigned char** ppbyEncryptedData,
                            int*            pnEncryptedData);

DLL_API(int) SM4DecryptData(unsigned char*  pbyEncryptedData,
                           int             nEncryptedData,
                           unsigned char*  pbySymKey,
                           int             nSymKey,
                           unsigned char** ppbyPlainData,
                           int*            pnPlainData);

DLL_API(int) SM4EncryptFile(const char*    szSourceFilePath,
                            unsigned char* pbySymKey, 
                            int            nSymKey,
                            const char*    szEncryptedFilePath);

DLL_API(int) SM4DecryptFile(const char*    szEncryptedFilePath,
                            unsigned char* pbySymKey, 
                            int            nSymKey,
                            const char*    szDecryptFilePath);

DLL_API(int) EncodeBase64Data(unsigned char* pbySourceData,
                              int            nSourceData,
                              char**         ppszBase64EncodedData,
                              int*           pnBase64EncodedData);

DLL_API(int) DecodeBase64Data(char*           pszBase64EncodedData,
                              int             nBase64EncodedData,
                              unsigned char** ppbySourceData,
                              int*            pnSourceData);

DLL_API(void) FreeMemory( void* pBuf );

#ifdef __cplusplus
}
#endif


#endif // _SADK_H__
