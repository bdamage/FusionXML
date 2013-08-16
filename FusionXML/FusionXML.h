// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the FUSIONXML_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// FUSIONXML_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.


#define _FUSION_XML_VERSION TEXT("2.0 beta")
#define logfilename "xmlprofile.htm"
#define logfilenameW _T("xmlprofile.htm")


#define SUCCESSFULL				0
#define ERR_ADDING_PROFILE		2
#define ERR_LOADING_FILE		5
#define ERR_TAG_FUSIONCONFIG	10
#define ERR_TAG_PROFILE			11
#define ERR_TAG_UNKNOWN			12
#define ERR_PARSING_CMD_ERROR	13


#ifdef FUSIONXML_EXPORTS
#define FUSIONXML_API __declspec(dllexport)
#else
#define FUSIONXML_API __declspec(dllimport)
#endif


typedef void (SENDDEBUGMESSAGE)( const TCHAR* );

FUSIONXML_API int loadXMLFile(char *szFilename);
FUSIONXML_API int loadXMLString(char *szXMLString);

FUSIONXML_API void DeinitializeFusion();
FUSIONXML_API int InitializeFusion();
FUSIONXML_API int GetMAC( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize );
FUSIONXML_API DWORD EnemurateAndDeleteProfiles();
FUSIONXML_API DWORD DeleteFusionProfile(TCHAR *pszGUID);
FUSIONXML_API DWORD CommandFusionAPI (DWORD dwAPIIdentifier, PVOID pInputBuff,	DWORD dwInputBuffLen,PVOID pOutputBuff,DWORD dwOutputBuffLen);
FUSIONXML_API BOOL ConnectToProfile(TCHAR *pszProfileID);
FUSIONXML_API void ClearLog();
FUSIONXML_API BOOL GetFusionVersion();
FUSIONXML_API int AddProfileW(TCHAR *cmd);
FUSIONXML_API void ExportAllProfilesW();
FUSIONXML_API int ExportProfile( TCHAR *szGUID );

extern "C"
{
FUSIONXML_API int PowerStatus( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize );
}