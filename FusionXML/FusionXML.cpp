// FusionXML.cpp : Defines the entry point for the DLL application.
// Initial code Kjell Lloyd 2008

#include "stdafx.h"
//#include "FusionPublicAPI.h"
#include "FusionXML.h"
#include "..\tinyxml\tinyxml.h"
#include "FusionXMLProfile.h"
#include "FusionMgr.h"


//typedefs for Fusion Public API function prototypes
typedef DWORD (WINAPI* LPFN_OPEN_FUSION_API)   (PDWORD,FAPI_ACCESS_TYPE,PTCHAR);
typedef DWORD (WINAPI* LPFN_CLOSE_FUSION_API)  (DWORD);
typedef	DWORD (WINAPI* LPFN_COMMAND_FUSION_API)(DWORD,DWORD,PVOID,DWORD,PVOID,DWORD, PDWORD);


//defines globals used withing high level APIs. 
static DWORD    				g_hInstFusionDLL      = 0;
static LPFN_OPEN_FUSION_API		lpfn_OpenFusionAPI    = NULL;
static LPFN_CLOSE_FUSION_API	lpfn_CloseFusionAPI   = NULL;
static LPFN_COMMAND_FUSION_API	lpfn_CommandFusionAPI = NULL;

DWORD FusionFindFirstWLANAdapter();
BOOL AddFusionProfile(PVOID pProfile);
int processData(TiXmlDocument *pDoc);
void AddLog(DWORD color, const TCHAR *lpszText, ...);
void  FusionSampleDisplayLastError();

BOOL bLog = TRUE;
BOOL bConnect = FALSE;
BOOL bExport = FALSE;

TCHAR tcszExportFilename[260];
TCHAR g_pszFusionVersionStr[FAPI_MAX_MODULE_VERSION_SIZE];


BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			ClearLog();
			InitializeFusion();
		}
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		DeinitializeFusion();
		break;
	}
    return TRUE;
}

void LogLastError()
{
	LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError(); 

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    // Display the error message and exit the process

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, 
        (lstrlen((LPCTSTR)lpMsgBuf)+lstrlen((LPCTSTR)"funcname")+40)*sizeof(TCHAR)); 
    StringCchPrintf((LPTSTR)lpDisplayBuf, 
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"), 
        _T("func"), dw, lpMsgBuf); 
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK); 

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}


void ClearLog()
{
	DeleteFile(logfilenameW);
}

//UNICODE version of AddLog function
void AddLog(int color, const TCHAR *lpszText, ...)
{

	if(bLog==FALSE)
		return;

	TCHAR szColor[10];
	if(color==1) //Err (Red)
		_tcscpy(szColor,_T("FF0000"));
	else if(color==2) // (Blue)
		_tcscpy(szColor,_T("0000FF"));
	else
		_tcscpy(szColor,_T("000000"));	

	va_list argList;
	FILE *pFile = NULL;

	//Initialize variable argument list
	va_start(argList, lpszText);
	SYSTEMTIME systime;
	GetSystemTime(&systime);  //get current time and date

	TCHAR szBuffer[1024];	
	int ret = _vsnwprintf(szBuffer,sizeof(szBuffer),lpszText, argList);
#ifdef _DEBUG				
	OutputDebugString(szBuffer);
	OutputDebugString(_T("\n"));
#endif
	va_end(argList);

	//Open the log file for appending
	pFile = fopen(logfilename, "a+");	
	if(pFile != NULL){
		//Write the error to the log file
		//fwprintf(pFile, _T("<font face=\"Arial\" size=\"2\" color=\"#%s\"><b>"),szColor);	
		fwprintf(pFile, _T("<font face=\"Arial\" size=\"2\" color=\"#%s\"> %d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d<b> "),szColor,systime.wYear,systime.wMonth,systime.wDay,systime.wHour,systime.wMinute,systime.wSecond); 				
		fwprintf(pFile, szBuffer);
		fwprintf(pFile, _T("</b></font><br>\n"));
		//Close the file
		fclose(pFile);			
	}			

}


//For logging purpose
TCHAR * GetAuthMethodName(DWORD dwAuth)
{
	switch(dwAuth) {
		case FAPI_EAP_TLS: return _T("EAP TLS");
		case FAPI_PEAP_MSCHAPV2: return _T("PEAP MSCHAPv2");
		case FAPI_PEAP_TLS: return _T("PEAP TLS");
		case FAPI_LEAP: return _T("LEAP");
		case FAPI_EAP_TTLS_CHAP :return _T("EAP TTLS CHAP");
		case FAPI_EAP_TTLS_MSCHAP:return _T("EAP TTLS MSCHAP");
		case FAPI_EAP_TTLS_MSCHAPV2: return _T("EAP TTLS MSCHAPv2");
		case FAPI_EAP_TTLS_PAP: return _T("EAP TTLS PAP");
		case FAPI_EAP_TTLS_MD5: return _T("EAP TTLS MD5");
		case FAPI_PEAP_GTC: return _T("PEAP EAP-GTC");
		case FAPI_EAP_FAST_MSCHAPV2: return _T("EAP-FAST MSCHAPv2");
		case FAPI_EAP_FAST_TLS: return _T("EAP-FAST TLS");
		case FAPI_EAP_FAST_GTC: return _T("EAP-FAST EAP-GTC");
		default:
		case FAPI_AUTH_NONE: return _T("None");	
	};
}


int loadXMLFile(char *szFilename)
{
	TiXmlDocument doc(szFilename);
	
	if(!doc.LoadFile()) {
		AddLog(1,_T("Error loading xml file: %S"),szFilename);
		return ERR_LOADING_FILE;
	}
	AddLog(3,_T("Loaded xml file!\n"));
	int iRet  = processData(&doc);
	return iRet;
}


int loadXMLString(char *szXMLString)
{
	TiXmlDocument doc("xmlstreaming");
	doc.Parse(szXMLString);
	return processData(&doc);
}


DWORD GetStructVersion()
{
	DWORD dwVer = FAPI_PROFILE_2_VERSION; 

	if(_tcsncmp(g_pszFusionVersionStr,_T("2.4."),4)==0){
		dwVer = FAPI_PROFILE_2_VERSION; 
	}
	else if(_tcsncmp(g_pszFusionVersionStr,_T("2.35."),5)==0){
		dwVer = FAPI_PROFILE_3_VERSION;
	} 
	else if(_tcsncmp(g_pszFusionVersionStr,_T("2.5."),4)==0){
		dwVer = FAPI_PROFILE_3_VERSION;
	}
	else if(_tcsncmp(g_pszFusionVersionStr,_T("2.55."),5)==0){
		dwVer = FAPI_PROFILE_4_VERSION;
	}
	else if(_tcsncmp(g_pszFusionVersionStr,_T("2.56."),5)==0){
		dwVer = FAPI_PROFILE_6_VERSION;
	} 
	else if(_tcsncmp(g_pszFusionVersionStr,_T("2.57."),5)==0){
		dwVer = FAPI_PROFILE_6_VERSION;
	} 
	else if(_tcsncmp(g_pszFusionVersionStr,_T("2.61."),5)==0){
		dwVer = FAPI_PROFILE_5_VERSION;
	} 
	else if(_tcsncmp(g_pszFusionVersionStr,_T("2.60."),5)==0){
		dwVer = FAPI_PROFILE_5_VERSION;
	}
	else if(_tcsncmp(g_pszFusionVersionStr,_T("3.00."),5)==0){
		dwVer = FAPI_PROFILE_7_VERSION;
	}
	else if(_tcsncmp(g_pszFusionVersionStr,_T("3.20."),5)==0){
		dwVer = FAPI_PROFILE_8_VERSION;
	}
	else if(_tcsncmp(g_pszFusionVersionStr,_T("3.30."),5)==0){
		dwVer = FAPI_PROFILE_9_VERSION;
	}
	return dwVer;
}

/******************************************************************
Autodetect security method depending on encryption & authentication being used or not.
******************************************************************/
FAPI_WLAN_SECURITY_TYPE GetSecurityMode(FAPI_WLAN_AUTHENTICATION_TYPE dwAuthentication,FAPI_WLAN_ENCRYPTION_TYPE dwEncryption)
{
	if((dwEncryption==FAPI_ENCRYPTION_TKIP) && (dwAuthentication==FAPI_AUTH_NONE))
	  return FAPI_SECURITY_WPA_PERSONAL;
	else if((dwEncryption==FAPI_ENCRYPTION_TKIP) && (dwAuthentication!=FAPI_AUTH_NONE))
	  return FAPI_SECURITY_WPA_ENTERPRISE;
	else if((dwEncryption==FAPI_ENCRYPTION_AES) && (dwAuthentication==FAPI_AUTH_NONE))
	  return FAPI_SECURITY_WPA2_PERSONAL;
	else if((dwEncryption==FAPI_ENCRYPTION_AES) && (dwAuthentication!=FAPI_AUTH_NONE))
	  return FAPI_SECURITY_WPA2_ENTERPRISE;

	return FAPI_SECURITY_LEGACY;
}


FAPI_PROFILE_2 ParseProfile2(CFusionXMLProfile &fxml)
{
	FAPI_PROFILE_2  fapiProfile = {0};

	fapiProfile.dwVersion = GetStructVersion();
	AddLog(3,_T("Detected Fusion Structure Ver = %d"),fapiProfile.dwVersion);

	//specify common properties for both Adhoc and Infrastructure
	fapiProfile.dwType = FAPI_PROFILE_TYPE;	

	//Default values
	fapiProfile.dwPowerIndex = FAPI_WLAN_POWERMODE_FAST_POWER_SAVE;
	fapiProfile.dwTxPower = FAPI_POWER_BSS_AUTO;					// Must use AUTO or PLUS for infrastructure
	fapiProfile.dwOpMode =  FAPI_NDIS802_11INFRASTRUCTURE ;			// infrastructure mode
	fapiProfile.NetworkType.Adhoc.dwChannel = 0;					// reset back to original	
	fapiProfile.dwIPAddressingMode = FAPI_ADDR_MODE_IPV4_DHCP;
	fapiProfile.dwEncryption = FAPI_ENCRYPTION_NONE ;
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_AUTH_NONE;


	fxml.SetProfileName(fapiProfile.pszName,sizeof(fapiProfile.pszName)/sizeof(TCHAR));
	AddLog(3,_T("Profile Name = %s"),fapiProfile.pszName);
	
	fapiProfile.dwOpMode = (FAPI_WLAN_NETWORK_TYPE) fxml.GetOpMode(); 
	fapiProfile.NetworkType.Adhoc.dwChannel = fxml.GetChannel();

	fxml.GetSSID(fapiProfile.pszSSID);
	fxml.GetCountry(fapiProfile.pszCountryCode);
	fapiProfile.dwPowerIndex = (FAPI_WLAN_POWER_MODE) fxml.GetPowerIndex();
	fapiProfile.dwTxPower = (FAPI_TRANSMIT_POWER_LEVEL) fxml.GetTxPower();


	fapiProfile.dwIPAddressingMode = (FAPI_NETWORK_ADDRESSING_MODE)fxml.GetIPAddressMode(); //Static or DHCP?

	fxml.GetIPv4Address(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Address);
	fxml.GetSubnet(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4SubnetMask);
	fxml.GetGateway(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Gateway);
	fxml.GetDNS1(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS1);
	fxml.GetDNS2(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS2);
	fxml.GetWINS1(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS1);
	fxml.GetWINS2(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS2);

	fapiProfile.NetworkType.Infrastructure.CredentialSettings.dwCredentialFlags = fxml.GetCredentialMode();
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = (FAPI_WLAN_AUTHENTICATION_TYPE) fxml.GetAuthenticationMode();
	AddLog(0,_T("Auth Method %s"),GetAuthMethodName(fapiProfile.NetworkType.Infrastructure.dwAuthentication));


	//Parse Cache options 
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = 0; //FAPI_CACHE_OPTION_CONNECT;

	DWORD dwCacheOpts,dwTimeCacheOpts,dwCacheRT;
	fxml.GetCredentialCache(&dwCacheOpts,&dwTimeCacheOpts,&dwCacheRT,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszFirstLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszSecondLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszThirdLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszFourthLoginPromptTime);

    fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = dwCacheOpts;
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwTimeCacheOpts = (FAPI_LOGIN_TIME_CACHE_OPTIONS)dwTimeCacheOpts;
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.TimeInterval.dwCacheRT = dwCacheRT;

	//fapiProfile.NetworkType.Infrastructure.dwSecurityMode = (FAPI_WLAN_SECURITY_TYPE)fxml.GetSecurityType();
	fapiProfile.dwEncryption = (FAPI_WLAN_ENCRYPTION_TYPE)fxml.GetEncryption();

	if(fapiProfile.dwEncryption == FAPI_ENCRYPTION_TKIP)
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.TKIPType.pszTKIPPassphrase);
	
	DWORD dwKeyIndex = 0;
	fxml.GetWEP128(&dwKeyIndex,
				fapiProfile.EncryptionAlgorithm.WEP128BitHexKey.pszWEPKey[0],
				fapiProfile.EncryptionAlgorithm.WEP128BitHexKey.pszWEPKey[1],
				fapiProfile.EncryptionAlgorithm.WEP128BitHexKey.pszWEPKey[2],
				fapiProfile.EncryptionAlgorithm.WEP128BitHexKey.pszWEPKey[3]);

	fapiProfile.EncryptionAlgorithm.WEP128BitHexKey.dwWEPKeyIndex = (FAPI_WLAN_WEP_KEY_INDEX)dwKeyIndex;

	dwKeyIndex = 0;
	fxml.GetWEP40(&dwKeyIndex,
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[0],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[1],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[2],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[3]);

	fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.dwWEPKeyIndex = (FAPI_WLAN_WEP_KEY_INDEX)dwKeyIndex;
	
	TiXmlElement *pElmProf = fxml.GetRootElement();

	TiXmlElement *pUserCred = NULL; 
	pUserCred = fxml.GetElementSafe(pElmProf,"UserCredentials");		
	if(pUserCred){
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszIdentity,"UserName",FAPI_MAX_USERNAME_LENGTH);
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszUserPwd,"Password",FAPI_MAX_PASSWORD_LENGTH);
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszDomain,"Domain",FAPI_MAX_DOMAINNAME_LENGTH);
	}

	TiXmlElement *pIEEE8021X = NULL; 
	pIEEE8021X = fxml.GetElementSafe(pElmProf,"IEEE8021X");		
	if(pIEEE8021X){
		fxml.GetText(pIEEE8021X,fapiProfile.NetworkType.Infrastructure.CredentialSettings.IEEE8021X_CredSettings.psz802_1xDomain,"Domain",FAPI_MAX_DOMAINNAME_LENGTH);
		fxml.GetText(pIEEE8021X,fapiProfile.NetworkType.Infrastructure.CredentialSettings.IEEE8021X_CredSettings.psz802_1xUserIdentity ,"UserIdentity",FAPI_MAX_USERNAME_LENGTH);
	}

	TiXmlElement *pServerCert = NULL; 
	pServerCert = fxml.GetElementSafe(pElmProf,"ServerCert");		
	if(pServerCert) {
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.FileCertInstall.pszServerCertFName ,"Filename",FAPI_MAX_CERT_FNAME_LENGTH);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.FileCertInstall.pszServerCertPath ,"Path",FAPI_MAX_SERVER_CERT_PATH_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.LocalCertInstall.pszServerCertFName ,"LocalCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	pServerCert = fxml.GetElementSafe(pElmProf,"LocalUserCert");		
	if(pServerCert) {	
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.LocalCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	pServerCert = fxml.GetElementSafe(pElmProf,"RemoteUserCert");		
	if(pServerCert) {
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszServerName,"ServerName",FAPI_MAX_REMOTE_SERVER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemoteUserName,"UserName",FAPI_MAX_REMOTE_USER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemotePassword,"Password",FAPI_MAX_REMOTE_PASSWORD_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}
	
	return fapiProfile;
}


FAPI_PROFILE_3 ParseProfile3(CFusionXMLProfile &fxml)
{
	FAPI_PROFILE_3  fapiProfile = {0};

	fapiProfile.dwVersion = GetStructVersion();
	//AddLog(3,_T("Detected Fusion Structure Ver = %d"),fapiProfile.dwVersion);

	//specify common properties for both Adhoc and Infrastructure
	fapiProfile.dwType = FAPI_PROFILE_TYPE;	

	//Default values
	fapiProfile.dwPowerIndex = FAPI_WLAN_POWERMODE_FAST_POWER_SAVE;
	fapiProfile.dwTxPower = FAPI_POWER_BSS_AUTO;					// Must use AUTO or PLUS for infrastructure
	fapiProfile.dwOpMode =  FAPI_NDIS802_11INFRASTRUCTURE ;			// infrastructure mode
	fapiProfile.NetworkType.Adhoc.dwChannel = 0;					// reset back to original	
	fapiProfile.dwIPAddressingMode = FAPI_ADDR_MODE_IPV4_DHCP;
	fapiProfile.dwEncryption = FAPI_ENCRYPTION_NONE ;
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_AUTH_NONE;


	fxml.SetProfileName(fapiProfile.pszName,sizeof(fapiProfile.pszName)/sizeof(TCHAR));
	AddLog(3,_T("Profile Name = %s"),fapiProfile.pszName);
	
	fapiProfile.dwOpMode = (FAPI_WLAN_NETWORK_TYPE) fxml.GetOpMode(); 
	fapiProfile.NetworkType.Adhoc.dwChannel = fxml.GetChannel();

	fxml.GetSSID(fapiProfile.pszSSID);
	fxml.GetCountry(fapiProfile.pszCountryCode);
	fapiProfile.dwPowerIndex = (FAPI_WLAN_POWER_MODE) fxml.GetPowerIndex();
	fapiProfile.dwTxPower = (FAPI_TRANSMIT_POWER_LEVEL) fxml.GetTxPower();


	fapiProfile.dwIPAddressingMode = (FAPI_NETWORK_ADDRESSING_MODE)fxml.GetIPAddressMode(); //Static or DHCP?

	fxml.GetIPv4Address(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Address);
	fxml.GetSubnet(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4SubnetMask);
	fxml.GetGateway(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Gateway);
	fxml.GetDNS1(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS1);
	fxml.GetDNS2(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS2);
	fxml.GetWINS1(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS1);
	fxml.GetWINS2(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS2);

	fapiProfile.NetworkType.Infrastructure.CredentialSettings.dwCredentialFlags = fxml.GetCredentialMode();
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = (FAPI_WLAN_AUTHENTICATION_TYPE) fxml.GetAuthenticationMode();
	AddLog(0,_T("Auth Method %s"),GetAuthMethodName(fapiProfile.NetworkType.Infrastructure.dwAuthentication));


	//Parse Cache options 
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = 0; //FAPI_CACHE_OPTION_CONNECT;

	DWORD dwCacheOpts,dwTimeCacheOpts,dwCacheRT;
	fxml.GetCredentialCache(&dwCacheOpts,&dwTimeCacheOpts,&dwCacheRT,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszFirstLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszSecondLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszThirdLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszFourthLoginPromptTime);

    fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = dwCacheOpts;
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwTimeCacheOpts = (FAPI_LOGIN_TIME_CACHE_OPTIONS)dwTimeCacheOpts;
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.TimeInterval.dwCacheRT = dwCacheRT;

	//fapiProfile.NetworkType.Infrastructure.dwSecurityMode = (FAPI_WLAN_SECURITY_TYPE)fxml.GetSecurityType();
	fapiProfile.dwEncryption = (FAPI_WLAN_ENCRYPTION_TYPE)fxml.GetEncryption();

	
	DWORD dwKeyIndex = 0;
	fxml.GetWEP128(&dwKeyIndex,
				fapiProfile.EncryptionAlgorithm.WEP128BitHexKey.pszWEPKey[0],
				fapiProfile.EncryptionAlgorithm.WEP128BitHexKey.pszWEPKey[1],
				fapiProfile.EncryptionAlgorithm.WEP128BitHexKey.pszWEPKey[2],
				fapiProfile.EncryptionAlgorithm.WEP128BitHexKey.pszWEPKey[3]);

	fapiProfile.EncryptionAlgorithm.WEP128BitHexKey.dwWEPKeyIndex = (FAPI_WLAN_WEP_KEY_INDEX)dwKeyIndex;


	dwKeyIndex = 0;
	fxml.GetWEP40(&dwKeyIndex,
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[0],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[1],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[2],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[3]);

	fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.dwWEPKeyIndex = (FAPI_WLAN_WEP_KEY_INDEX)dwKeyIndex;


	if(fapiProfile.dwEncryption == FAPI_ENCRYPTION_TKIP)
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.TKIPType.pszTKIPPassphrase);
	else if( fapiProfile.dwEncryption == FAPI_ENCRYPTION_AES)
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.AESType.pszAESPassphrase);


	TiXmlElement *pElmProf = fxml.GetRootElement();

	TiXmlElement *pUserCred = NULL; 
	pUserCred = fxml.GetElementSafe(pElmProf,"UserCredentials");		
	if(pUserCred) {
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszIdentity,"UserName",FAPI_MAX_USERNAME_LENGTH);
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszUserPwd,"Password",FAPI_MAX_PASSWORD_LENGTH);
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszDomain,"Domain",FAPI_MAX_DOMAINNAME_LENGTH);
	}

	TiXmlElement *pIEEE8021X = NULL; 
	pIEEE8021X = fxml.GetElementSafe(pElmProf,"IEEE8021X");		
	if(pIEEE8021X){
		fxml.GetText(pIEEE8021X,fapiProfile.NetworkType.Infrastructure.CredentialSettings.IEEE8021X_CredSettings.psz802_1xDomain,"Domain",FAPI_MAX_DOMAINNAME_LENGTH);
		fxml.GetText(pIEEE8021X,fapiProfile.NetworkType.Infrastructure.CredentialSettings.IEEE8021X_CredSettings.psz802_1xUserIdentity ,"UserIdentity",FAPI_MAX_USERNAME_LENGTH);
	}

	TiXmlElement *pServerCert = NULL; 
	pServerCert = fxml.GetElementSafe(pElmProf,"ServerCert");		
	if(pServerCert) {
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.FileCertInstall.pszServerCertFName ,"Filename",FAPI_MAX_CERT_FNAME_LENGTH);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.FileCertInstall.pszServerCertPath ,"Path",FAPI_MAX_SERVER_CERT_PATH_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.LocalCertInstall.pszServerCertFName ,"LocalCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}
	//Special for Ver 3 profile
	//Server cert is mandatory if authnetication is being used
	if(fapiProfile.NetworkType.Infrastructure.dwAuthentication != FAPI_AUTH_NONE) {
		//strcpy(fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.LocalCertInstall.pszServerCertFName,"Thawte");
		fapiProfile.NetworkType.Infrastructure.CredentialSettings.dwCredentialFlags = (FAPI_SPECIFY_SERVER_CERTIFICATE_LOCAL | FAPI_SPECIFY_PROFILE_TYPE_AS_USER_PROFILE);
		_tcscpy(fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.LocalCertInstall.pszServerCertFName,_T("Class 2 Public Primary Certification Authority"));
	
	}


	pServerCert = fxml.GetElementSafe(pElmProf,"LocalUserCert");		
	if(pServerCert) {	
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.LocalCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	pServerCert = fxml.GetElementSafe(pElmProf,"RemoteUserCert");		
	if(pServerCert) {
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszServerName,"ServerName",FAPI_MAX_REMOTE_SERVER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemoteUserName,"UserName",FAPI_MAX_REMOTE_USER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemotePassword,"Password",FAPI_MAX_REMOTE_PASSWORD_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}
	
	return fapiProfile;

}

//
FAPI_PROFILE_4 ParseProfile4(CFusionXMLProfile &fxml)
{
	FAPI_PROFILE_4  fapiProfile = {0};

	fapiProfile.dwVersion = GetStructVersion();
	AddLog(3,_T("Detected Fusion Structure Ver = %d"),fapiProfile.dwVersion);

	//specify common properties for both Adhoc and Infrastructure
	fapiProfile.dwType = FAPI_PROFILE_TYPE;	

	//Default values
	fapiProfile.dwPowerIndex = FAPI_WLAN_POWERMODE_FAST_POWER_SAVE;
	fapiProfile.dwTxPower = FAPI_POWER_BSS_AUTO;					// Must use AUTO or PLUS for infrastructure
	fapiProfile.dwOpMode =  FAPI_NDIS802_11INFRASTRUCTURE ;			// infrastructure mode
	fapiProfile.NetworkType.Adhoc.dwChannel = 0;					// reset back to original	
	fapiProfile.dwIPAddressingMode = FAPI_ADDR_MODE_IPV4_DHCP;
	fapiProfile.dwEncryption = FAPI_ENCRYPTION_NONE ;
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_AUTH_NONE;


	fxml.SetProfileName(fapiProfile.pszName,sizeof(fapiProfile.pszName)/sizeof(TCHAR));
	AddLog(3,_T("Profile Name = %s"),fapiProfile.pszName);
	
	fapiProfile.dwOpMode = (FAPI_WLAN_NETWORK_TYPE) fxml.GetOpMode(); 
	fapiProfile.NetworkType.Adhoc.dwChannel = fxml.GetChannel();

	fxml.GetSSID(fapiProfile.pszSSID);
	fxml.GetCountry(fapiProfile.pszCountryCode);
	fapiProfile.dwPowerIndex = (FAPI_WLAN_POWER_MODE) fxml.GetPowerIndex();
	fapiProfile.dwTxPower = (FAPI_TRANSMIT_POWER_LEVEL) fxml.GetTxPower();


	fapiProfile.dwIPAddressingMode = (FAPI_NETWORK_ADDRESSING_MODE)fxml.GetIPAddressMode(); //Static or DHCP?

	fxml.GetIPv4Address(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Address);
	fxml.GetSubnet(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4SubnetMask);
	fxml.GetGateway(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Gateway);
	fxml.GetDNS1(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS1);
	fxml.GetDNS2(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS2);
	fxml.GetWINS1(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS1);
	fxml.GetWINS2(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS2);

	fapiProfile.NetworkType.Infrastructure.CredentialSettings.dwCredentialFlags = fxml.GetCredentialMode();
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = (FAPI_WLAN_AUTHENTICATION_TYPE) fxml.GetAuthenticationMode();
	AddLog(0,_T("Auth Method %s"),GetAuthMethodName(fapiProfile.NetworkType.Infrastructure.dwAuthentication));


	//Parse Cache options 
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = 0; //FAPI_CACHE_OPTION_CONNECT;

	DWORD dwCacheOpts = 0,dwTimeCacheOpts = 0,dwCacheRT = 0;  //fixed 1.16
	fxml.GetCredentialCache(&dwCacheOpts,&dwTimeCacheOpts,&dwCacheRT,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszFirstLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszSecondLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszThirdLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszFourthLoginPromptTime);

    fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = dwCacheOpts;
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwTimeCacheOpts = (FAPI_LOGIN_TIME_CACHE_OPTIONS)dwTimeCacheOpts;
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.TimeInterval.dwCacheRT = dwCacheRT;

	//fapiProfile.NetworkType.Infrastructure.dwSecurityMode = (FAPI_WLAN_SECURITY_TYPE)fxml.GetSecurityType();
	fapiProfile.dwEncryption = (FAPI_WLAN_ENCRYPTION_TYPE)fxml.GetEncryption();


	DWORD dwKeyIndex = 0;
	fxml.GetWEP128(&dwKeyIndex,
				fapiProfile.EncryptionAlgorithm.WEP128BitHexKey.pszWEPKey[0],
				fapiProfile.EncryptionAlgorithm.WEP128BitHexKey.pszWEPKey[1],
				fapiProfile.EncryptionAlgorithm.WEP128BitHexKey.pszWEPKey[2],
				fapiProfile.EncryptionAlgorithm.WEP128BitHexKey.pszWEPKey[3]);

	fapiProfile.EncryptionAlgorithm.WEP128BitHexKey.dwWEPKeyIndex = (FAPI_WLAN_WEP_KEY_INDEX)dwKeyIndex;

	dwKeyIndex = 0;
	fxml.GetWEP40(&dwKeyIndex,
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[0],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[1],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[2],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[3]);

	fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.dwWEPKeyIndex = (FAPI_WLAN_WEP_KEY_INDEX)dwKeyIndex;


	if(fapiProfile.dwEncryption == FAPI_ENCRYPTION_TKIP)
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.TKIPType.pszTKIPPassphrase);
	else if( fapiProfile.dwEncryption == FAPI_ENCRYPTION_AES)
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.AESType.pszAESPassphrase);
	


	TiXmlElement *pElmProf = fxml.GetRootElement();

	TiXmlElement *pUserCred = NULL; 
	pUserCred = fxml.GetElementSafe(pElmProf,"UserCredentials");		
	if(pUserCred) {
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszIdentity,"UserName",FAPI_MAX_USERNAME_LENGTH);
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszUserPwd,"Password",FAPI_MAX_PASSWORD_LENGTH);
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszDomain,"Domain",FAPI_MAX_DOMAINNAME_LENGTH);
	}

	TiXmlElement *pIEEE8021X = NULL; 
	pIEEE8021X = fxml.GetElementSafe(pElmProf,"IEEE8021X");		
	if(pIEEE8021X) {
		fxml.GetText(pIEEE8021X,fapiProfile.NetworkType.Infrastructure.CredentialSettings.IEEE8021X_CredSettings.psz802_1xDomain,"Domain",FAPI_MAX_DOMAINNAME_LENGTH);
		fxml.GetText(pIEEE8021X,fapiProfile.NetworkType.Infrastructure.CredentialSettings.IEEE8021X_CredSettings.psz802_1xUserIdentity ,"UserIdentity",FAPI_MAX_USERNAME_LENGTH);
	}

	TiXmlElement *pServerCert = NULL; 
	pServerCert = fxml.GetElementSafe(pElmProf,"ServerCert");		
	if(pServerCert) {
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.FileCertInstall.pszServerCertFName ,"Filename",FAPI_MAX_CERT_FNAME_LENGTH);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.FileCertInstall.pszServerCertPath ,"Path",FAPI_MAX_SERVER_CERT_PATH_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.LocalCertInstall.pszServerCertFName ,"LocalCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	pServerCert = fxml.GetElementSafe(pElmProf,"LocalUserCert");		
	if(pServerCert) {	
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.LocalCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	pServerCert = fxml.GetElementSafe(pElmProf,"RemoteUserCert");		
	if(pServerCert) {
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszServerName,"ServerName",FAPI_MAX_REMOTE_SERVER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemoteUserName,"UserName",FAPI_MAX_REMOTE_USER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemotePassword,"Password",FAPI_MAX_REMOTE_PASSWORD_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}
	
	return fapiProfile;

}

FAPI_PROFILE_5 ParseProfile5(CFusionXMLProfile &fxml)
{
	FAPI_PROFILE_5  fapiProfile = {0};

	fapiProfile.dwVersion = GetStructVersion();
	AddLog(3,_T("Detected Fusion Structure Ver = %d"),fapiProfile.dwVersion);

	//specify common properties for both Adhoc and Infrastructure
	fapiProfile.dwType = FAPI_PROFILE_TYPE;	

	//Default values
	fapiProfile.dwPowerIndex = FAPI_WLAN_POWERMODE_FAST_POWER_SAVE;
	fapiProfile.dwTxPower = FAPI_POWER_BSS_AUTO;					// Must use AUTO or PLUS for infrastructure
	fapiProfile.dwOpMode =  FAPI_NDIS802_11INFRASTRUCTURE ;			// infrastructure mode
	fapiProfile.NetworkType.Adhoc.dwChannel = 0;					// reset back to original	
	fapiProfile.dwIPAddressingMode = FAPI_ADDR_MODE_IPV4_DHCP;
	fapiProfile.dwEncryption = FAPI_ENCRYPTION_NONE ;
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_AUTH_NONE;


	fxml.SetProfileName(fapiProfile.pszName,sizeof(fapiProfile.pszName)/sizeof(TCHAR));
	AddLog(3,_T("Profile Name = %s"),fapiProfile.pszName);
	
	fapiProfile.dwOpMode = (FAPI_WLAN_NETWORK_TYPE) fxml.GetOpMode(); 
	fapiProfile.NetworkType.Adhoc.dwChannel = fxml.GetChannel();

	fxml.GetSSID(fapiProfile.pszSSID);
	fxml.GetCountry(fapiProfile.pszCountryCode);
	fapiProfile.dwPowerIndex = (FAPI_WLAN_POWER_MODE) fxml.GetPowerIndex();
	fapiProfile.dwTxPower = (FAPI_TRANSMIT_POWER_LEVEL) fxml.GetTxPower();


	fapiProfile.dwIPAddressingMode = (FAPI_NETWORK_ADDRESSING_MODE)fxml.GetIPAddressMode(); //Static or DHCP?

	fxml.GetIPv4Address(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Address);
	fxml.GetSubnet(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4SubnetMask);
	fxml.GetGateway(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Gateway);
	fxml.GetDNS1(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS1);
	fxml.GetDNS2(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS2);
	fxml.GetWINS1(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS1);
	fxml.GetWINS2(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS2);

	fapiProfile.NetworkType.Infrastructure.CredentialSettings.dwCredentialFlags = fxml.GetCredentialMode();
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = (FAPI_WLAN_AUTHENTICATION_TYPE) fxml.GetAuthenticationMode();
	AddLog(0,_T("Auth Method %s"),GetAuthMethodName(fapiProfile.NetworkType.Infrastructure.dwAuthentication));


	//Parse Cache options 
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = 0; //FAPI_CACHE_OPTION_CONNECT;

	DWORD dwCacheOpts,dwTimeCacheOpts,dwCacheRT;
	fxml.GetCredentialCache(&dwCacheOpts,&dwTimeCacheOpts,&dwCacheRT,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszFirstLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszSecondLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszThirdLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszFourthLoginPromptTime);

    fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = dwCacheOpts;
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwTimeCacheOpts = (FAPI_LOGIN_TIME_CACHE_OPTIONS)dwTimeCacheOpts;
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.TimeInterval.dwCacheRT = dwCacheRT;

	fapiProfile.NetworkType.Infrastructure.dwSecurityMode = (FAPI_WLAN_SECURITY_TYPE)fxml.GetSecurityType();
	fapiProfile.dwEncryption = (FAPI_WLAN_ENCRYPTION_TYPE)fxml.GetEncryption();

	fapiProfile.NetworkType.Infrastructure.dwSecurityMode = GetSecurityMode(fapiProfile.NetworkType.Infrastructure.dwAuthentication,fapiProfile.dwEncryption);

	DWORD dwKeyIndex = 0;
	fxml.GetWEP128(&dwKeyIndex,
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[0],
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[1],
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[2],
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[3]);

	fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.dwWEPKeyIndex = (FAPI_WLAN_WEP_KEY_INDEX)dwKeyIndex;


	dwKeyIndex = 0;
	fxml.GetWEP40(&dwKeyIndex,
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[0],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[1],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[2],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[3]);

	fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.dwWEPKeyIndex = (FAPI_WLAN_WEP_KEY_INDEX)dwKeyIndex;

	if(fapiProfile.dwEncryption == FAPI_ENCRYPTION_TKIP)
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.TKIPPassphrase.pszTKIPPassphrase);
	else if( fapiProfile.dwEncryption == FAPI_ENCRYPTION_AES)
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.AESPassphrase.pszAESPassphrase);


	TiXmlElement *pElmProf = fxml.GetRootElement();

	TiXmlElement *pUserCred = NULL; 
	pUserCred = fxml.GetElementSafe(pElmProf,"UserCredentials");		
	if(pUserCred)
	{
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszIdentity,"UserName",FAPI_MAX_USERNAME_LENGTH);
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszUserPwd,"Password",FAPI_MAX_PASSWORD_LENGTH);
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszDomain,"Domain",FAPI_MAX_DOMAINNAME_LENGTH);
	}

	TiXmlElement *pIEEE8021X = NULL; 
	pIEEE8021X = fxml.GetElementSafe(pElmProf,"IEEE8021X");		
	if(pIEEE8021X)
	{
		fxml.GetText(pIEEE8021X,fapiProfile.NetworkType.Infrastructure.CredentialSettings.IEEE8021X_CredSettings.psz802_1xDomain,"Domain",FAPI_MAX_DOMAINNAME_LENGTH);
		fxml.GetText(pIEEE8021X,fapiProfile.NetworkType.Infrastructure.CredentialSettings.IEEE8021X_CredSettings.psz802_1xUserIdentity ,"UserIdentity",FAPI_MAX_USERNAME_LENGTH);
	}

	TiXmlElement *pServerCert = NULL; 
	pServerCert = fxml.GetElementSafe(pElmProf,"ServerCert");		
	if(pServerCert){
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.FileCertInstall.pszServerCertFName ,"Filename",FAPI_MAX_CERT_FNAME_LENGTH);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.FileCertInstall.pszServerCertPath ,"Path",FAPI_MAX_SERVER_CERT_PATH_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.LocalCertInstall.pszServerCertFName ,"LocalCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	pServerCert = fxml.GetElementSafe(pElmProf,"LocalUserCert");		
	if(pServerCert){	
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.LocalCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	pServerCert = fxml.GetElementSafe(pElmProf,"RemoteUserCert");		
	if(pServerCert)
	{
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszServerName,"ServerName",FAPI_MAX_REMOTE_SERVER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemoteUserName,"UserName",FAPI_MAX_REMOTE_USER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemotePassword,"Password",FAPI_MAX_REMOTE_PASSWORD_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}
	
	return fapiProfile;
}

FAPI_PROFILE_6 ParseProfile6(CFusionXMLProfile &fxml)
{
	FAPI_PROFILE_6  fapiProfile = {0}; //for 2.55 and 2.57
	//ZeroMemory(&fapiProfile, sizeof(FAPI_PROFILE_6)); 

	fapiProfile.dwVersion = GetStructVersion();
	AddLog(3,_T("Detected Fusion Structure Ver = %d"),fapiProfile.dwVersion);

	//specify common properties for both Adhoc and Infrastructure
	fapiProfile.dwType = FAPI_PROFILE_TYPE;	

	//Default values
	fapiProfile.dwPowerIndex = FAPI_WLAN_POWERMODE_FAST_POWER_SAVE;
	fapiProfile.dwTxPower = FAPI_POWER_BSS_AUTO;					// Must use AUTO or PLUS for infrastructure
	fapiProfile.dwOpMode =  FAPI_NDIS802_11INFRASTRUCTURE ;			// infrastructure mode
	fapiProfile.NetworkType.Adhoc.dwChannel = 0;					// reset back to original	
	fapiProfile.dwIPAddressingMode = FAPI_ADDR_MODE_IPV4_DHCP;
	fapiProfile.dwEncryption = FAPI_ENCRYPTION_NONE ;
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_AUTH_NONE;


	fxml.SetProfileName(fapiProfile.pszName,sizeof(fapiProfile.pszName)/sizeof(TCHAR));
	AddLog(3,_T("Profile Name = %s"),fapiProfile.pszName);
	
	fapiProfile.dwOpMode = (FAPI_WLAN_NETWORK_TYPE) fxml.GetOpMode(); 
	fapiProfile.NetworkType.Adhoc.dwChannel = fxml.GetChannel();

	fxml.GetSSID(fapiProfile.pszSSID);
	fxml.GetCountry(fapiProfile.pszCountryCode);
	fapiProfile.dwPowerIndex = (FAPI_WLAN_POWER_MODE) fxml.GetPowerIndex();
	fapiProfile.dwTxPower = (FAPI_TRANSMIT_POWER_LEVEL) fxml.GetTxPower();


	fapiProfile.dwIPAddressingMode = (FAPI_NETWORK_ADDRESSING_MODE)fxml.GetIPAddressMode(); //Static or DHCP?

	fxml.GetIPv4Address(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Address);
	fxml.GetSubnet(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4SubnetMask);
	fxml.GetGateway(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Gateway);
	fxml.GetDNS1(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS1);
	fxml.GetDNS2(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS2);
	fxml.GetWINS1(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS1);
	fxml.GetWINS2(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS2);

	fapiProfile.NetworkType.Infrastructure.CredentialSettings.dwCredentialFlags = fxml.GetCredentialMode();
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = (FAPI_WLAN_AUTHENTICATION_TYPE) fxml.GetAuthenticationMode();
	AddLog(0,_T("Auth Method %s"),GetAuthMethodName(fapiProfile.NetworkType.Infrastructure.dwAuthentication));


	//Parse Cache options 
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = 0; //FAPI_CACHE_OPTION_CONNECT;

	DWORD dwCacheOpts,dwTimeCacheOpts,dwCacheRT;
	fxml.GetCredentialCache(&dwCacheOpts,&dwTimeCacheOpts,&dwCacheRT,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszFirstLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszSecondLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszThirdLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszFourthLoginPromptTime);

    fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = dwCacheOpts;
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwTimeCacheOpts = (FAPI_LOGIN_TIME_CACHE_OPTIONS)dwTimeCacheOpts;
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.TimeInterval.dwCacheRT = dwCacheRT;

	fapiProfile.NetworkType.Infrastructure.dwSecurityMode = (FAPI_WLAN_SECURITY_TYPE)fxml.GetSecurityType();
	AddLog(0,_T("NetworkType.Infrastructure.dwSecurityMode = %d"),fapiProfile.NetworkType.Infrastructure.dwSecurityMode);

	fapiProfile.dwEncryption = (FAPI_WLAN_ENCRYPTION_TYPE)fxml.GetEncryption();
	AddLog(0,_T("fapiProfile.dwEncryption = %d"),fapiProfile.dwEncryption);

	if(fapiProfile.NetworkType.Infrastructure.dwAuthentication == FAPI_LEAP) 
		fapiProfile.dwEncryption = FAPI_ENCRYPTION_104BIT;
	


	//Since struct version 6
	fapiProfile.EncryptionAlgorithm.AESPassphrase.dwAesAllowMixedMode = (FAPI_WLAN_AES_ALLOW_MIXED_MODE)fxml.GetAllowAESMixedMode();
	AddLog(0,_T("Allow mixed mode security = %d"),fapiProfile.EncryptionAlgorithm.AESPassphrase.dwAesAllowMixedMode);

	fapiProfile.NetworkType.Infrastructure.dwSecurityMode = GetSecurityMode(fapiProfile.NetworkType.Infrastructure.dwAuthentication,fapiProfile.dwEncryption);

	DWORD dwKeyIndex = 0;
	if(fxml.GetWEP128(&dwKeyIndex,
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[0],
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[1],
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[2],
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[3]))
	{

		fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.dwWEPKeyIndex = static_cast<FAPI_WLAN_WEP_KEY_INDEX>(dwKeyIndex);
	}




	dwKeyIndex = 0;
	if(fxml.GetWEP40(&dwKeyIndex,
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[0],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[1],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[2],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[3]))
	{

		fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.dwWEPKeyIndex = static_cast<FAPI_WLAN_WEP_KEY_INDEX>(dwKeyIndex);
	}


	if(fapiProfile.dwEncryption==FAPI_ENCRYPTION_TKIP) {
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.TKIPPassphrase.pszTKIPPassphrase);
	} else if( fapiProfile.dwEncryption == FAPI_ENCRYPTION_AES){
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.AESPassphrase.pszAESPassphrase);
	}

	TiXmlElement *pElmProf = fxml.GetRootElement();

	TiXmlElement *pUserCred = NULL; 
	pUserCred = fxml.GetElementSafe(pElmProf,"UserCredentials");		
	if(pUserCred) {
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszIdentity,"UserName",FAPI_MAX_USERNAME_LENGTH);
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszUserPwd,"Password",FAPI_MAX_PASSWORD_LENGTH);
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszDomain,"Domain",FAPI_MAX_DOMAINNAME_LENGTH);
	}

	TiXmlElement *pIEEE8021X = NULL; 
	pIEEE8021X = fxml.GetElementSafe(pElmProf,"IEEE8021X");		
	if(pIEEE8021X) {
		fxml.GetText(pIEEE8021X,fapiProfile.NetworkType.Infrastructure.CredentialSettings.IEEE8021X_CredSettings.psz802_1xDomain,"Domain",FAPI_MAX_DOMAINNAME_LENGTH);
		fxml.GetText(pIEEE8021X,fapiProfile.NetworkType.Infrastructure.CredentialSettings.IEEE8021X_CredSettings.psz802_1xUserIdentity ,"UserIdentity",FAPI_MAX_USERNAME_LENGTH);
	}

	TiXmlElement *pServerCert = NULL; 
	pServerCert = fxml.GetElementSafe(pElmProf,"ServerCert");		
	if(pServerCert) {
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.FileCertInstall.pszServerCertFName ,"Filename",FAPI_MAX_CERT_FNAME_LENGTH);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.FileCertInstall.pszServerCertPath ,"Path",FAPI_MAX_SERVER_CERT_PATH_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.LocalCertInstall.pszServerCertFName ,"LocalCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	pServerCert = fxml.GetElementSafe(pElmProf,"LocalUserCert");		
	if(pServerCert)
	{	
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.LocalCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	pServerCert = fxml.GetElementSafe(pElmProf,"RemoteUserCert");		
	if(pServerCert)
	{
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszServerName,"ServerName",FAPI_MAX_REMOTE_SERVER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemoteUserName,"UserName",FAPI_MAX_REMOTE_USER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemotePassword,"Password",FAPI_MAX_REMOTE_PASSWORD_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	return fapiProfile;

}



FAPI_PROFILE_7 ParseProfile7(CFusionXMLProfile &fxml)
{
	FAPI_PROFILE_7  fapiProfile = {0}; //for 2.55 and 2.57
	//ZeroMemory(&fapiProfile, sizeof(FAPI_PROFILE_6)); 

	fapiProfile.dwVersion = GetStructVersion();
	AddLog(3,_T("Detected Fusion Structure Ver = %d"),fapiProfile.dwVersion);

	//specify common properties for both Adhoc and Infrastructure
	fapiProfile.dwType = FAPI_PROFILE_TYPE;	

	//Default values
	fapiProfile.dwPowerIndex = FAPI_WLAN_POWERMODE_FAST_POWER_SAVE;
	fapiProfile.dwTxPower = FAPI_POWER_BSS_AUTO;					// Must use AUTO or PLUS for infrastructure
	fapiProfile.dwOpMode =  FAPI_NDIS802_11INFRASTRUCTURE ;			// infrastructure mode
	fapiProfile.NetworkType.Adhoc.dwChannel = 0;					// reset back to original	
	fapiProfile.dwIPAddressingMode = FAPI_ADDR_MODE_IPV4_DHCP;
	fapiProfile.dwEncryption = FAPI_ENCRYPTION_NONE ;
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_AUTH_NONE;


	fxml.SetProfileName(fapiProfile.pszName,sizeof(fapiProfile.pszName)/sizeof(TCHAR));
	AddLog(3,_T("Profile Name = %s"),fapiProfile.pszName);
	
	fapiProfile.dwOpMode = (FAPI_WLAN_NETWORK_TYPE) fxml.GetOpMode(); 
	fapiProfile.NetworkType.Adhoc.dwChannel = fxml.GetChannel();

	fxml.GetSSID(fapiProfile.pszSSID);
	fxml.GetCountry(fapiProfile.pszCountryCode);
	fapiProfile.dwPowerIndex = (FAPI_WLAN_POWER_MODE) fxml.GetPowerIndex();
	fapiProfile.dwTxPower = (FAPI_TRANSMIT_POWER_LEVEL) fxml.GetTxPower();


	fapiProfile.dwIPAddressingMode = (FAPI_NETWORK_ADDRESSING_MODE)fxml.GetIPAddressMode(); //Static or DHCP?

	fxml.GetIPv4Address(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Address);
	fxml.GetSubnet(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4SubnetMask);
	fxml.GetGateway(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Gateway1);
	fxml.GetDNS1(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS1);
	fxml.GetDNS2(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS2);
	fxml.GetWINS1(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS1);
	fxml.GetWINS2(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS2);

	fapiProfile.NetworkType.Infrastructure.CredentialSettings.dwCredentialFlags = fxml.GetCredentialMode();
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = (FAPI_WLAN_AUTHENTICATION_TYPE) fxml.GetAuthenticationMode();
	AddLog(0,_T("Auth Method %s"),GetAuthMethodName(fapiProfile.NetworkType.Infrastructure.dwAuthentication));


	//Parse Cache options 
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = 0; //FAPI_CACHE_OPTION_CONNECT;

	DWORD dwCacheOpts,dwTimeCacheOpts,dwCacheRT;
	fxml.GetCredentialCache(&dwCacheOpts,&dwTimeCacheOpts,&dwCacheRT,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszFirstLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszSecondLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszThirdLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszFourthLoginPromptTime);

    fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = dwCacheOpts;
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwTimeCacheOpts = (FAPI_LOGIN_TIME_CACHE_OPTIONS)dwTimeCacheOpts;
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.TimeInterval.dwCacheRT = dwCacheRT;

	fapiProfile.NetworkType.Infrastructure.dwSecurityMode = (FAPI_WLAN_SECURITY_TYPE)fxml.GetSecurityType();
	fapiProfile.dwEncryption = (FAPI_WLAN_ENCRYPTION_TYPE)fxml.GetEncryption();


	fapiProfile.dwAesAllowMixedMode = (FAPI_WLAN_AES_ALLOW_MIXED_MODE)fxml.GetAllowAESMixedMode();
	AddLog(0,_T("Allow mixed mode security = %d"),fapiProfile.dwAesAllowMixedMode);

	//Removed version 20 - on MC75A with Fusion 3.00.2.0.025R
	//Default to 104 bit WEP if LEAP being used (modified Version 1.17)
	//if((fapiProfile.NetworkType.Infrastructure.dwAuthentication == FAPI_LEAP) && (fapiProfile.dwEncryption == FAPI_ENCRYPTION_NONE)) 
	//	fapiProfile.dwEncryption = FAPI_ENCRYPTION_104BIT;


	fapiProfile.NetworkType.Infrastructure.dwSecurityMode = GetSecurityMode(fapiProfile.NetworkType.Infrastructure.dwAuthentication,fapiProfile.dwEncryption);

	DWORD dwKeyIndex = 0;
	fxml.GetWEP128(&dwKeyIndex,
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[0],
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[1],
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[2],
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[3]);

	fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.dwWEPKeyIndex = (FAPI_WLAN_WEP_KEY_INDEX)dwKeyIndex;


	dwKeyIndex = 0;
	fxml.GetWEP40(&dwKeyIndex,
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[0],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[1],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[2],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[3]);

	fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.dwWEPKeyIndex = (FAPI_WLAN_WEP_KEY_INDEX)dwKeyIndex;


	if(fapiProfile.dwEncryption == FAPI_ENCRYPTION_TKIP)
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.TKIPPassphrase.pszTKIPPassphrase);
	else if( fapiProfile.dwEncryption == FAPI_ENCRYPTION_AES)
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.AESPassphrase.pszAESPassphrase);

	
	TiXmlElement *pElmProf = fxml.GetRootElement();

	TiXmlElement *pUserCred = NULL; 
	pUserCred = fxml.GetElementSafe(pElmProf,"UserCredentials");		
	if(pUserCred)
	{
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszIdentity,"UserName",FAPI_MAX_USERNAME_LENGTH);
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszUserPwd,"Password",FAPI_MAX_PASSWORD_LENGTH);
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszDomain,"Domain",FAPI_MAX_DOMAINNAME_LENGTH);
	}

 	TiXmlElement *pIEEE8021X = NULL; 
	pIEEE8021X = fxml.GetElementSafe(pElmProf,"IEEE8021X");		
	if(pIEEE8021X)
	{
		fxml.GetText(pIEEE8021X,fapiProfile.NetworkType.Infrastructure.CredentialSettings.IEEE8021X_CredSettings.psz802_1xDomain,"Domain",FAPI_MAX_DOMAINNAME_LENGTH);
		fxml.GetText(pIEEE8021X,fapiProfile.NetworkType.Infrastructure.CredentialSettings.IEEE8021X_CredSettings.psz802_1xUserIdentity ,"UserIdentity",FAPI_MAX_USERNAME_LENGTH);
	}

	TiXmlElement *pServerCert = NULL; 
	pServerCert = fxml.GetElementSafe(pElmProf,"ServerCert");		
	if(pServerCert)
	{
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.FileCertInstall.pszServerCertFName ,"Filename",FAPI_MAX_CERT_FNAME_LENGTH);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.FileCertInstall.pszServerCertPath ,"Path",FAPI_MAX_SERVER_CERT_PATH_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.LocalCertInstall.pszServerCertFName ,"LocalCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

   	pServerCert = fxml.GetElementSafe(pElmProf,"LocalUserCert");		
	if(pServerCert)
	{	
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.LocalCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	pServerCert = fxml.GetElementSafe(pElmProf,"RemoteUserCert");		
	if(pServerCert)
	{
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszServerName,"ServerName",FAPI_MAX_REMOTE_SERVER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemoteUserName,"UserName",FAPI_MAX_REMOTE_USER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemotePassword,"Password",FAPI_MAX_REMOTE_PASSWORD_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}
	
	return fapiProfile;

}


FAPI_PROFILE_8 ParseProfile8(CFusionXMLProfile &fxml)
{
	FAPI_PROFILE_8  fapiProfile = {0}; 
	
	ZeroMemory(&fapiProfile, sizeof(FAPI_PROFILE_8)); 

	fapiProfile.dwVersion = GetStructVersion();
	AddLog(3,_T("Detected Fusion Structure Ver = %d"),fapiProfile.dwVersion);

	//specify common properties for both Adhoc and Infrastructure
	fapiProfile.dwType = FAPI_PROFILE_TYPE;	

	//Default values
	fapiProfile.dwPowerIndex = FAPI_WLAN_POWERMODE_FAST_POWER_SAVE;
	fapiProfile.dwTxPower = FAPI_POWER_BSS_AUTO;					// Must use AUTO or PLUS for infrastructure
	fapiProfile.dwOpMode =  FAPI_NDIS802_11INFRASTRUCTURE ;			// infrastructure mode
	fapiProfile.NetworkType.Adhoc.dwChannel = 0;					// reset back to original	
	fapiProfile.dwIPAddressingMode = FAPI_ADDR_MODE_IPV4_DHCP;
	fapiProfile.dwEncryption = FAPI_ENCRYPTION_NONE ;
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_AUTH_NONE;


	fxml.SetProfileName(fapiProfile.pszName,sizeof(fapiProfile.pszName)/sizeof(TCHAR));
	AddLog(3,_T("Profile Name = %s"),fapiProfile.pszName);
	
	fapiProfile.dwOpMode = (FAPI_WLAN_NETWORK_TYPE) fxml.GetOpMode(); 
	fapiProfile.NetworkType.Adhoc.dwChannel = fxml.GetChannel();

	fxml.GetSSID(fapiProfile.pszSSID);
	fxml.GetCountry(fapiProfile.pszCountryCode);
	fapiProfile.dwPowerIndex = (FAPI_WLAN_POWER_MODE) fxml.GetPowerIndex();
	fapiProfile.dwTxPower = (FAPI_TRANSMIT_POWER_LEVEL) fxml.GetTxPower();


	fapiProfile.dwIPAddressingMode = (FAPI_NETWORK_ADDRESSING_MODE)fxml.GetIPAddressMode(); //Static or DHCP?

	fxml.GetIPv4Address(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Address);
	fxml.GetSubnet(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4SubnetMask);
	fxml.GetGateway(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Gateway1);
	fxml.GetDNS1(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS1);
	fxml.GetDNS2(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS2);
	fxml.GetWINS1(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS1);
	fxml.GetWINS2(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS2);

	fapiProfile.NetworkType.Infrastructure.CredentialSettings.dwCredentialFlags = fxml.GetCredentialMode();
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = (FAPI_WLAN_AUTHENTICATION_TYPE) fxml.GetAuthenticationMode();
	AddLog(0,_T("Auth Method %s"),GetAuthMethodName(fapiProfile.NetworkType.Infrastructure.dwAuthentication));


	//Parse Cache options 
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = 0; //FAPI_CACHE_OPTION_CONNECT;

	DWORD dwCacheOpts,dwTimeCacheOpts,dwCacheRT;
	fxml.GetCredentialCache(&dwCacheOpts,&dwTimeCacheOpts,&dwCacheRT,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszFirstLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszSecondLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszThirdLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszFourthLoginPromptTime);

    fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = dwCacheOpts;
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwTimeCacheOpts = (FAPI_LOGIN_TIME_CACHE_OPTIONS)dwTimeCacheOpts;
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.TimeInterval.dwCacheRT = dwCacheRT;

	fapiProfile.NetworkType.Infrastructure.dwSecurityMode = (FAPI_WLAN_SECURITY_TYPE)fxml.GetSecurityType();
	fapiProfile.dwEncryption = (FAPI_WLAN_ENCRYPTION_TYPE)fxml.GetEncryption();


	fapiProfile.dwAllowMixedMode = (FAPI_WLAN_ALLOW_MIXED_MODE)fxml.GetAllowAESMixedMode();
	AddLog(0,_T("Allow mixed mode security = %d"),fapiProfile.dwAllowMixedMode);
	

	//Default to 104 bit WEP if LEAP being used (modified Version 1.17)
	if((fapiProfile.NetworkType.Infrastructure.dwAuthentication == FAPI_LEAP) && (fapiProfile.dwEncryption == FAPI_ENCRYPTION_NONE)) 
		fapiProfile.dwEncryption = FAPI_ENCRYPTION_104BIT;


	fapiProfile.NetworkType.Infrastructure.dwSecurityMode = GetSecurityMode(fapiProfile.NetworkType.Infrastructure.dwAuthentication,fapiProfile.dwEncryption);


	DWORD dwKeyIndex = 0;
	fxml.GetWEP128(&dwKeyIndex,
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[0],
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[1],
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[2],
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[3]);

	fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.dwWEPKeyIndex = (FAPI_WLAN_WEP_KEY_INDEX)dwKeyIndex;


	dwKeyIndex = 0;
	fxml.GetWEP40(&dwKeyIndex,
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[0],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[1],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[2],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[3]);

	fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.dwWEPKeyIndex = (FAPI_WLAN_WEP_KEY_INDEX)dwKeyIndex;


	if(fapiProfile.dwEncryption == FAPI_ENCRYPTION_TKIP)
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.TKIPPassphrase.pszTKIPPassphrase);
	else if( fapiProfile.dwEncryption == FAPI_ENCRYPTION_AES)
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.AESPassphrase.pszAESPassphrase);


	
	TiXmlElement *pElmProf = fxml.GetRootElement();

	TiXmlElement *pUserCred = NULL; 
	pUserCred = fxml.GetElementSafe(pElmProf,"UserCredentials");		
	if(pUserCred)
	{
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszIdentity,"UserName",FAPI_MAX_USERNAME_LENGTH);
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszUserPwd,"Password",FAPI_MAX_PASSWORD_LENGTH);
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszDomain,"Domain",FAPI_MAX_DOMAINNAME_LENGTH);
	}

	TiXmlElement *pIEEE8021X = NULL; 
	pIEEE8021X = fxml.GetElementSafe(pElmProf,"IEEE8021X");		
	if(pIEEE8021X)
	{
		fxml.GetText(pIEEE8021X,fapiProfile.NetworkType.Infrastructure.CredentialSettings.IEEE8021X_CredSettings.psz802_1xDomain,"Domain",FAPI_MAX_DOMAINNAME_LENGTH);
		fxml.GetText(pIEEE8021X,fapiProfile.NetworkType.Infrastructure.CredentialSettings.IEEE8021X_CredSettings.psz802_1xUserIdentity ,"UserIdentity",FAPI_MAX_USERNAME_LENGTH);
	}

	TiXmlElement *pServerCert = NULL; 
	pServerCert = fxml.GetElementSafe(pElmProf,"ServerCert");		
	if(pServerCert)
	{
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.FileCertInstall.pszServerCertFName ,"Filename",FAPI_MAX_CERT_FNAME_LENGTH);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.FileCertInstall.pszServerCertPath ,"Path",FAPI_MAX_SERVER_CERT_PATH_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.LocalCertInstall.pszServerCertFName ,"LocalCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	pServerCert = fxml.GetElementSafe(pElmProf,"LocalUserCert");		
	if(pServerCert)
	{	
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.LocalCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	pServerCert = fxml.GetElementSafe(pElmProf,"RemoteUserCert");		
	if(pServerCert)
	{
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszServerName,"ServerName",FAPI_MAX_REMOTE_SERVER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemoteUserName,"UserName",FAPI_MAX_REMOTE_USER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemotePassword,"Password",FAPI_MAX_REMOTE_PASSWORD_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}
	
	return fapiProfile;

}


FAPI_PROFILE_9 ParseProfile9(CFusionXMLProfile &fxml)
{
	FAPI_PROFILE_9  fapiProfile = {0}; 
	
	ZeroMemory(&fapiProfile, sizeof(FAPI_PROFILE_9)); 

	fapiProfile.dwVersion = GetStructVersion();
	AddLog(3,_T("Detected Fusion Structure Ver = %d"),fapiProfile.dwVersion);

	//specify common properties for both Adhoc and Infrastructure
	fapiProfile.dwType = FAPI_PROFILE_TYPE;	

	//Default values
	fapiProfile.dwPowerIndex = FAPI_WLAN_POWERMODE_FAST_POWER_SAVE;
	fapiProfile.dwTxPower = FAPI_POWER_BSS_AUTO;					// Must use AUTO or PLUS for infrastructure
	fapiProfile.dwOpMode =  FAPI_NDIS802_11INFRASTRUCTURE ;			// infrastructure mode
	fapiProfile.NetworkType.Adhoc.dwChannel = 0;					// reset back to original	
	fapiProfile.dwIPAddressingMode = FAPI_ADDR_MODE_IPV4_DHCP;
	fapiProfile.dwEncryption = FAPI_ENCRYPTION_NONE ;
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_AUTH_NONE;


	fxml.SetProfileName(fapiProfile.pszName,sizeof(fapiProfile.pszName)/sizeof(TCHAR));
	AddLog(3,_T("Profile Name = %s"),fapiProfile.pszName);
	
	fapiProfile.dwOpMode = (FAPI_WLAN_NETWORK_TYPE) fxml.GetOpMode(); 
	fapiProfile.NetworkType.Adhoc.dwChannel = fxml.GetChannel();

	fxml.GetSSID(fapiProfile.pszSSID);
	fxml.GetCountry(fapiProfile.pszCountryCode);
	fapiProfile.dwPowerIndex = (FAPI_WLAN_POWER_MODE) fxml.GetPowerIndex();
	fapiProfile.dwTxPower = (FAPI_TRANSMIT_POWER_LEVEL) fxml.GetTxPower();


	fapiProfile.dwIPAddressingMode = (FAPI_NETWORK_ADDRESSING_MODE)fxml.GetIPAddressMode(); //Static or DHCP?

	fxml.GetIPv4Address(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Address);
	fxml.GetSubnet(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4SubnetMask);
	fxml.GetGateway(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Gateway1);
	fxml.GetDNS1(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS1);
	fxml.GetDNS2(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS2);
	fxml.GetWINS1(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS1);
	fxml.GetWINS2(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS2);

	fapiProfile.NetworkType.Infrastructure.CredentialSettings.dwCredentialFlags = fxml.GetCredentialMode();
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = (FAPI_WLAN_AUTHENTICATION_TYPE) fxml.GetAuthenticationMode();
	AddLog(0,_T("Auth Method %s"),GetAuthMethodName(fapiProfile.NetworkType.Infrastructure.dwAuthentication));


	//Parse Cache options 
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = 0; //FAPI_CACHE_OPTION_CONNECT;

	DWORD dwCacheOpts,dwTimeCacheOpts,dwCacheRT;
	fxml.GetCredentialCache(&dwCacheOpts,&dwTimeCacheOpts,&dwCacheRT,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszFirstLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszSecondLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszThirdLoginPromptTime,
			fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.AbsoluteTime.pszFourthLoginPromptTime);

    fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = dwCacheOpts;
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwTimeCacheOpts = (FAPI_LOGIN_TIME_CACHE_OPTIONS)dwTimeCacheOpts;
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.TimePromptOption.TimeInterval.dwCacheRT = dwCacheRT;

	fapiProfile.NetworkType.Infrastructure.dwSecurityMode = (FAPI_WLAN_SECURITY_TYPE)fxml.GetSecurityType();
	fapiProfile.dwEncryption = (FAPI_WLAN_ENCRYPTION_TYPE)fxml.GetEncryption();


	fapiProfile.dwAllowMixedMode = (FAPI_WLAN_ALLOW_MIXED_MODE)fxml.GetAllowAESMixedMode();
	AddLog(0,_T("Allow mixed mode security = %d"),fapiProfile.dwAllowMixedMode);

	//Default to 104 bit WEP if LEAP being used (modified Version 1.17)
	if((fapiProfile.NetworkType.Infrastructure.dwAuthentication == FAPI_LEAP) && (fapiProfile.dwEncryption == FAPI_ENCRYPTION_NONE)) 
		fapiProfile.dwEncryption = FAPI_ENCRYPTION_104BIT;

	fapiProfile.NetworkType.Infrastructure.dwSecurityMode = GetSecurityMode(fapiProfile.NetworkType.Infrastructure.dwAuthentication,fapiProfile.dwEncryption);



	DWORD dwKeyIndex = 0;
	fxml.GetWEP128(&dwKeyIndex,
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[0],
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[1],
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[2],
				fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.pszWEPKey[3]);

	fapiProfile.EncryptionAlgorithm.WEP104BitHexKey.dwWEPKeyIndex = (FAPI_WLAN_WEP_KEY_INDEX)dwKeyIndex;


	dwKeyIndex = 0;
	fxml.GetWEP40(&dwKeyIndex,
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[0],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[1],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[2],
				fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.pszWEPKey[3]);

	fapiProfile.EncryptionAlgorithm.WEP40BitHexKey.dwWEPKeyIndex = (FAPI_WLAN_WEP_KEY_INDEX)dwKeyIndex;


	if(fapiProfile.dwEncryption == FAPI_ENCRYPTION_TKIP)
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.TKIPPassphrase.pszTKIPPassphrase);
	else if( fapiProfile.dwEncryption == FAPI_ENCRYPTION_AES)
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.AESPassphrase.pszAESPassphrase);


	
	TiXmlElement *pElmProf = fxml.GetRootElement();

	TiXmlElement *pUserCred = NULL; 
	pUserCred = fxml.GetElementSafe(pElmProf,"UserCredentials");		
	if(pUserCred) {
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszIdentity,"UserName",FAPI_MAX_USERNAME_LENGTH);
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszUserPwd,"Password",FAPI_MAX_PASSWORD_LENGTH);
		fxml.GetText(pUserCred,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszDomain,"Domain",FAPI_MAX_DOMAINNAME_LENGTH);
	}

	TiXmlElement *pIEEE8021X = NULL; 
	pIEEE8021X = fxml.GetElementSafe(pElmProf,"IEEE8021X");		
	if(pIEEE8021X) {
		fxml.GetText(pIEEE8021X,fapiProfile.NetworkType.Infrastructure.CredentialSettings.IEEE8021X_CredSettings.psz802_1xDomain,"Domain",FAPI_MAX_DOMAINNAME_LENGTH);
		fxml.GetText(pIEEE8021X,fapiProfile.NetworkType.Infrastructure.CredentialSettings.IEEE8021X_CredSettings.psz802_1xUserIdentity ,"UserIdentity",FAPI_MAX_USERNAME_LENGTH);
	}

	TiXmlElement *pServerCert = NULL; 
	pServerCert = fxml.GetElementSafe(pElmProf,"ServerCert");		
	if(pServerCert) {
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.FileCertInstall.pszServerCertFName ,"Filename",FAPI_MAX_CERT_FNAME_LENGTH);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.FileCertInstall.pszServerCertPath ,"Path",FAPI_MAX_SERVER_CERT_PATH_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.LocalCertInstall.pszServerCertFName ,"LocalCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	pServerCert = fxml.GetElementSafe(pElmProf,"LocalUserCert");		
	if(pServerCert) {
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.LocalCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	pServerCert = fxml.GetElementSafe(pElmProf,"RemoteUserCert");		
	if(pServerCert) {
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszServerName,"ServerName",FAPI_MAX_REMOTE_SERVER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemoteUserName,"UserName",FAPI_MAX_REMOTE_USER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemotePassword,"Password",FAPI_MAX_REMOTE_PASSWORD_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}
	
	return fapiProfile;

}

/*
Experimental universal function 

*/

FAPI_PROFILE_9 UniversalProfile(CFusionXMLProfile &fxml)
{
	FAPI_PROFILE_9  fapiProfile = {0}; 
	
	ZeroMemory(&fapiProfile, sizeof(FAPI_PROFILE_9)); 

	fapiProfile.dwVersion = GetStructVersion();
	AddLog(3,_T("Detected Fusion Structure Ver = %d"),fapiProfile.dwVersion);

	//specify common properties for both Adhoc and Infrastructure
	fapiProfile.dwType = FAPI_PROFILE_TYPE;	

	//Default values
	fapiProfile.dwPowerIndex = FAPI_WLAN_POWERMODE_FAST_POWER_SAVE;
	fapiProfile.dwTxPower = FAPI_POWER_BSS_AUTO;					// Must use AUTO or PLUS for infrastructure
	fapiProfile.dwOpMode =  FAPI_NDIS802_11INFRASTRUCTURE ;			// infrastructure mode
	fapiProfile.NetworkType.Adhoc.dwChannel = 0;					// reset back to original	
	fapiProfile.dwIPAddressingMode = FAPI_ADDR_MODE_IPV4_DHCP;
	fapiProfile.dwEncryption = FAPI_ENCRYPTION_NONE ;
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_AUTH_NONE;
	_tcscpy(fapiProfile.pszCountryCode,_T("US"));


	_tcscpy(fapiProfile.pszName,_T("[My Profile 01234567890123456789]"));
	
	fapiProfile.dwOpMode = FAPI_NDIS802_11INFRASTRUCTURE; 
	fapiProfile.NetworkType.Adhoc.dwChannel = 99;

	_tcscpy(fapiProfile.pszSSID,_T("[My ESSID 01234567890123456789]"));
	_tcscpy(fapiProfile.pszCountryCode,_T("SE"));
	fapiProfile.dwPowerIndex = FAPI_WLAN_POWERMODE_CAM;
	fapiProfile.dwTxPower = FAPI_POWER_BSS_PLUS;
	fapiProfile.dwEncryption = FAPI_ENCRYPTION_AES;
	fapiProfile.dwAllowMixedMode = (FAPI_WLAN_ALLOW_MIXED_MODE)fxml.GetAllowAESMixedMode();

	if(fapiProfile.NetworkType.Infrastructure.dwAuthentication == FAPI_LEAP) 
		fapiProfile.dwEncryption = FAPI_ENCRYPTION_104BIT;

	fapiProfile.NetworkType.Infrastructure.dwSecurityMode = (FAPI_WLAN_SECURITY_TYPE)fxml.GetSecurityType();
	//Redudancy & autodetection of security type
	fapiProfile.NetworkType.Infrastructure.dwSecurityMode = GetSecurityMode(fapiProfile.NetworkType.Infrastructure.dwAuthentication,fapiProfile.dwEncryption);

	fapiProfile.dwIPAddressingMode = FAPI_ADDR_MODE_IPV4_STATIC;

	_tcscpy(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Address,_T("192.168.1.250"));
	_tcscpy(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4SubnetMask,_T("255.255.255.0"));
	_tcscpy(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Gateway1,_T("192.168.1.1"));
	_tcscpy(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS1,_T("192.168.1.1"));
	_tcscpy(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS2,_T("192.168.1.2"));
	_tcscpy(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS1,_T("192.168.2.1"));
	_tcscpy(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS2,_T("192.168.2.2"));
	return fapiProfile;
}




int processData(TiXmlDocument *pDoc)
{
	TiXmlHandle hDoc(pDoc);

	TiXmlElement *pRootElm;
	TiXmlNode	*pNode=NULL;

	pRootElm = hDoc.FirstChildElement().Element();
	if(!pRootElm)
	{
		AddLog(1,_T("Error finding root element &lt;FusionConfig&gt; in xml file!\n"));
		return ERR_TAG_FUSIONCONFIG;
	}

	CFusionXMLProfile fxml(pRootElm);

	//Do initial config
	DWORD dwDummyValue=0;
	if(fxml.GetInteger(pRootElm,&dwDummyValue,"SetLog")==0)  
		if(dwDummyValue==0)
		{
			ClearLog();
			bLog = FALSE;
		}

	dwDummyValue = 0;
	if(fxml.GetInteger(pRootElm,&dwDummyValue,"Connect")==0)  
		if(dwDummyValue==1)
			bConnect = TRUE;
	
	dwDummyValue = 0;
	if(fxml.GetInteger(pRootElm,&dwDummyValue,"Export")==0)  
		if(dwDummyValue==1)
			bExport = TRUE;

	memset(tcszExportFilename,0,sizeof(tcszExportFilename));
	fxml.GetText(pRootElm,tcszExportFilename,"ExportFileName",260);
	

	DWORD dwVersion = GetStructVersion();
	switch(dwVersion)
	{
		default:
		case FAPI_PROFILE_2_VERSION:
			if(AddFusionProfile((PVOID)&ParseProfile2(fxml)))
				return SUCCESSFULL;
			break;
		case FAPI_PROFILE_3_VERSION:
			if(AddFusionProfile((PVOID)&ParseProfile3(fxml)))
				return SUCCESSFULL;
			break;
		case FAPI_PROFILE_4_VERSION:
			if(AddFusionProfile((PVOID)&ParseProfile4(fxml)))
				return SUCCESSFULL;
			break;
		case FAPI_PROFILE_5_VERSION:
			if(AddFusionProfile((PVOID)&ParseProfile5(fxml)))
				return SUCCESSFULL;
			break;
		case FAPI_PROFILE_6_VERSION:			
			if(AddFusionProfile((PVOID)&ParseProfile6(fxml)))
				return SUCCESSFULL;
			break;
		case FAPI_PROFILE_7_VERSION:
			if(AddFusionProfile((PVOID)&ParseProfile7(fxml)))
				return SUCCESSFULL;
			break;
		case FAPI_PROFILE_8_VERSION:
			if(AddFusionProfile((PVOID)&ParseProfile8(fxml)))
				return SUCCESSFULL;
			break;
		case FAPI_PROFILE_9_VERSION:
			if(AddFusionProfile((PVOID)&ParseProfile9(fxml)))
				return SUCCESSFULL;
			break;
	}
	return ERR_ADDING_PROFILE;
}

/******************************************************************************
* SYNOPSIS:     DWORD FusionSampleLoadAPILibrary()
*
* DESCRIPTION:  Dynamically loads fusion public API dll and get required 
*               function pointers
*
* PARAMETERS:   None
*
* RETURN VALUE: FUSION_SAMP_ERROR_SUCCESS or string tabel error ID
*******************************************************************************/
DWORD FusionSampleLoadAPILibrary()
{
	if(g_hInstFusionDLL==0)
	{
	
		HINSTANCE hInst = LoadLibrary(L"FusionPublicAPI.DLL");
		g_hInstFusionDLL = (DWORD)hInst;
		if (!g_hInstFusionDLL)
		{
			return -1;
		}

		
		lpfn_OpenFusionAPI		= (LPFN_OPEN_FUSION_API)	GetProcAddress((HMODULE)g_hInstFusionDLL, _T("OpenFusionAPI"));
		lpfn_CloseFusionAPI		= (LPFN_CLOSE_FUSION_API)	GetProcAddress((HMODULE)g_hInstFusionDLL, _T("CloseFusionAPI"));
		lpfn_CommandFusionAPI	= (LPFN_COMMAND_FUSION_API)	GetProcAddress((HMODULE)g_hInstFusionDLL, _T("CommandFusionAPI"));

		if( (!lpfn_OpenFusionAPI) || (!lpfn_CloseFusionAPI) || (!lpfn_CommandFusionAPI)  )
		{
			FreeLibrary((HMODULE)g_hInstFusionDLL);
			g_hInstFusionDLL = 0;
			lpfn_OpenFusionAPI = NULL;
			lpfn_CloseFusionAPI = NULL;
			lpfn_CommandFusionAPI = NULL;
			return -2;
		}
	}
	
	return 0;

}

/******************************************************************************
* SYNOPSIS:     DWORD FusionFindFirstWLANAdapter()
*
* DESCRIPTION:  Finds the first WLAN adapter
*
* PARAMETERS:   None.
*
* RETURN VALUE: Adpter handle or 0. 
*******************************************************************************/
DWORD FusionFindFirstWLANAdapter()
{
	DWORD   dwAdapterBufLen, dwResult,dwReturn = 0;
	PBYTE   pFusionData = NULL;
	PFAPI_AdapterIDHeader pfapiAdapterHeader=NULL;
	PFAPI_AdapterLink  pfapiAdapterLink = NULL;
		

	dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
		                              ADAPTER_WLAN_GET_BUFFER_SIZE, 
									  NULL, 0, 
									  &dwAdapterBufLen, sizeof(DWORD), 
									  NULL);
	if( dwResult == FAPI_SUCCESS )
	{
		pFusionData = (PBYTE)calloc( 1, dwAdapterBufLen );
		if( pFusionData != NULL)
		{
			dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
				                              ADAPTER_WLAN_GET_ENUM_DATA, 
											  NULL, 0, 
											  pFusionData, dwAdapterBufLen, 
											  NULL);
			if( dwResult == FAPI_SUCCESS )
			{
				pfapiAdapterHeader  =  (PFAPI_AdapterIDHeader)pFusionData;
				if( pfapiAdapterHeader -> numAdapters)
				{
					pfapiAdapterLink =  (PFAPI_AdapterLink) ( pFusionData + sizeof( FAPI_AdapterIDHeader  )  );
					dwReturn = pfapiAdapterLink->Pointer.pWLANAdapterID->dwAdapterHandle;
				}
			}	
			free( pFusionData );			
		}
	}
	return dwReturn;
}

DWORD DeleteFusionProfile(TCHAR *pszGUID)
{
	DWORD dwResult;
	dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
	                              DELETE_WLAN_PROFILE, 
								  pszGUID,FAPI_MAX_GUID_STRING_LENGTH*2, 
								  NULL, 0, 
								  NULL);
	

	if(dwResult==FAPI_SUCCESS)
		AddLog(0,_T("Successfully deleted profile %s"),pszGUID);
	else
	{
		FusionSampleDisplayLastError();
		AddLog(0,_T("Error code %d , Unsuccessfully deleted profile %s"),dwResult,pszGUID);
	
	}

	return dwResult;
}


DWORD EnemurateAndDeleteProfiles()
{
	DWORD   dwBufLen, dwResult,dwReturn = 0;
	PBYTE   pFusionData = NULL;
	PBYTE	pNextProfile = NULL;
	PFAPI_ProfileHeader	pfapiProfileheader = NULL;
	PFAPI_ProfileLink	pfapiProfileLink = NULL;
	PFAPI_WLANProfile	pfapiWLANProfile = NULL;

	dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
									  ENUMERATE_PROFILES_WLAN_GET_BUFFER_SIZE, 
									  NULL, 0, 
									  &dwBufLen, sizeof(DWORD), 
									  NULL);

	if( dwResult == FAPI_SUCCESS )
	{
		pFusionData = (PBYTE)calloc( 1, dwBufLen );
		if( pFusionData != NULL)
		{
			dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
				                              ENUMERATE_PROFILES_WLAN_GET_PROFILES_DATA, 
											  NULL, 0, 
											  pFusionData, dwBufLen, 
											  NULL);
			if( dwResult == FAPI_SUCCESS )
			{
				pfapiProfileheader  =  (PFAPI_ProfileHeader)pFusionData;
								
				if(pfapiProfileheader->numProfiles > FAPI_MAX_WLAN_NUM_PROFILES)
						pfapiProfileheader->numProfiles = FAPI_MAX_WLAN_NUM_PROFILES;

				pfapiProfileLink =  (PFAPI_ProfileLink) ( pFusionData + sizeof( FAPI_ProfileHeader  )  );

				for(int i=0; i<(int)pfapiProfileheader->numProfiles; i++, pfapiProfileLink++)			
				{
					DeleteFusionProfile(pfapiProfileLink->Pointer.pWLANProfile->pszProfileID);
					AddLog(0,_T("Profile enum %s"),pfapiProfileLink->Pointer.pWLANProfile->pszProfileID);			
				}
				
			}	
			free( pFusionData );			
		}
	}
	return dwReturn;
}


/******************************************************************************
* SYNOPSIS:     DWORD FusionSampleOpenAPILibrary()
*
* DESCRIPTION:  Open Fusion Public API library. 
*
* PARAMETERS:   None
*
* RETURN VALUE: FUSION_SAMP_ERROR_SUCCESS or string tabel error ID
*******************************************************************************/
DWORD FusionSampleOpenAPILibrary()
{
	if( lpfn_OpenFusionAPI(&g_hInstFusionDLL,COMMAND_MODE ,L"FusionXML") != FAPI_SUCCESS )	
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

/******************************************************************************
* SYNOPSIS:     void  FusionSampleCloseAPILibrary()
*
* DESCRIPTION:  Close Fusion Public API library. 
*
* PARAMETERS:   None
*
* RETURN VALUE: None
*******************************************************************************/
void  FusionSampleCloseAPILibrary()
{
	if(g_hInstFusionDLL!=NULL)
		lpfn_CloseFusionAPI(g_hInstFusionDLL);
	return;
}

/******************************************************************************
* SYNOPSIS:     void FusionSampleUnloadAPILibrary()
*
* DESCRIPTION:  Unload Fusion Public API dll
*
* PARAMETERS:   None
*
* RETURN VALUE: None
*******************************************************************************/
void FusionSampleUnloadAPILibrary()
{
	if(g_hInstFusionDLL)
	{
		FreeLibrary((HMODULE)g_hInstFusionDLL);
		g_hInstFusionDLL = 0;
		lpfn_OpenFusionAPI = NULL;
		lpfn_CloseFusionAPI = NULL;
		lpfn_CommandFusionAPI = NULL;
		
	}
}


/******************************************************************************
* SYNOPSIS:     void  FusionSampleDisplayLastError(HWND hWnd, PTCHAR pszMsgTitle)
*
* DESCRIPTION:  Display the last error given by  fusion public API 
*
* PARAMETERS:   hWnd - Parent window
*               pszMsgTitle - Title of the message
*
* RETURN VALUE: None. Message box is displayed. 
*
* NOTES:        Displayed message may not be meaningful if Fusion functions are 
*               called from multiple threads
*******************************************************************************/
void  FusionSampleDisplayLastError()
{
	TCHAR szLastError[FAPI_ERROR_TEXT_LEN / sizeof(TCHAR)];
	
	lpfn_CommandFusionAPI( g_hInstFusionDLL, 
		                   ERROR_INFO_GET_LAST_ERROR, 
						   NULL, 0,
						   szLastError, FAPI_ERROR_TEXT_LEN, 
						   NULL);
	
	AddLog(1,_T("%s"),szLastError);
}



/******************************************************************************
* SYNOPSIS:     void FusionSampleGetWLANVersions( LPFUSION_SAMP_VERSION_LIST pVersionList)
*
* DESCRIPTION:  Get the fusion component version list
*
* PARAMETERS:   pVersionList - buffer to receive component versions
*
* RETURN VALUE: None. Parameter pVersionList is updated with the component versions.
*******************************************************************************/
void FusionSampleGetWLANVersions( LPFUSION_SAMP_VERSION_LIST pVersionList)
{
	DWORD dwResult,dwVersionBufLen;
	PBYTE pFusionData;
	PFAPI_FusionVersionInfo pfapiVerInfo;
	int i;


	dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
		                              GET_FUSION_VERSION_BUFFER_SIZE, 
									  NULL, 0, 
									  &dwVersionBufLen, sizeof(DWORD), 
									  NULL);
	
	if( dwResult == FAPI_SUCCESS ) {
		pFusionData = (PBYTE)calloc( 1, dwVersionBufLen );
		if( pFusionData != NULL) {
			dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
				                              GET_FUSION_VERSION_DATA, 
											  NULL, 0, 
											  pFusionData, dwVersionBufLen, 
											  NULL);
			if( dwResult == FAPI_SUCCESS ) {
				pVersionList->dwVersionCount =  ( (PFAPI_FusionVersionHeader)pFusionData ) -> dwNumVersionInfo;
				pfapiVerInfo =  (PFAPI_FusionVersionInfo) ( pFusionData + sizeof( FAPI_FusionVersionHeader  )  );
				for(i=0; i<(int)pVersionList->dwVersionCount; i++, pfapiVerInfo++) {
					_tcscpy(pVersionList->fapiVersionList[i].pszFriendlyCompName, pfapiVerInfo -> pszFriendlyCompName);
					_tcscpy(pVersionList->fapiVersionList[i].pszVersionStr, pfapiVerInfo -> pszVersionStr);
						
					if(i==0)
					 _tcscpy(g_pszFusionVersionStr, pfapiVerInfo -> pszVersionStr);

					AddLog(0,_T("%s %s"),pVersionList->fapiVersionList[i].pszFriendlyCompName,pVersionList->fapiVersionList[i].pszVersionStr);
				}
			}
			free( pFusionData );
		}
	}


	
}

BOOL GetFusionVersion()
{
	FusionSampleGetWLANVersions( &VersionList);
	return TRUE;
}

BOOL ConnectToProfile(TCHAR *pszProfileID)
{
	DWORD dwResult;
	FAPI_SelectAndConnectParams_1 selNConn;
	memset (&selNConn, 0, sizeof (FAPI_SelectAndConnectParams_1));

	selNConn.dwVersion = FAPI_SELECT_AND_CONNECT_VERSION;
	selNConn.dwType = FAPI_SELECT_AND_CONNECT_TYPE;
	selNConn.bPersistent = TRUE;					//Similar to turning off profile roaming.

	memcpy (selNConn.pszProfileID,pszProfileID,FAPI_MAX_GUID_STRING_LENGTH * sizeof(TCHAR)); 
	dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, SELECT_AND_CONNECT_WLAN_PROFILE, &selNConn,sizeof (FAPI_SelectAndConnectParams), NULL, 0 ,NULL);
	if(dwResult != FAPI_SUCCESS) {
		FusionSampleDisplayLastError();
		AddLog(1,_T("\nError connecting to profile!\n"));
		return FALSE;
	} else {
		AddLog(1,_T("\nConnecting to profile successed!\n"));
		return TRUE;
	}
}


BOOL AddFusionProfile(PVOID pProfile)
{
	DWORD         dwResult;
	FAPI_AddedWLANProfileParams  fapiAddedWLANProfileParams;
	dwResult = FAPI_SUCCESS;
	memset(&fapiAddedWLANProfileParams, 0x0, sizeof(fapiAddedWLANProfileParams));

	DWORD structSize = sizeof(FAPI_PROFILE_2);
	FAPI_PROFILE_2 *p = (FAPI_PROFILE_2 *)pProfile;
#ifdef _DEBUG
	//for debugging purpose
	FAPI_PROFILE_3 *p3 = (FAPI_PROFILE_3 *)pProfile;
	FAPI_PROFILE_4 *p4 = (FAPI_PROFILE_4 *)pProfile; 
	FAPI_PROFILE_6 *p6 = (FAPI_PROFILE_6 *)pProfile; 
	FAPI_PROFILE_7 *p7 = (FAPI_PROFILE_7 *)pProfile; 
	FAPI_PROFILE_8 *p8 = (FAPI_PROFILE_8 *)pProfile; 
#endif
	
	switch(p->dwVersion)
	{
		case  FAPI_PROFILE_9_VERSION: structSize =  sizeof(FAPI_PROFILE_9); break;
		case  FAPI_PROFILE_8_VERSION: structSize =  sizeof(FAPI_PROFILE_8); break;
		case  FAPI_PROFILE_7_VERSION: structSize =  sizeof(FAPI_PROFILE_7); break;
		case  FAPI_PROFILE_6_VERSION: structSize =  sizeof(FAPI_PROFILE_6); break;
		case  FAPI_PROFILE_5_VERSION: structSize =  sizeof(FAPI_PROFILE_5); break;
		case  FAPI_PROFILE_4_VERSION: structSize =  sizeof(FAPI_PROFILE_4); break;
		case  FAPI_PROFILE_3_VERSION: structSize =  sizeof(FAPI_PROFILE_3); break;
		default:
		case  FAPI_PROFILE_2_VERSION: structSize =  sizeof(FAPI_PROFILE_2); break;
		
	}

	dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
										  ADD_WLAN_PROFILE, 
										  pProfile,structSize,  
										  &fapiAddedWLANProfileParams, sizeof(fapiAddedWLANProfileParams), 
										  NULL);

	if(dwResult != FAPI_SUCCESS) {
		FusionSampleDisplayLastError();
		AddLog(1,_T("\nError adding profile!\n"));
		return FALSE;
	} else {
		AddLog(0,_T("Added profile %s successfully!\n"),fapiAddedWLANProfileParams.pszName);
		AddLog(0,_T("Profile ID %s\n"),fapiAddedWLANProfileParams.pszProfileID);

		if(bConnect) {
			ConnectToProfile(fapiAddedWLANProfileParams.pszProfileID);
		}
		if(bExport) {
			ExportProfile( fapiAddedWLANProfileParams.pszProfileID);
		}
		return TRUE;
	}
		
}


 void InitializeFusion()
{
	int nResult;
	
	AddLog(0,_T("Trying to load Fusion API"));
	nResult =  FusionSampleLoadAPILibrary();
	if( nResult == 0 ) {
		AddLog(0,_T("Trying to open Fusion API"));
		nResult =  FusionSampleOpenAPILibrary();
	}else {
		AddLog(1,_T("Error loading Fusion API!"));
	}

	AddLog(0,_T("Initialize of Fusion API DONE!"));

}

 void DeinitializeFusion()
{
	AddLog(0,_T("Unloading Fusion API!"));
	FusionSampleCloseAPILibrary();  
	FusionSampleUnloadAPILibrary();
}


/************************************************

	GetMAC(...)

	This function will only return successfully 
	if the adpater is powered.

*************************************************/
FUSIONXML_API int GetMAC( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{

	AddLog(0,_T("GetMAC function was called!"));

	DWORD         dwResult;
	DWORD hAdapter = FusionFindFirstWLANAdapter();
	FAPI_AdapterInfo fapiAdapterInf;


	if(hAdapter==0) {
		AddLog(1,_T("Couldn't retrieve Adapter handle!"));
		return -1;
	}
	dwResult = FAPI_SUCCESS;
	
	
	dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
										  ADAPTER_INFO_WLAN, 
										  &hAdapter, sizeof(DWORD), 
										  &fapiAdapterInf, sizeof(FAPI_AdapterInfo), 
										  NULL);

	if(dwResult != FAPI_SUCCESS) {
		FusionSampleDisplayLastError();
		AddLog(1,_T("\nError reading MAC address - Check that ActiveSync is turned off or WLAN adapter is powered on!\n"));
		return -2;
	} else {
		AddLog(0,_T("Got MAC successfully!\n"));		
	}
	TCHAR szBuffer[50];
	wsprintf(szBuffer,_T("%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X"),fapiAdapterInf.macAddr[0],fapiAdapterInf.macAddr[1],fapiAdapterInf.macAddr[2],fapiAdapterInf.macAddr[3],fapiAdapterInf.macAddr[4],fapiAdapterInf.macAddr[5]);
    _tcsncpy( szBuf, szBuffer, BufSize-1 );   
	AddLog(0,_T("MAC address on first WLAN adapter is %s"),szBuffer);

	return 0;
}

FUSIONXML_API int ExportProfile( TCHAR *szGUID )
{
	AddLog(0,_T("ExportAllProfiles was called!"));
	FAPI_ExportProfile exppro;	
	ZeroMemory(&exppro,sizeof(FAPI_ExportProfile));
	
	exppro.dwVersion = FAPI_EXPORT_PROFILE_1_VERSION; 
	exppro.dwType = FAPI_EXPORT_PROFILE_TYPE;
	exppro.dwOutputFormat = FAPI_REG_FILE;

	exppro.dwFlag = FAPI_SINGLE_PROFILE;
	_tcsncpy(exppro.pszProfileID,&szGUID[0],wcslen(&szGUID[0]));
	TCHAR szPath[] = _T("\\Application\\");
	TCHAR szFileName[260];

	if(_tcslen(tcszExportFilename)==0)
		wsprintf(szFileName,_T("FusionXML_%s.reg"),szGUID);
	else
		_tcscpy(szFileName,tcszExportFilename);

	_tcsncpy(exppro.pszFileName,&szFileName[0],wcslen(&szFileName[0]));
	_tcsncpy(exppro.pszFilePath,&szPath[0],wcslen(&szPath[0]));
	
	DWORD         dwResult;

	dwResult = FAPI_SUCCESS;
	int len = sizeof(FAPI_ExportProfile);

	dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
				DATA_EXPORT_OPERATION_WLAN_PROFILE, &exppro, len,  NULL, 0, NULL);

	
	if(dwResult != FAPI_SUCCESS) {
		FusionSampleDisplayLastError();
		AddLog(1,_T("\nError exporting profile!\n"));
		return FALSE;
	}
	AddLog(0,_T("Exported profile %s successfully!\n"),szGUID);		
	return TRUE;	
}


//Main interfaces to Symscript
extern "C"
{


FUSIONXML_API int GetSignalQuality( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{
	DWORD hAdapter = FusionFindFirstWLANAdapter();
	DWORD dwQuality = 0;
	DWORD dwBytesReturned = 0;
	DWORD dwResult;
	dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
		RF_SIGNAL_QUALITY_WLAN_GET, 
		&hAdapter,sizeof (DWORD), &dwQuality, sizeof(DWORD) , &dwBytesReturned); 
	return dwQuality;
}

FUSIONXML_API int GetSignalStrength( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{
	DWORD hAdapter = FusionFindFirstWLANAdapter();
	DWORD dwSignal = 0;
	DWORD dwBytesReturned = 0;
	DWORD dwResult;
	dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
		RF_SIGNAL_STRENGTH_WLAN_GET, 
		&hAdapter,sizeof (DWORD), &dwSignal, sizeof(DWORD) , &dwBytesReturned); 
	return dwSignal;
}

//A blocking call to wait for a connection to establish.
FUSIONXML_API int GetConnectionStatus( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{
	DWORD hAdapter = FusionFindFirstWLANAdapter();
	DWORD dwConnStatus = 0;
	DWORD dwBytesReturned = 0;
	DWORD dwResult;
	dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
		CONNECTION_STATUS_WLAN_GET, 
		&hAdapter,sizeof (DWORD), &dwConnStatus, sizeof(DWORD) , &dwBytesReturned); 
	return dwConnStatus;
}


//Not finished
FUSIONXML_API int GetAdapterStatus( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{
	DWORD hAdapter = FusionFindFirstWLANAdapter();
	DWORD dwConnStatus = 0;
	DWORD dwBytesReturned = 0;
	DWORD dwResult;
	
	FAPI_AdapterStat adapterStat = {0};
	adapterStat.dwVersion = FAPI_ADAPTER_STAT_1_VERSION;
	adapterStat.dwType =  FAPI_ADAPTER_STAT_TYPE;
	
	dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
		WLAN_ADAPTER_STATISTICS_GET, 
		&hAdapter,sizeof (DWORD), &dwConnStatus, sizeof(DWORD) , &dwBytesReturned); 
	return dwConnStatus;
}

FUSIONXML_API int ExportAllProfiles( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{
	AddLog(0,_T("ExportAllProfiles was called!"));
	FAPI_ExportProfile exppro;	
	ZeroMemory(&exppro,sizeof(FAPI_ExportProfile));
	
	exppro.dwVersion = FAPI_EXPORT_PROFILE_1_VERSION; 
	exppro.dwType = FAPI_EXPORT_PROFILE_TYPE;
	exppro.dwOutputFormat = FAPI_REG_FILE;

	exppro.dwFlag = FAPI_MULTIPLE_PROFILE;
	TCHAR szPath[] = _T("\\Application\\");
	TCHAR szFileName[] = _T("fusionprofiles.reg");

	if(_tcslen(CmdLine)==0)
		_tcsncpy(exppro.pszFileName,&szFileName[0],wcslen(&szFileName[0]));
	else
		_tcsncpy(exppro.pszFileName,CmdLine,wcslen(CmdLine));

	_tcsncpy(exppro.pszFilePath,&szPath[0],wcslen(&szPath[0]));

	DWORD         dwResult;

	dwResult = FAPI_SUCCESS;
	dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
				DATA_EXPORT_OPERATION_WLAN_PROFILE, &exppro, sizeof(FAPI_ExportProfile_1),  NULL, 0, NULL);

	if(dwResult != FAPI_SUCCESS) {
		FusionSampleDisplayLastError();
		AddLog(1,_T("\nError exporting profiles!\n"));
		return FALSE;
	}
	AddLog(0,_T("Exported profiles successfully!\n"));		
	return TRUE;	
}

FUSIONXML_API int SetLog( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{
	AddLog(0,_T("SetLog was called!"));

	if(_wcsnicmp(CmdLine,_T("\"disable\""),_tcslen((TCHAR*)CmdLine))==0) {
		AddLog(0,_T("Log disabled!"));
		bLog = FALSE;
		ClearLog();
	} else {
		AddLog(0,_T("Log enabled!"));
		bLog = TRUE;
	}
	return 0;
}

FUSIONXML_API int DeleteAllProfiles( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{
	AddLog(0,_T("DeleteAllProfiles was called!"));
	EnemurateAndDeleteProfiles();

	return 0;
}

FUSIONXML_API int GetVersion( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{
	AddLog(0,_T("GetVersion was called!"));
    _tcsncpy( szBuf, _FUSION_XML_VERSION, BufSize-1 );   
	return 0;
}

FUSIONXML_API int PowerStatus( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{
	AddLog(0,_T("PowerStatus was called!"));
	DWORD hAdapter = FusionFindFirstWLANAdapter();
	DWORD dwPowerStatus = 0;
	DWORD dwBytesReturned;
	DWORD dwResult;
	dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
		POWER_CONTROL_WLAN_GET_POWER_STATUS, 
		&hAdapter,sizeof (DWORD), &dwPowerStatus, sizeof(DWORD) , &dwBytesReturned); 
	return dwPowerStatus;
}

FUSIONXML_API int PowerOn( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{
	AddLog(0,_T("PowerOn was called!"));
	DWORD hAdapter = FusionFindFirstWLANAdapter();
	DWORD dwResult;
	dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
		POWER_CONTROL_WLAN_ENABLE_POWER, 
		&hAdapter,sizeof (DWORD), NULL, 0 ,NULL); 
	return 0;
}

FUSIONXML_API int PowerOff( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{
	AddLog(0,_T("PowerOff was called!"));
    DWORD dwResult;
	
	DWORD hAdapter = FusionFindFirstWLANAdapter();

	dwResult = lpfn_CommandFusionAPI( g_hInstFusionDLL, 
		POWER_CONTROL_WLAN_DISABLE_POWER, 
		&hAdapter,sizeof (DWORD), NULL, 0 ,NULL);
	return 0;
}


/*******************************************
*                                          *
* The main function to add a new profile.  *
*                                          *
********************************************/
FUSIONXML_API int AddProfile(SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine )
{

	TCHAR szPath[MAX_PATH+1];
	int iReturnValue=0;
	GetModuleFileName ( NULL, szPath, MAX_PATH );
	
	AddLog(0,_T("Fusion XML profile version %s"),_FUSION_XML_VERSION);
	AddLog(0,_T("Module path %s"),szPath);
	AddLog(0,_T("Enter AddProfile function!"));
	AddLog(0,_T("Got following command:"));
	TCHAR *tStrOutput=NULL;
	//AddLog(2,(TCHAR*)ReplaceHTMLtag(CmdLine,tStrOutput));
	if(tStrOutput!=NULL)
		free(tStrOutput);

	AddLog(2,(TCHAR*)CmdLine);
	
	GetFusionVersion();

	TCHAR *pStartT = _tcschr((TCHAR*)CmdLine,'"');
	if(pStartT==NULL) {
		AddLog(1,_T("Error parsing command!"));
		DeinitializeFusion();
		return ERR_PARSING_CMD_ERROR;
	}

	//Trim command from start char (")
	pStartT++;
	//MessageBox(NULL,CmdLine,_T("Add profile"),MB_OK);

	int size = _tcslen((TCHAR*)pStartT);
	char *pString = (char*)malloc(size+1);
	memset(pString,0,size+1);

	if(pString!=NULL) {
		//convert unicode string to multi byte		
		wcstombs(pString,(TCHAR*)pStartT,size);

		//Trim command from end "
		char *pEndT = strrchr(pString,'"');
		if(pEndT==NULL) {
			free(pString);
			AddLog(1,_T("Error parsing command (no end \")!"));
			DeinitializeFusion();
			return ERR_PARSING_CMD_ERROR;
		}		
		pEndT[0]=0;


	//	MessageBox(NULL,pStartT,_T("Add profile"),MB_OK);

		//Simple check for a xml string vs file representation of the command string
		if (strchr(pString,'<')!=NULL)
			iReturnValue = loadXMLString(pString);
		else
			iReturnValue = loadXMLFile(pString);

		free(pString);
	}
	
	dwDebugMask = 0;
	return iReturnValue;
}

} //end of extern "c"

//Wrapper function for the test application
int AddProfileW(TCHAR *cmd)
{
	return AddProfile(NULL, 0, cmd );
}

//Test wrapper
 void ExportAllProfilesW()
{
	ExportAllProfiles(NULL,0,NULL,NULL,0);
}