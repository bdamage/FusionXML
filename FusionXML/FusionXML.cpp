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
HINSTANCE g_hInst = NULL;
/*static DWORD	   				g_hInstFusionDLL      = 0;
static LPFN_OPEN_FUSION_API		lpfn_OpenFusionAPI    = NULL;
static LPFN_CLOSE_FUSION_API	lpfn_CloseFusionAPI   = NULL;
static LPFN_COMMAND_FUSION_API	lpfn_CommandFusionAPI = NULL;
*/

BOOL AddFusionProfile(PVOID pProfile);
int processData(TiXmlDocument *pDoc);
void AddLog(DWORD color, const TCHAR *lpszText, ...);
void  FusionSampleDisplayLastError();

BOOL bLog = TRUE;
BOOL bConnect = FALSE;
BOOL bExport = FALSE;

TCHAR tcszExportFilename[260];
//TCHAR g_pszFusionVersionStr[FAPI_MAX_MODULE_VERSION_SIZE];


CFusionMgr g_fusion;  //Common Fusion API wrapper


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
			AddLog(0,_T("Trying to load Fusion API"));
			if(g_fusion.InitializeLib()==false){
				AddLog(1,_T("Error loading Fusion API!"));
				return FALSE;
			}
		
			AddLog(0,_T("Initialization of Fusion API Success!"));
		}
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		AddLog(0,_T("Unloading Fusion API!"));
		g_fusion.DeInitializeLib();
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

//	TCHAR szBuffer[2048];
	TCHAR *szBuffer = new TCHAR[2048];

	int size = sizeof(TCHAR[2048]);
	ZeroMemory(szBuffer,size);
	int ret = _vsnwprintf(szBuffer,size,lpszText, argList);
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
	delete szBuffer;


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

	if(_tcsncmp(g_fusion.m_pszFusionVersionStr,_T("2.4."),4)==0){
		dwVer = FAPI_PROFILE_2_VERSION; 
	}
	else if(_tcsncmp(g_fusion.m_pszFusionVersionStr,_T("2.35."),5)==0){
		dwVer = FAPI_PROFILE_3_VERSION;
	} 
	else if(_tcsncmp(g_fusion.m_pszFusionVersionStr,_T("2.5."),4)==0){
		dwVer = FAPI_PROFILE_3_VERSION;
	}
	else if(_tcsncmp(g_fusion.m_pszFusionVersionStr,_T("2.55."),5)==0){
		dwVer = FAPI_PROFILE_4_VERSION;
	}
	else if(_tcsncmp(g_fusion.m_pszFusionVersionStr,_T("2.56."),5)==0){
		dwVer = FAPI_PROFILE_6_VERSION;
	} 
	else if(_tcsncmp(g_fusion.m_pszFusionVersionStr,_T("2.57."),5)==0){
		dwVer = FAPI_PROFILE_6_VERSION;
	} 
	else if(_tcsncmp(g_fusion.m_pszFusionVersionStr,_T("2.61."),5)==0){
		dwVer = FAPI_PROFILE_5_VERSION;
	} 
	else if(_tcsncmp(g_fusion.m_pszFusionVersionStr,_T("2.60."),5)==0){
		dwVer = FAPI_PROFILE_5_VERSION;
	}
	else if(_tcsncmp(g_fusion.m_pszFusionVersionStr,_T("3.00."),5)==0){
		dwVer = FAPI_PROFILE_7_VERSION;
	}
	else if(_tcsncmp(g_fusion.m_pszFusionVersionStr,_T("3.20."),5)==0){
		dwVer = FAPI_PROFILE_8_VERSION;
	}
	else if(_tcsncmp(g_fusion.m_pszFusionVersionStr,_T("3.30."),5)==0){
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



FAPI_PROFILE_7 *ParseProfile7(CFusionXMLProfile &fxml)
{
	
	FAPI_PROFILE_7  *pfapiProfile = (FAPI_PROFILE_7  *)malloc(sizeof(FAPI_PROFILE_7));
	memset(pfapiProfile,0,sizeof(FAPI_PROFILE_7));
	FAPI_PROFILE_7  &fapiProfile =  *pfapiProfile; //{0}; //for 3.00
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


	fxml.SetProfileName(fapiProfile.pszName,FAPI_MAX_PROFILE_NAME_LENGTH);
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

	
	//Default to 104 bit WEP if LEAP being used (modified Version 1.17)
	if((fapiProfile.NetworkType.Infrastructure.dwAuthentication == FAPI_LEAP) && (fapiProfile.dwEncryption == FAPI_ENCRYPTION_NONE)) 
		fapiProfile.dwEncryption = FAPI_ENCRYPTION_104BIT_PASSPH;
	else if((fapiProfile.NetworkType.Infrastructure.dwAuthentication == FAPI_LEAP) && (fapiProfile.dwEncryption == FAPI_ENCRYPTION_104BIT_HEX))   //added in version 1.20 for sanity check
		fapiProfile.dwEncryption = FAPI_ENCRYPTION_104BIT_PASSPH;

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

//	TCHAR passphrase[FAPI_MAX_PASSPHRASE_LENGTH];
//	fxml.GetPassphrase(passphrase);

	if(fapiProfile.dwEncryption == FAPI_ENCRYPTION_TKIP)
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.TKIPPassphrase.pszTKIPPassphrase);
	else if( fapiProfile.dwEncryption == FAPI_ENCRYPTION_AES)
		fxml.GetPassphrase(fapiProfile.EncryptionAlgorithm.AESPassphrase.pszAESPassphrase);
//	else if()
	
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
	if(pServerCert){	
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.LocalCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	pServerCert = fxml.GetElementSafe(pElmProf,"RemoteUserCert");		
	if(pServerCert) {
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszServerName,"ServerName",FAPI_MAX_REMOTE_SERVER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemoteUserName,"UserName",FAPI_MAX_REMOTE_USER_NAME_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszRemotePassword,"Password",FAPI_MAX_REMOTE_PASSWORD_LEN);
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.RemoteCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}
	
	return pfapiProfile; //fapiProfile;
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
	else if((fapiProfile.NetworkType.Infrastructure.dwAuthentication == FAPI_LEAP) && (fapiProfile.dwEncryption == FAPI_ENCRYPTION_104BIT_HEX))   //added in version 1.20 for sanity check
		fapiProfile.dwEncryption = FAPI_ENCRYPTION_104BIT_PASSPH;

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
	if(pServerCert){	
		fxml.GetText(pServerCert,fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.LocalCertInstall.pszUserCertFName,"UserCertFilename",FAPI_MAX_CERT_FNAME_LENGTH);
	}

	pServerCert = fxml.GetElementSafe(pElmProf,"RemoteUserCert");		
	if(pServerCert){
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
	else if((fapiProfile.NetworkType.Infrastructure.dwAuthentication == FAPI_LEAP) && (fapiProfile.dwEncryption == FAPI_ENCRYPTION_104BIT_HEX))   //added in version 1.20 for sanity check
		fapiProfile.dwEncryption = FAPI_ENCRYPTION_104BIT_PASSPH;

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
	if(!pRootElm){
		AddLog(1,_T("Error finding root element &lt;FusionConfig&gt; in xml file!\n"));
		return ERR_TAG_FUSIONCONFIG;
	}

	CFusionXMLProfile fxml(pRootElm);

	//Do initial config
	DWORD dwDummyValue=0;
	if(fxml.GetInteger(pRootElm,&dwDummyValue,"SetLog")==0) {
		if(dwDummyValue==0) {
			ClearLog();
			bLog = FALSE;
		}
	}

	dwDummyValue = 0;
	if(fxml.GetInteger(pRootElm,&dwDummyValue,"Connect")==0)  {
		if(dwDummyValue==1)
			bConnect = TRUE;
	}
	
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
			if(g_fusion.AddFusionProfile((PVOID)&ParseProfile2(fxml)))
				return SUCCESSFULL;
			break;
		case FAPI_PROFILE_3_VERSION:
			if(g_fusion.AddFusionProfile((PVOID)&ParseProfile3(fxml)))
				return SUCCESSFULL;
			break;
		case FAPI_PROFILE_4_VERSION:
			if(g_fusion.AddFusionProfile((PVOID)&ParseProfile4(fxml)))
				return SUCCESSFULL;
			break;
		case FAPI_PROFILE_5_VERSION:
			if(g_fusion.AddFusionProfile((PVOID)&ParseProfile5(fxml)))
				return SUCCESSFULL;
			break;
		case FAPI_PROFILE_6_VERSION:			
			if(g_fusion.AddFusionProfile((PVOID)&ParseProfile6(fxml)))
				return SUCCESSFULL;
			break;
		case FAPI_PROFILE_7_VERSION:
			{
				void* p = ParseProfile7(fxml);
				BOOL bRet = g_fusion.AddFusionProfile((PVOID)p);
				free(p);
				if(bRet)
					return SUCCESSFULL;
			}
			break;
		case FAPI_PROFILE_8_VERSION:
			if(g_fusion.AddFusionProfile((PVOID)&ParseProfile8(fxml)))
				return SUCCESSFULL;
			break;
		case FAPI_PROFILE_9_VERSION:
			if(g_fusion.AddFusionProfile((PVOID)&ParseProfile9(fxml)))
				return SUCCESSFULL;
			break;
	}
	return ERR_ADDING_PROFILE;
}

void DumpLastError(){	
	LPVOID lpMsgBuf;
	FormatMessage( 
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM | 
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		0, // Default language
		(LPTSTR) &lpMsgBuf,
		0,
		NULL 
	);
	// Process any inserts in lpMsgBuf.
	// ...
	// Display the string.
	OutputDebugString((LPCTSTR)lpMsgBuf);
	// Free the buffer.
	LocalFree( lpMsgBuf );

}






BOOL GetFusionVersion()
{
	g_fusion.GetWLANVersions( &VersionList);
	//_tcscpy(g_pszFusionVersionStr, VersionList -> pszVersionStr);
	return TRUE;
}
/*
BOOL AddFusionProfile(PVOID pProfile)
{
	DWORD         dwResult;
	FAPI_AddedWLANProfileParams  fapiAddedWLANProfileParams;
	dwResult = FAPI_SUCCESS;
	memset(&fapiAddedWLANProfileParams, 0x0, sizeof(fapiAddedWLANProfileParams));

	DWORD structSize = sizeof(FAPI_PROFILE_2);
	FAPI_PROFILE_2 *p = (FAPI_PROFILE_2 *)pProfile;
//#ifdef _DEBUG
	//for debugging purpose
	FAPI_PROFILE_3 *p3 = (FAPI_PROFILE_3 *)pProfile;
	FAPI_PROFILE_4 *p4 = (FAPI_PROFILE_4 *)pProfile; 
	FAPI_PROFILE_6 *p6 = (FAPI_PROFILE_6 *)pProfile; 
	FAPI_PROFILE_7 *p7 = (FAPI_PROFILE_7 *)pProfile; 
	FAPI_PROFILE_8 *p8 = (FAPI_PROFILE_8 *)pProfile; 
//#endif
	
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
			g_fusion.ConnectToProfile(pszProfileID);
		}
		if(bExport) {
			g_fusion.ExportProfile( fapiAddedWLANProfileParams.pszProfileID);
		}
		return TRUE;
	}
		
}
*/

/************************************************

	GetMAC(...)

	This function will only return successfully 
	if the adpater is powered.

*************************************************/
FUSIONXML_API int GetMAC( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{

	AddLog(0,_T("GetMAC function was called!"));
	g_fusion.GetMAC(szBuf, BufSize);
	return 0;
}

FUSIONXML_API int ExportProfile( TCHAR *szGUID )
{
	AddLog(0,_T("ExportAllProfiles was called!"));
	
	return g_fusion.ExportProfile(szGUID);	
}


//Main interfaces to Symscript
extern "C"
{


FUSIONXML_API int GetSignalQuality( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{
	return g_fusion.GetSignalQuality();
}

FUSIONXML_API int GetSignalStrength( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{
	return g_fusion.GetSignalStrength();
}

//A blocking call to wait for a connection to establish.
FUSIONXML_API int GetConnectionStatus( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{	
	return g_fusion.GetConnectionStatus();
}


FUSIONXML_API int ExportAllProfiles( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{
	AddLog(0,_T("ExportAllProfiles was called!"));
	g_fusion.ExportAllProfiles(CmdLine);
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
	g_fusion.EnumerateAndDeleteProfiles();
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
	return g_fusion.PowerStatus();
}

FUSIONXML_API int PowerOn( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{
	AddLog(0,_T("PowerOn was called!"));
	g_fusion.PowerOn();
	return 0;
}

FUSIONXML_API int PowerOff( SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine, TCHAR *szBuf, int BufSize )
{
	AddLog(0,_T("PowerOff was called!"));
	g_fusion.PowerOff();
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

	int l = _tcslen(CmdLine);
	if(l<1600)
		AddLog(2,(TCHAR*)CmdLine);
	else
		AddLog(2,_T("Skipping dump of command line to log."));
	
	GetFusionVersion();

	TCHAR *pStartT = _tcschr((TCHAR*)CmdLine,'"');
	if(pStartT==NULL) {
		AddLog(1,_T("Error parsing command!"));
		g_fusion.DeInitializeLib();
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
			g_fusion.DeInitializeLib();
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