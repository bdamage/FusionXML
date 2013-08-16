// FusionAPItest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <FusionPublicAPI.h>
#include "..\FusionXML\FusionMgr.h"


CFusionMgr g_fusion;  //Common Fusion API wrapper


//UNICODE version of AddLog function
void AddLog(int color, const TCHAR *lpszText, ...)
{
	va_list argList;
	FILE *pFile = NULL;

	//Initialize variable argument list
	va_start(argList, lpszText);
	SYSTEMTIME systime;
	GetSystemTime(&systime);  //get current time and date

	TCHAR szBuffer[1024];	
	int ret = _vsnwprintf(szBuffer,sizeof(szBuffer),lpszText, argList);

	OutputDebugString(szBuffer);
	OutputDebugString(_T("\n"));

	va_end(argList);
}


void AddNewProfile()
{
	FAPI_PROFILE_4  fapiProfile = {0}; 
	fapiProfile.dwVersion = FAPI_PROFILE_4_VERSION;

	AddLog(3,_T("Detected Fusion Structure Ver = %d"),fapiProfile.dwVersion);

	//specify common properties for both Adhoc and Infrastructure
	fapiProfile.dwType = FAPI_PROFILE_TYPE;	

	//----------- Default values --------------
	fapiProfile.dwPowerIndex = FAPI_WLAN_POWERMODE_FAST_POWER_SAVE;
	fapiProfile.dwTxPower = FAPI_POWER_BSS_AUTO;					// Must use AUTO or PLUS for infrastructure
	fapiProfile.dwOpMode =  FAPI_NDIS802_11INFRASTRUCTURE ;			// infrastructure mode
	fapiProfile.dwIPAddressingMode = FAPI_ADDR_MODE_IPV4_DHCP;
	fapiProfile.dwEncryption = FAPI_ENCRYPTION_NONE ;
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_AUTH_NONE;
	_tcscpy(fapiProfile.pszCountryCode,_T("US"));

	//----------- End of default values -----------

	SYSTEMTIME systime;
	GetSystemTime(&systime);  //get current time and date
	TCHAR tcsProfileName[64];
	_stprintf(tcsProfileName,_T("[My profile %2.2d:%2.2d]"),systime.wHour,systime.wMinute);
	_tcscpy(fapiProfile.pszName,tcsProfileName);
	
	fapiProfile.dwOpMode = FAPI_NDIS802_11INFRASTRUCTURE; 

	//Do only set if Adhoc is being used otherwise authentication method will be overwritten!
	if(fapiProfile.dwOpMode == FAPI_NDIS802_11IBSS)
		fapiProfile.NetworkType.Adhoc.dwChannel = 11;

	_tcscpy(fapiProfile.pszSSID,_T("[My ESSID 01234567890123456789]"));
	_tcscpy(fapiProfile.pszCountryCode,_T("SE"));
	fapiProfile.dwPowerIndex = FAPI_WLAN_POWERMODE_CAM;
	fapiProfile.dwTxPower = FAPI_POWER_BSS_PLUS;
	fapiProfile.dwEncryption = FAPI_ENCRYPTION_AES;


	//WARNING! Below parameter doesn't exsist in structure 8 and newer
//	fapiProfile.dwAllowMixedMode = (FAPI_WLAN_ALLOW_MIXED_MODE)fxml.GetAllowAESMixedMode();
	
	//WARNING! Below parameter doesn't exsist in structure 5 and newer
//	fapiProfile.NetworkType.Infrastructure.dwSecurityMode = (FAPI_WLAN_SECURITY_TYPE)fxml.GetSecurityType();
	//Redudancy & autodetection of security type
//	fapiProfile.NetworkType.Infrastructure.dwSecurityMode = GetSecurityMode(fapiProfile.NetworkType.Infrastructure.dwAuthentication,fapiProfile.dwEncryption);

/*	fapiProfile.dwIPAddressingMode = FAPI_ADDR_MODE_IPV4_STATIC;

	_tcscpy(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Address,_T("192.168.1.250"));
	_tcscpy(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4SubnetMask,_T("255.255.255.0"));

	_tcscpy(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Gateway,_T("192.168.1.1"));
	
	//WARNING! Gateway1 & 2 parameter does only exsist in structure 7 and newer
	//_tcscpy(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Gateway1,_T("192.168.1.1"));
	//_tcscpy(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Gateway2,_T("192.168.1.2"));
	_tcscpy(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS1,_T("192.168.1.10"));
	_tcscpy(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS2,_T("192.168.1.11"));
	_tcscpy(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS1,_T("192.168.2.1"));
	_tcscpy(fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS2,_T("192.168.2.2"));
*/
	
//	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_PEAP_MSCHAPV2; //FAPI_LEAP;
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_LEAP; //;

	//Only apply a passphrase if needed to avoid union type structure overwrite
	if(fapiProfile.NetworkType.Infrastructure.dwAuthentication == FAPI_AUTH_NONE) {
		if(fapiProfile.dwEncryption == FAPI_ENCRYPTION_AES)
			_tcscpy(fapiProfile.EncryptionAlgorithm.AESType.pszAESPassphrase,_T("Something very secret!"));
		else if(fapiProfile.dwEncryption == FAPI_ENCRYPTION_TKIP)
			_tcscpy(fapiProfile.EncryptionAlgorithm.TKIPType.pszTKIPPassphrase,_T("Something very secret!"));
	}



	//Correct encryption if LEAP is being used
	if(fapiProfile.NetworkType.Infrastructure.dwAuthentication == FAPI_LEAP) 
		fapiProfile.dwEncryption = FAPI_ENCRYPTION_104BIT_PASSPH;  //This can set to WEP104, TKIP & AES.
		//fapiProfile.dwEncryption = FAPI_ENCRYPTION_104BIT_PASSPH;  //This can set to WEP104, TKIP & AES.

	
	_tcscpy(fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszDomain,_T("[Domain]"));
	_tcscpy(fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszIdentity,_T("[Username]"));
	_tcscpy(fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszUserPwd,_T("[Password]"));
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.dwCredentialFlags = 0; //see TABLE 3 what to set

	/* Add dummy certificate this needed to set On connect & resume check boxes.
	    ---------  From documentation --------------
		2. What is the essence of “FAPI_REQUIRE_SERVER_CERTIFICATE” credential flag and why it is 
		introduced in the later releases of Fusion (Fusion 2.55 and above)?

		During Fusion 2.40/2.35/2.50/2.53, any authentication profile creation mandates the server 
		certificate in profile creation through Fusion Public API. This limitation restricts the 
		user from creating authentication profiles with out server certificates.

		Fusion 2.55 and above, the restriction is removed and users are encouraged to create authentication 
		profiles with out server certificates. This is achieved with the credential 
		flag “FAPI_REQUIRE_SERVER_CERTIFICATE”. 
		If user wants to create an authentication profile with server certificate, 
		then this particular flag has to be set. 
		If user wants to create an authentication profile with out server certificate, 
		then this particular flag has to be reset (cleared).
	-------------------------------------------------------*/
	
	
  //	FAPI_SPECIFY_PROFILE_TYPE_AS_USER_PROFILE //if used, then username and password is ignored!
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.dwCredentialFlags = (FAPI_SPECIFY_SERVER_CERTIFICATE_LOCAL | FAPI_SPECIFY_PROFILE_TYPE_AS_USER_PROFILE );
	_tcscpy(fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.LocalCertInstall.pszServerCertFName,_T("Class 2 Public Primary Certification Authority"));
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = (FAPI_CACHE_OPTION_CONNECT | FAPI_CACHE_OPTION_RESUME); //see TABLE 3 what to set

	//_tcscpy(fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.LocalCertInstall.pszUserCertFName,_T("mycert"));
	g_fusion.AddFusionProfile((PVOID)&fapiProfile);
}


void AddNewLEAPProfile()
{
	FAPI_PROFILE_7  fapiProfile = {0}; 
	fapiProfile.dwVersion = FAPI_PROFILE_7_VERSION;

	AddLog(3,_T("Detected Fusion Structure Ver = %d"),fapiProfile.dwVersion);

	//specify common properties for both Adhoc and Infrastructure
	fapiProfile.dwType = FAPI_PROFILE_TYPE;	

	//----------- Default values --------------
	fapiProfile.dwPowerIndex = FAPI_WLAN_POWERMODE_FAST_POWER_SAVE;
	fapiProfile.dwTxPower = FAPI_POWER_BSS_AUTO;					// Must use AUTO or PLUS for infrastructure
	fapiProfile.dwOpMode =  FAPI_NDIS802_11INFRASTRUCTURE ;			// infrastructure mode
	fapiProfile.dwIPAddressingMode = FAPI_ADDR_MODE_IPV4_DHCP;
	fapiProfile.dwEncryption = FAPI_ENCRYPTION_NONE ;
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_AUTH_NONE;
	_tcscpy(fapiProfile.pszCountryCode,_T("US"));

	//----------- End of default values -----------

	SYSTEMTIME systime;
	GetSystemTime(&systime);  //get current time and date
	TCHAR tcsProfileName[64];
	_stprintf(tcsProfileName,_T("[My LEAP profile %2.2d:%2.2d]"),systime.wHour,systime.wMinute);
	_tcscpy(fapiProfile.pszName,tcsProfileName);
	
	_tcscpy(fapiProfile.pszSSID,_T("[My ESSID 01234567890123456789]"));
	_tcscpy(fapiProfile.pszCountryCode,_T("SE"));
	fapiProfile.dwEncryption = FAPI_ENCRYPTION_104BIT_PASSPH;
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_LEAP; 

	if((fapiProfile.NetworkType.Infrastructure.dwAuthentication != FAPI_AUTH_NONE) && (fapiProfile.NetworkType.Infrastructure.dwAuthentication != FAPI_LEAP))
		fapiProfile.NetworkType.Infrastructure.dwSecurityMode = FAPI_SECURITY_WPA2_ENTERPRISE;


	_tcscpy(fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszDomain,_T("[Domain]"));
	_tcscpy(fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszIdentity,_T("[Username]"));
	_tcscpy(fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszUserPwd,_T("[Password]"));
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.dwCredentialFlags = 0; //see TABLE 3 what to set

   //Add a dummy cert and set "at connect" & "resume" credential flags
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.dwCredentialFlags = (FAPI_SPECIFY_SERVER_CERTIFICATE_LOCAL | FAPI_SPECIFY_PROFILE_TYPE_AS_USER_PROFILE );
	_tcscpy(fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.LocalCertInstall.pszServerCertFName,_T("Class 2 Public Primary Certification Authority"));
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = (FAPI_CACHE_OPTION_CONNECT | FAPI_CACHE_OPTION_RESUME); //see TABLE 3 what to set

	g_fusion.AddFusionProfile((PVOID)&fapiProfile);
}

void AddNewPEAPProfile()
{
	FAPI_PROFILE_7  fapiProfile = {0}; 
	fapiProfile.dwVersion = FAPI_PROFILE_7_VERSION;

	AddLog(3,_T("Detected Fusion Structure Ver = %d"),fapiProfile.dwVersion);

	//specify common properties for both Adhoc and Infrastructure
	fapiProfile.dwType = FAPI_PROFILE_TYPE;	

	//----------- Default values --------------
	fapiProfile.dwPowerIndex = FAPI_WLAN_POWERMODE_FAST_POWER_SAVE;
	fapiProfile.dwTxPower = FAPI_POWER_BSS_AUTO;					// Must use AUTO or PLUS for infrastructure
	fapiProfile.dwOpMode =  FAPI_NDIS802_11INFRASTRUCTURE ;			// infrastructure mode
	fapiProfile.dwIPAddressingMode = FAPI_ADDR_MODE_IPV4_DHCP;
	fapiProfile.dwEncryption = FAPI_ENCRYPTION_NONE ;
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_AUTH_NONE;
	_tcscpy(fapiProfile.pszCountryCode,_T("US"));

	//----------- End of default values -----------

	SYSTEMTIME systime;
	GetSystemTime(&systime);  //get current time and date
	TCHAR tcsProfileName[64];
	_stprintf(tcsProfileName,_T("[My PEAP profile %2.2d:%2.2d]"),systime.wHour,systime.wMinute);
	_tcscpy(fapiProfile.pszName,tcsProfileName);
	
	_tcscpy(fapiProfile.pszSSID,_T("[My ESSID 01234567890123456789]"));
	_tcscpy(fapiProfile.pszCountryCode,_T("SE"));
	fapiProfile.dwEncryption = FAPI_ENCRYPTION_AES;
	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_PEAP_MSCHAPV2; 
//	fapiProfile.NetworkType.Infrastructure.dwAuthentication = FAPI_EAP_TLS; 

	
	if((fapiProfile.NetworkType.Infrastructure.dwAuthentication != FAPI_AUTH_NONE) && (fapiProfile.NetworkType.Infrastructure.dwAuthentication != FAPI_LEAP))
		fapiProfile.NetworkType.Infrastructure.dwSecurityMode = FAPI_SECURITY_WPA2_ENTERPRISE;


	_tcscpy(fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszDomain,_T("[Domain]"));
	_tcscpy(fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszIdentity,_T("[Username]"));
	_tcscpy(fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCredSettings.pszUserPwd,_T("[Password]"));
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.dwCredentialFlags = 0; //see TABLE 3 what to set

   //Add a dummy cert and set "at connect" & "resume" credential flags
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.dwCredentialFlags = (FAPI_SPECIFY_SERVER_CERTIFICATE_LOCAL | FAPI_SPECIFY_PROFILE_TYPE_AS_USER_PROFILE | FAPI_SPECIFY_USER_CERTIFICATE_LOCAL );
	_tcscpy(fapiProfile.NetworkType.Infrastructure.CredentialSettings.ServerCertInstall.LocalCertInstall.pszServerCertFName,_T("Class 2 Public Primary Certification Authority"));
	fapiProfile.NetworkType.Infrastructure.CredentialSettings.CredentialPromptOption.dwCacheOpts = (FAPI_CACHE_OPTION_CONNECT ); //see TABLE 3 what to set

	_tcscpy(fapiProfile.NetworkType.Infrastructure.CredentialSettings.UserCertInstall.LocalCertInstall.pszUserCertFName,_T("mycert"));
	
	g_fusion.AddFusionProfile((PVOID)&fapiProfile);
}


int _tmain(int argc, _TCHAR* argv[])
{
	g_fusion.EnumerateAndDeleteProfiles();
	AddNewLEAPProfile();
	AddNewPEAPProfile();
	AddNewProfile();
	return 0;
}

