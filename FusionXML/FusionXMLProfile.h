#include "FusionPublicAPI.h"

extern void AddLog(int color, const TCHAR *lpszText, ...);

 
class CFusionXMLProfile
{
	TiXmlElement *m_pRootElm;
	TiXmlElement *pElmProf;

public:
	CFusionXMLProfile(TiXmlElement *pRootElement) :
	m_pRootElm(pRootElement)
	{
		pElmProf = m_pRootElm->FirstChild("Profile")->ToElement();

	}

	TiXmlElement *GetRootElement()
	{
		return pElmProf;
	}

	int SetProfileName(TCHAR *pProfileNameStr, size_t maxLength)
	{

		if(pElmProf==NULL) {
			AddLog(1,_T("Couldn't find Profile tag!"));
			return ERR_TAG_PROFILE;
		}

		const char *szProfileName = pElmProf->Attribute("name");
		if(szProfileName!=NULL)
			 mbstowcs(pProfileNameStr,szProfileName,strlen(szProfileName)+1);			
		else
			_tcscpy(pProfileNameStr, _T("Unknown name"));	

		return 0;
	}

	DWORD GetOpMode()
	{
		DWORD dwOPValue=FAPI_NDIS802_11INFRASTRUCTURE;
		//Only set if the data is provided in the xml file otherwise leave the default values.
		if(GetInteger(pElmProf,&dwOPValue,"OPMode")==0)  //Adhoc or Infra
		{		
			// success dwOPValue; 
		}
		return dwOPValue;
	}

	DWORD GetChannel()
	{
		DWORD dwChannelValue=0;
		if(GetInteger(pElmProf,&dwChannelValue,"Channel")==0)  
		{		
		//success dwChannelValue; 
		}
		return dwChannelValue;
	}

	DWORD GetPowerIndex()
	{
		DWORD dwValue = FAPI_WLAN_POWERMODE_FAST_POWER_SAVE;
		if(GetInteger(pElmProf,&dwValue,"PowerIndex")==0)
		{
			//Only set if the data is provided in xml file otherwise don't touch default values.
			//dwValue; 
		}
		return dwValue;
	}
	DWORD GetTxPower()
	{
		DWORD dwValue = FAPI_POWER_BSS_AUTO;
		if(GetInteger(pElmProf,&dwValue,"TxPower")==0)
		{
	
		}
		return dwValue;
	}

	void GetSSID(TCHAR *pOutString)
	{
		GetText(pElmProf,pOutString,"ESSID",FAPI_MAX_SSID_LENGTH);
	}

	void GetCountry(TCHAR *pOutString)
	{
		//_tcscpy(pOutString,_T("US"));
		_tcscpy(pOutString,FAPI_ALLOW_ANY_COUNTRY);  //Default Allow any country by applying empty string
		GetText(pElmProf,pOutString,"Country",FAPI_MAX_COUNTRY_CODE_LENGTH);
		
		if(_wcsicmp(_T("UK"),pOutString)==0)  //simplify for the end user
			_tcscpy(pOutString,_T("GB"));
	}

	DWORD GetIPAddressMode()
	{
		TiXmlElement *pElmV4Mode = NULL; 
		DWORD dwMode = FAPI_ADDR_MODE_IPV4_DHCP;

		pElmV4Mode = GetElementSafe(pElmProf,"IPv4Mode");
		if(pElmV4Mode)
		{
			const char *szIPMode = pElmV4Mode->GetText();
			if(szIPMode!=NULL)
			{
				if(_stricmp("STATIC",szIPMode)==0)
					dwMode = FAPI_ADDR_MODE_IPV4_STATIC;
				else
					dwMode = FAPI_ADDR_MODE_IPV4_DHCP;
					
			}else
				OutputDebugString(_T("IPv4Mode defined in xml file/string but NOT set to a value!\n"));
		}
		return dwMode;
	}

	void GetIPv4Address(TCHAR *szOut)
	{
		TiXmlElement *pElmIPv4 = GetElementSafe(pElmProf,"IPv4");
		if(pElmIPv4)
			GetText(pElmIPv4,szOut,"IPAddress",FAPI_MAX_IP_ADDRESS_LENGTH);
		else
			ZeroMemory(szOut,FAPI_MAX_IP_ADDRESS_LENGTH);
	}

	void GetSubnet(TCHAR *szOut)
	{
		TiXmlElement *pElmIPv4 = GetElementSafe(pElmProf,"IPv4");
		if(pElmIPv4)
			GetText(pElmIPv4,szOut,"Subnet",FAPI_MAX_IP_ADDRESS_LENGTH);
		else
				ZeroMemory(szOut,FAPI_MAX_IP_ADDRESS_LENGTH);

	}

	void GetDNS1(TCHAR *szOut)
	{
		TiXmlElement *pElmIPv4 = GetElementSafe(pElmProf,"IPv4");
		if(pElmIPv4)
			GetText(pElmIPv4,szOut,"DNS1",FAPI_MAX_IP_ADDRESS_LENGTH);
		else
			ZeroMemory(szOut,FAPI_MAX_IP_ADDRESS_LENGTH);

	}

	void GetDNS2(TCHAR *szOut)
	{
		TiXmlElement *pElmIPv4 = GetElementSafe(pElmProf,"IPv4");
		if(pElmIPv4)
			GetText(pElmIPv4,szOut,"DNS2",FAPI_MAX_IP_ADDRESS_LENGTH);
		else
			ZeroMemory(szOut,FAPI_MAX_IP_ADDRESS_LENGTH);

	}

	void GetGateway(TCHAR *szOut)
	{
		TiXmlElement *pElmIPv4 = GetElementSafe(pElmProf,"IPv4");
		if(pElmIPv4)
			GetText(pElmIPv4,szOut,"Gateway",FAPI_MAX_IP_ADDRESS_LENGTH);
		else
			ZeroMemory(szOut,FAPI_MAX_IP_ADDRESS_LENGTH);

	}

	void GetWINS1(TCHAR *szOut)
	{
		TiXmlElement *pElmIPv4 = GetElementSafe(pElmProf,"IPv4");
		if(pElmIPv4)
			GetText(pElmIPv4,szOut,"WINS1",FAPI_MAX_IP_ADDRESS_LENGTH);
	}

	void GetWINS2(TCHAR *szOut)
	{
		TiXmlElement *pElmIPv4 = GetElementSafe(pElmProf,"IPv4");
		if(pElmIPv4)
			GetText(pElmIPv4,szOut,"WINS2",FAPI_MAX_IP_ADDRESS_LENGTH);
		else
			ZeroMemory(szOut,FAPI_MAX_IP_ADDRESS_LENGTH);

	}


/*			GetText(pElmIPv4,fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS1,"DNS1",FAPI_MAX_IP_ADDRESS_LENGTH);
			GetText(pElmIPv4,fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4DNS2,"DNS2",FAPI_MAX_IP_ADDRESS_LENGTH);
			GetText(pElmIPv4,fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4Gateway,"Gateway",FAPI_MAX_IP_ADDRESS_LENGTH);
			GetText(pElmIPv4,fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS1,"WINS1",FAPI_MAX_IP_ADDRESS_LENGTH);
			GetText(pElmIPv4,fapiProfile.StaticIPSettings.IPV4Settings.pszIPV4WINS2,"WINS2",FAPI_MAX_IP_ADDRESS_LENGTH);
*/

	DWORD GetSecurityType()
	{
		DWORD dwSecValue = FAPI_SECURITY_LEGACY;                 
		if(GetInteger(pElmProf,&dwSecValue,"SecurityType")==0) {
			//Success?
		}
		return dwSecValue;
	}

	DWORD GetAllowAESMixedMode()
	{
		DWORD dwSecValue = FAPI_WLAN_AES_ALLOW_MIXED_MODE_OFF;                 
		if(GetInteger(pElmProf,&dwSecValue,"AllowAESMixedMode")==0) {
			//Success?
		}
		return dwSecValue;
	}
	DWORD GetEncryption()
	{
		TiXmlElement *pEncMode = NULL; 
		pEncMode = GetElementSafe(pElmProf,"EncryptionMethod");
		if(pEncMode==NULL)
			pEncMode = GetElementSafe(pElmProf,"EncryptMethod");

		DWORD dwEncrypt = FAPI_ENCRYPTION_NONE;	
		if(pEncMode) {
			const char *szEncMode = pEncMode->GetText();
			if(_stricmp("OPEN",szEncMode)==0)
				dwEncrypt = FAPI_ENCRYPTION_NONE ;
			else if(_stricmp("TKIP",szEncMode)==0)
				dwEncrypt = FAPI_ENCRYPTION_TKIP ;
			else if(_stricmp("AES",szEncMode)==0)
				dwEncrypt = FAPI_ENCRYPTION_AES ;
			else if(_stricmp("WEP40",szEncMode)==0)
				dwEncrypt = FAPI_ENCRYPTION_40BIT_HEX ;
			else if(_stricmp("WEP128",szEncMode)==0)
				dwEncrypt = FAPI_ENCRYPTION_104BIT_HEX ;
			else if(_stricmp("WEP104",szEncMode)==0)
				dwEncrypt = FAPI_ENCRYPTION_104BIT_HEX ;
		}
		return dwEncrypt;
	}

	void GetPassphrase(TCHAR *szOut)
	{
		GetText(pElmProf,szOut,"Passphrase",FAPI_MAX_PASSPHRASE_LENGTH);
	}

	bool GetWEP40(DWORD *dwKeyIndex, TCHAR *szKey1,TCHAR *szKey2,TCHAR *szKey3,TCHAR *szKey4)
	{
		TiXmlNode	*pNode=NULL;
		TiXmlElement *pElmWEP40 = NULL;
		pNode = pElmProf->FirstChild("WEP40");
		if(pNode)
		{
			pElmWEP40 = pNode->ToElement();
			if(pElmWEP40)
			{		
				DWORD keyindex = 1;		
				GetInteger(pElmWEP40,&keyindex,"KeyToUse");
				
				//defaulting to key 1
				*dwKeyIndex = (DWORD)FAPI_FIRST_WEP_KEY;
				if(keyindex==2)
					*dwKeyIndex= FAPI_SECOND_WEP_KEY;
				else if(keyindex==3)
					*dwKeyIndex= FAPI_THIRD_WEP_KEY;
				else if(keyindex==4)
					*dwKeyIndex = FAPI_FOURTH_WEP_KEY;

				GetText(pElmWEP40,szKey1,"Key1Hex",FAPI_MAX_KEY_LENGTH_40_BIT*2 + 1);
				GetText(pElmWEP40,szKey2,"Key2Hex",FAPI_MAX_KEY_LENGTH_40_BIT*2 + 1);
				GetText(pElmWEP40,szKey3,"Key3Hex",FAPI_MAX_KEY_LENGTH_40_BIT*2 + 1);
				GetText(pElmWEP40,szKey4,"Key4Hex",FAPI_MAX_KEY_LENGTH_40_BIT*2 + 1);
				return true;
				
			}
		}
		return false;
	}
	bool GetWEP128(DWORD *dwKeyIndex, TCHAR *szKey1,TCHAR *szKey2,TCHAR *szKey3,TCHAR *szKey4)
	{
		TiXmlNode	*pNode=NULL;
		TiXmlElement *pElmWEP40 = NULL;
		*dwKeyIndex = (DWORD)FAPI_FIRST_WEP_KEY;
		pNode = pElmProf->FirstChild("WEP128");
		if(pNode)
		{
			pElmWEP40 = pNode->ToElement();
			if(pElmWEP40)
			{		
				DWORD keyindex = 1;		
				GetInteger(pElmWEP40,&keyindex,"KeyToUse");
				
				//default is set to key 1
				*dwKeyIndex = (DWORD)FAPI_FIRST_WEP_KEY;
				if(keyindex==2)
					*dwKeyIndex = FAPI_SECOND_WEP_KEY;
				else if(keyindex==3)
					*dwKeyIndex= FAPI_THIRD_WEP_KEY;
				else if(keyindex==4)
					*dwKeyIndex = FAPI_FOURTH_WEP_KEY;

				GetText(pElmWEP40,szKey1,"Key1Hex",FAPI_MAX_KEY_LENGTH_104_BIT*2 + 1);
				GetText(pElmWEP40,szKey2,"Key2Hex",FAPI_MAX_KEY_LENGTH_104_BIT*2 + 1);
				GetText(pElmWEP40,szKey3,"Key3Hex",FAPI_MAX_KEY_LENGTH_104_BIT*2 + 1);
				GetText(pElmWEP40,szKey4,"Key4Hex",FAPI_MAX_KEY_LENGTH_104_BIT*2 + 1);
				return true;
			}
		}
		return false;
	}



	DWORD GetCredentialMode()
	{
		DWORD dwCredMode = 0;
		TiXmlElement *pCredFlags = NULL; 
		pCredFlags = GetElementSafe(pElmProf,"CredentialFlags");		
		if(pCredFlags) {
			DWORD dwValue = 0;
			if(GetInteger(pCredFlags,&dwValue,"RequireUserCertificate")==0)
				if(dwValue==1)
					dwCredMode  |= FAPI_REQUIRE_USER_CERTIFICATE;

			if(GetInteger(pCredFlags,&dwValue,"SpecifyUserCertificateLocal")==0)
				if(dwValue==1)
					dwCredMode  |= FAPI_SPECIFY_USER_CERTIFICATE_LOCAL;

			if(GetInteger(pCredFlags,&dwValue,"SpecifyServerCertificateLocal")==0)
				if(dwValue==1)
					dwCredMode  |= FAPI_SPECIFY_SERVER_CERTIFICATE_LOCAL;

			if(GetInteger(pCredFlags,&dwValue,"ValidateServerCertificate")==0)
				if(dwValue==1)
					dwCredMode  |= FAPI_VALIDATE_SERVER_CERTIFICATE;

			if(GetInteger(pCredFlags,&dwValue,"EnableSecureTunnelCredentials")==0)
				if(dwValue==1)
					dwCredMode  |= FAPI_ENABLE_SECURE_TUNNEL_CREDENTIALS;
			
			if(GetInteger(pCredFlags,&dwValue,"SpecifyProfileTypeAsUserProfile")==0)
				if(dwValue==1)
					dwCredMode  |= FAPI_SPECIFY_PROFILE_TYPE_AS_USER_PROFILE;

		}
		return dwCredMode;
	}

	DWORD GetAuthenticationMode()
	{
		DWORD dwAuthMode = FAPI_AUTH_NONE;
		TiXmlElement *pAuthMode = NULL; 
		pAuthMode = GetElementSafe(pElmProf,"AuthMethod");	
		if(pAuthMode==NULL) //if first optional shortname tag is not found test with the long name
			pAuthMode = GetElementSafe(pElmProf,"AuthenticationMethod");		
		if(pAuthMode) {
			const char *szEncMode = pAuthMode->GetText();
			if(_stricmp("EAP_TLS",szEncMode)==0)
				dwAuthMode = FAPI_EAP_TLS;
			else if(_stricmp("PEAP_MSCHAPV2",szEncMode)==0)
				dwAuthMode = FAPI_PEAP_MSCHAPV2;
			else if(_stricmp("PEAP_TLS",szEncMode)==0)
				dwAuthMode = FAPI_PEAP_TLS;
			else if(_stricmp("LEAP",szEncMode)==0)
				dwAuthMode = FAPI_LEAP;
			else if(_stricmp("EAP_TTLS_CHAP",szEncMode)==0)
				dwAuthMode = FAPI_EAP_TTLS_CHAP;
			else if(_stricmp("EAP_TTLS_MSCHAP",szEncMode)==0)
				dwAuthMode = FAPI_EAP_TTLS_MSCHAP;
			else if(_stricmp("EAP_TTLS_MSCHAPV2",szEncMode)==0)
				dwAuthMode = FAPI_EAP_TTLS_MSCHAPV2;
			else if(_stricmp("EAP_TTLS_PAP",szEncMode)==0)
				dwAuthMode = FAPI_EAP_TTLS_PAP;
			else if(_stricmp("EAP_TTLS_MD5",szEncMode)==0)
				dwAuthMode = FAPI_EAP_TTLS_MD5;
			else if(_stricmp("PEAP_EAP-GTC",szEncMode)==0)
				dwAuthMode = FAPI_PEAP_GTC;
			else if(_stricmp("EAP-FAST_MSCHAPV2",szEncMode)==0)
				dwAuthMode = FAPI_EAP_FAST_MSCHAPV2;
			else if(_stricmp("EAP-FAST_TLS",szEncMode)==0)
				dwAuthMode = FAPI_EAP_FAST_TLS;
			else if(_stricmp("EAP-FAST_EAP-GTC",szEncMode)==0)
				dwAuthMode = FAPI_EAP_FAST_GTC;
			else
				dwAuthMode = FAPI_AUTH_NONE;
		}
		return dwAuthMode;
	}

	void GetCredentialCache(DWORD *dwCacheOpts,DWORD *dwTimeCacheOpts,DWORD *dwCacheRT, TCHAR* pszFirstLoginPromptTime, TCHAR* pszSecondLoginPromptTime , TCHAR* pszThirdLoginPromptTime, TCHAR* pszFourthLoginPromptTime)
	{
		TiXmlElement *pCredOpt = NULL; 
		*dwCacheOpts = 0;  //added 1.16
		*dwTimeCacheOpts = 0; //added 1.16
		*dwCacheRT = 0; //added 1.16
		pCredOpt = GetElementSafe(pElmProf,"CredentialCache");		
		if(pCredOpt) {
			DWORD dwValue = 0;
			if(GetInteger(pCredOpt,&dwValue,"OnConnect")==0)
				if(dwValue==1)
					*dwCacheOpts = FAPI_CACHE_OPTION_CONNECT;

			if(GetInteger(pCredOpt,&dwValue,"OnResume")==0)
				if(dwValue==1)
					*dwCacheOpts |= FAPI_CACHE_OPTION_RESUME;

			if(GetInteger(pCredOpt,&dwValue,"OnTime")==0)
				if(dwValue==1)
					*dwCacheOpts |= FAPI_CACHE_OPTION_TIME;

			if(GetInteger(pCredOpt,&dwValue,"TimeOption")==0) {
				if(dwValue==0)
					*dwTimeCacheOpts = FAPI_TIME_CACHE_INTERVAL;
				else if (dwValue==1)
					*dwTimeCacheOpts = FAPI_TIME_CACHE_ABSOLUTE;
			}

			GetInteger(pCredOpt,dwCacheRT,"TimeInterval");

			GetText(pCredOpt,pszFirstLoginPromptTime,"FirstLoginPromptTime",FAPI_MAX_TIME_STR_LEN);
			GetText(pCredOpt,pszSecondLoginPromptTime,"SecondLoginPromptTime",FAPI_MAX_TIME_STR_LEN);
			GetText(pCredOpt,pszThirdLoginPromptTime,"ThirdLoginPromptTime",FAPI_MAX_TIME_STR_LEN);
			GetText(pCredOpt,pszFourthLoginPromptTime,"FourthLoginPromptTime",FAPI_MAX_TIME_STR_LEN);
		}
	}

	TiXmlElement * GetElementSafe(TiXmlElement *pElement,char *szElementName)
	{
		TiXmlNode *pNode;
		pNode=NULL;
		pNode = pElement->FirstChild(szElementName);
		if(pNode!=NULL) {
			 return pNode->ToElement();
		}
		//AddLog(2,_T("Could not find tag %S"),szElementName);
		return NULL;
	}

	/***************************
	GetText Returns
	  0 Successfull parse
	 -1 Unsuccessfull parse
	****************************/
	int GetText(TiXmlElement *pElm,TCHAR *pszOut,char * szElementName, DWORD dwBufferLen)
	{
		TiXmlNode* pNode=NULL;
		pNode = pElm->FirstChild(szElementName);
		if(pNode!=NULL) {
			TiXmlElement *pElement= pNode->ToElement();
			if(pElement) {
				const char *szTxt = pElement->GetText();
				if(szTxt!=NULL) {
					if(strlen(szTxt)+1 <= dwBufferLen)
						dwBufferLen = strlen(szTxt)+1;
					else
						AddLog(1,_T("Tag &lt;%S&gt; value length is overrided, max length is %d - <br>Part of the value will only be added into the profile. "),szElementName,dwBufferLen);

					AddLog(0,_T("&lt;%S&gt; = %S"),szElementName,szTxt);

					mbstowcs(pszOut, szTxt,dwBufferLen);	
				}
				return 0;
			} //end element								
		} //end node
	//	AddLog(2,_T("Could not find tag %S"),szElementName);
		ZeroMemory(pszOut,dwBufferLen); //default fill zero
		return -1;
	}

	/***************************
	GetInteger Returns
	  0 Successfull parse
	 -1 Unsuccessfull parse
	****************************/
	int GetInteger(TiXmlElement *pElm,DWORD *dwOut,char * szElementName)
	{
		TiXmlNode* pNode=NULL;
		pNode = pElm->FirstChild(szElementName);
		if(pNode!=NULL){			
			TiXmlElement *pElement= pNode->ToElement();
			if(pElement) {
				const char *szTxt = pElement->GetText();
				if(szTxt!=NULL) {
					*dwOut = (DWORD)atol(szTxt);
					AddLog(0,_T("&lt;%S&gt; = %d"),szElementName,*dwOut);
				}
				return 0;
			}
		}
		//AddLog(2,_T("Could not find tag %S"),elementname);
		return -1;
	}


};