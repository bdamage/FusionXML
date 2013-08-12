// FusionXMLtestCE.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#define ADDPROFILE _T("AddProfile")

typedef int (WINAPI* LPFNFSYMSCRIPTPLUGIN)(const TCHAR*, DWORD, const TCHAR*);
static LPFNFSYMSCRIPTPLUGIN lpfnFXML_AddProfile = NULL;

static LPFNFSYMSCRIPTPLUGIN lpfnFXML_DelAllProfiles = NULL;
static LPFNFSYMSCRIPTPLUGIN lpfnFXML_PowerOn = NULL;
static LPFNFSYMSCRIPTPLUGIN lpfnFXML_PowerOff = NULL;
static LPFNFSYMSCRIPTPLUGIN lpfnFXML_PowerStatus = NULL;

static LPFNFSYMSCRIPTPLUGIN lpfnFXML_ExportAlLProfiles = NULL;

//FUSIONXML_API int AddProfile(SENDDEBUGMESSAGE *pfnDebug, DWORD dwDebugMask, const TCHAR *CmdLine )


int _tmain(int argc, _TCHAR* argv[])
{
	OutputDebugString(_T("CE debugging\n"));
	TCHAR szStreamXML[]  = _T("\"<?xml version=\"1.0\" encoding=\"utf-8\"?>\
		<FusionConfig>\
		<Profile name=\"test\">\
		<ESSID>Gateway1</ESSID>\
		<Country>UK</Country>\
		<IPv4Mode>STATIC</IPv4Mode>\
		<IPv4>\
		<IPAddress>10.32.64.40</IPAddress>\
		<Subnet>255.255.255.0</Subnet>\
		<Gateway>10.32.64.99</Gateway>\
		<DNS1>10.32.64.99</DNS1>\
		<WINS1>10.32.64.99</WINS1></IPv4>\
		<SecurityType>1</SecurityType>\
		<EncryptionMethod>TKIP</EncryptionMethod><Passphrase>abcdef=-3Vsdqf!rr+efgh</Passphrase></Profile></FusionConfig>\"");
//	TCHAR xmlLEAP[] = _T("\"<FusionConfig> <SetLog>0</SetLog>  <Export>1</Export>  <ExportFileName>WCS_PROFILES.REG</ExportFileName>  <Profile name=\"Enter_Your_Profile_Name_Here\">  <ESSID>Enter_Your_SSID_Here</ESSID>  <IPv4Mode>DHCP</IPv4Mode>  <SecurityType>0</SecurityType>  <AuthMethod>LEAP</AuthMethod>  <CredentialFlags>    <RequireUserCertificate>0</RequireUserCertificate>    <SpecifyUserCertificateLocal>0</SpecifyUserCertificateLocal>    <SpecifyServerCertificateLocal>0</SpecifyServerCertificateLocal>    <ValidateServerCertificate>0</ValidateServerCertificate>    <EnableSecureTunnelCredentials>0</EnableSecureTunnelCredentials>    <SpecifyProfileTypeAsUserProfile>0</SpecifyProfileTypeAsUserProfile>  </CredentialFlags>  <CredentialCache>    <OnConnect>0</OnConnect>    <OnResume>0</OnResume>    <OnTime>0</OnTime>    <TimeOption>0</TimeOption>  </CredentialCache>  <UserCredentials>    <UserName>AUTHUSERNAME</UserName>    <Password>AUTHPASSWORD</Password>    <Domain></Domain>  </UserCredentials>  <OPMode>1</OPMode>  <EncryptMethod>WEP128</EncryptMethod>  <PowerIndex>1</PowerIndex>  <TxPower>0</TxPower>  </Profile></FusionConfig>\"");	

	
	TCHAR xmlLEAP[] = _T("\"<FusionConfig><SetLog>0</SetLog><Export>1</Export><ExportFileName>WCS_PROFILES.REG</ExportFileName><Profile name=\"Enter_Your_Profile_Name_Here\"><ESSID>Enter_Your_SSID_Here</ESSID>\
					   <CredentialFlags><RequireUserCertificate>0</RequireUserCertificate>    <SpecifyUserCertificateLocal>0</SpecifyUserCertificateLocal>    <SpecifyServerCertificateLocal>0</SpecifyServerCertificateLocal>\
					   <ValidateServerCertificate>0</ValidateServerCertificate>    <EnableSecureTunnelCredentials>0</EnableSecureTunnelCredentials>    <SpecifyProfileTypeAsUserProfile>0</SpecifyProfileTypeAsUserProfile>  </CredentialFlags>  <CredentialCache>    <OnConnect>0</OnConnect><OnResume>0</OnResume><OnTime>0</OnTime>    <TimeOption>0</TimeOption>  </CredentialCache>  <UserCredentials>    <UserName>AUTHUSERNAME</UserName>    <Password>AUTHPASSWORD</Password>    <Domain></Domain>  </UserCredentials><OPMode>1</OPMode><EncryptMethod>WEP128</EncryptMethod><PowerIndex>1</PowerIndex><TxPower>0</TxPower></Profile></FusionConfig>\"");
	HINSTANCE hInstFXML = (HINSTANCE)LoadLibrary(L"FusionXML.dll");
	if(hInstFXML!=NULL) {
		OutputDebugString(_T("Found FusionXML.dll!\n"));
		lpfnFXML_AddProfile = (LPFNFSYMSCRIPTPLUGIN)GetProcAddress(hInstFXML,ADDPROFILE);
		lpfnFXML_DelAllProfiles = (LPFNFSYMSCRIPTPLUGIN)GetProcAddress(hInstFXML,_T("DeleteAllProfiles"));
		lpfnFXML_PowerOn = (LPFNFSYMSCRIPTPLUGIN)GetProcAddress(hInstFXML,_T("PowerOn"));
		lpfnFXML_PowerOff = (LPFNFSYMSCRIPTPLUGIN)GetProcAddress(hInstFXML,_T("PowerOff"));
		lpfnFXML_PowerStatus = (LPFNFSYMSCRIPTPLUGIN)GetProcAddress(hInstFXML,_T("PowerStatus"));
		lpfnFXML_ExportAlLProfiles = (LPFNFSYMSCRIPTPLUGIN)GetProcAddress(hInstFXML,_T("PowerStatus"));

		if(lpfnFXML_AddProfile){
		//	lpfnFXML_DelAllProfiles(NULL,0,NULL);
			lpfnFXML_AddProfile(NULL,0,_T("\"\\WiFiConfMaster.xml\""));
		//	lpfnFXML_AddProfile(NULL,0,_T("\"\\FusionCfgMaster.xml\""));
		//	lpfnFXML_AddProfile(NULL,0,_T("\"\\example_tkip_dhcp.xml\""));
		//	lpfnFXML_AddProfile(NULL,0,_T("\"\\example_aes_dhcp.xml\""));
			
	//		lpfnFXML_AddProfile(NULL,0,_T("\"\\example_export_test.xml\""));
	//		lpfnFXML_AddProfile(NULL,0,_T("\"\\example_leap_profile.xml\""));

		//	lpfnFXML_AddProfile(NULL,0,_T("\"\\LEAP_profile.xml\""));

		//	lpfnFXML_AddProfile(NULL,0,_T("\"\\eap_fast_profile.xml\""));
		//	lpfnFXML_AddProfile(NULL,0,_T("\"\\example_eap_fast_profile.xml\""));
		

		//	lpfnFXML_AddProfile(NULL,0,_T("\"\\open_dhcp.xml\""));
		//	lpfnFXML_AddProfile(NULL,0,_T("\"\\wep_static_ip.xml\""));
		//	lpfnFXML_AddProfile(NULL,0,_T("\"\\tkip_dhcp.xml\""));				
		//	lpfnFXML_AddProfile(NULL,0,xmlLEAP);
		}
		
		//if(lpfnFXML_PowerOn)
		//	lpfnFXML_PowerOn(NULL,0,NULL);
//		if(lpfnFXML_PowerOff)
//					lpfnFXML_PowerOff(NULL,0,NULL);
/*		if(lpfnFXML_PowerStatus)
		{
			int status = lpfnFXML_PowerStatus(NULL,0,NULL);
			if(status==0)
			{
				if(lpfnFXML_PowerOn)
					lpfnFXML_PowerOn(NULL,0,NULL);
			}
			else
			{
				if(lpfnFXML_PowerOff)
					lpfnFXML_PowerOff(NULL,0,NULL);
			}
		}
		
*/
		lpfnFXML_AddProfile = NULL;
		FreeLibrary((HMODULE)hInstFXML);
		hInstFXML = NULL;
	} else
	{
		OutputDebugString(_T("Missing FusionXML.dll!\n"));
	}

	return 0;
}

