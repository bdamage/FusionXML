// FusionXMLtest.cpp : Defines the entry point for the console application.
// Initial code Kjell Lloyd
// Test application to quickly test features of FusionXML dll.

#include "stdafx.h"

#pragma comment(lib, "FusionXML.lib")


int _tmain(int argc, _TCHAR* argv[])
{
	TCHAR szStreamXML[] = _T("\"<?xml version=\"1.0\" encoding=\"utf-8\"?><FusionConfig><Export>1</Export><Connect>0</Connect><Profile name=\"test\"><Country>SE</Country><ESSID>abcd</ESSID><IPv4Mode>STATIC</IPv4Mode><IPv4><IPAddress>192.168.80.99</IPAddress><Subnet>255.255.255.0</Subnet><Gateway>192.168.80.1</Gateway><DNS1>192.168.80.2</DNS1><DNS2>192.168.80.3</DNS2><WINS1>192.168.80.4</WINS1></IPv4><EncryptionMethod>TKIP</EncryptionMethod><AuthMethod>PEAP_MSCHAPV2</AuthMethod><CredentialFlags><SpecifyServerCertificateLocal>1</SpecifyServerCertificateLocal><SpecifyProfileTypeAsUserProfile>0</SpecifyProfileTypeAsUserProfile></CredentialFlags><ServerCert><LocalCertFilename>GlobalSign Root CA</LocalCertFilename></ServerCert><UserCredentials><UserName></UserName><Password></Password></UserCredentials></Profile></FusionConfig>\"");
//	TCHAR szBuffer[200];

//	EnemurateAndDeleteProfiles();

	int iRet = PowerStatus(NULL,0,NULL,NULL,0);



	//DeleteFusionProfile(_T("{9B7BE8F1-055F-4D81-95F0-1A24F7CC7EC3}"));

/*	AddProfileW(_T("\"\\peap_mschapv2.xml\""));

	AddProfileW(szStreamXML);
	
	AddProfileW(_T("\"\\WEP128profile.xml\""));
*/
	//ExportAllProfilesW();

	//AddProfileW(_T("\"\\eap_fast_profile.xml\""));
	//EnemurateAndDeleteProfiles();

	

	//AddProfileW(_T("\\Application\\empty_DNS_string.xml"));
	
//	GetMAC( 0, 0, NULL, szBuffer, sizeof(szBuffer));	
	return 0;
}

