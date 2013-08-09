#pragma once

#define FUSION_SAMPLE_MAXCOMPONENTS 32

//Data structure to hold components and versions
typedef struct tagFUSION_SAMP_VERSION_LIST
{
	DWORD dwVersionCount;
	FAPI_FusionVersionInfo  fapiVersionList[FUSION_SAMPLE_MAXCOMPONENTS];

}FUSION_SAMP_VERSION_LIST, *LPFUSION_SAMP_VERSION_LIST;


FUSION_SAMP_VERSION_LIST VersionList;

extern void AddLog(int color, const TCHAR *lpszText, ...);

class CFusionMgr
{

	TCHAR m_pszFusionVersionStr[FAPI_MAX_MODULE_VERSION_SIZE];

	//typedefs for Fusion Public API function prototypes
	typedef DWORD (WINAPI* LPFN_OPEN_FUSION_API)   (PDWORD,FAPI_ACCESS_TYPE,PTCHAR);
	typedef DWORD (WINAPI* LPFN_CLOSE_FUSION_API)  (DWORD);
	typedef	DWORD (WINAPI* LPFN_COMMAND_FUSION_API)(DWORD,DWORD,PVOID,DWORD,PVOID,DWORD, PDWORD);


	//defines globals used withing high level APIs. 
	DWORD     				m_hInstFusionDLL;
	LPFN_OPEN_FUSION_API	lpfn_OpenFusionAPI;
	LPFN_CLOSE_FUSION_API	lpfn_CloseFusionAPI;
	LPFN_COMMAND_FUSION_API	lpfn_CommandFusionAPI;

	bool m_bConnect;
	bool m_bExport;

public:
	CFusionMgr(void)
	{
		m_hInstFusionDLL      = 0;
		lpfn_OpenFusionAPI    = NULL;
		lpfn_CloseFusionAPI   = NULL;
		lpfn_CommandFusionAPI = NULL;
		m_bConnect = false;
		m_bExport = false;
		LoadAPILibrary();
		OpenAPILibrary();
	}
	~CFusionMgr(void)
	{
		CloseAPILibrary();
		UnloadAPILibrary();
	}



	/************************************************
		GetMAC(...)

		This function will only return successfully 
		if the adpater is powered.
	*************************************************/
	int GetMAC( TCHAR *szBuf, int BufSize )
	{

		AddLog(0,_T("GetMAC function was called!"));

		DWORD         dwResult;
		DWORD hAdapter = FindFirstWLANAdapter();
		FAPI_AdapterInfo fapiAdapterInf;


		if(hAdapter==0)
		{
			AddLog(1,_T("Couldn't retrieve Adapter handle!"));
			return -1;
		}
		dwResult = FAPI_SUCCESS;
				
		dwResult = lpfn_CommandFusionAPI( m_hInstFusionDLL, 
											  ADAPTER_INFO_WLAN, 
											  &hAdapter, sizeof(DWORD), 
											  &fapiAdapterInf, sizeof(FAPI_AdapterInfo), 
											  NULL);

		if(dwResult != FAPI_SUCCESS)
		{
			FusionDisplayLastError();
			AddLog(1,_T("\nError reading MAC address - Check that ActiveSync is turned off or WLAN adapter is powered on!\n"));
			return -2;
		}
		else
		{
			AddLog(0,_T("Got MAC successfully!\n"));		
		}
		TCHAR szBuffer[50];
		wsprintf(szBuffer,_T("%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X"),fapiAdapterInf.macAddr[0],fapiAdapterInf.macAddr[1],fapiAdapterInf.macAddr[2],fapiAdapterInf.macAddr[3],fapiAdapterInf.macAddr[4],fapiAdapterInf.macAddr[5]);
		_tcsncpy( szBuf, szBuffer, BufSize-1 );   
		AddLog(0,_T("MAC address on first WLAN adapter is %s"),szBuffer);

		return 0;
	}



	BOOL AddFusionProfile(PVOID pProfile)
	{
		DWORD         dwResult;
		FAPI_AddedWLANProfileParams  fapiAddedWLANProfileParams;
		dwResult = FAPI_SUCCESS;
		memset(&fapiAddedWLANProfileParams, 0x0, sizeof(fapiAddedWLANProfileParams));

		DWORD structSize = sizeof(FAPI_PROFILE_2);
		FAPI_PROFILE_2 *p = (FAPI_PROFILE_2 *)pProfile;
		FAPI_PROFILE_4 *p4 = (FAPI_PROFILE_4 *)pProfile; //for debugging purpose
		FAPI_PROFILE_6 *p6 = (FAPI_PROFILE_6 *)pProfile; //for debugging purpose
		FAPI_PROFILE_7 *p7 = (FAPI_PROFILE_7 *)pProfile; //for debugging purpose
		FAPI_PROFILE_8 *p8 = (FAPI_PROFILE_8 *)pProfile; //for debugging purpose

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

		dwResult = lpfn_CommandFusionAPI( CFusionMgr::m_hInstFusionDLL, 
											  ADD_WLAN_PROFILE, 
											  pProfile,structSize,  
											  &fapiAddedWLANProfileParams, sizeof(fapiAddedWLANProfileParams), 
											  NULL);

		if(dwResult != FAPI_SUCCESS) {
			FusionDisplayLastError();
			AddLog(1,_T("\nError adding profile!\n"));
			return FALSE;
		} else {
			AddLog(0,_T("Added profile %s successfully!\n"),fapiAddedWLANProfileParams.pszName);
			AddLog(0,_T("Profile ID %s\n"),fapiAddedWLANProfileParams.pszProfileID);

			if(m_bConnect)
				ConnectToProfile(fapiAddedWLANProfileParams.pszProfileID);

			if(m_bExport)
				ExportProfile( fapiAddedWLANProfileParams.pszProfileID);

			return TRUE;
		}			
	}

	BOOL ConnectToProfile(TCHAR *pszProfileID)
	{
		DWORD dwResult;
		FAPI_SelectAndConnectParams_1 selNConn;
		memset (&selNConn, 0, sizeof (FAPI_SelectAndConnectParams_1));

		selNConn.dwVersion = FAPI_SELECT_AND_CONNECT_VERSION;
		selNConn.dwType = FAPI_SELECT_AND_CONNECT_TYPE;
		selNConn.bPersistent = TRUE;

		memcpy (selNConn.pszProfileID,pszProfileID,FAPI_MAX_GUID_STRING_LENGTH * sizeof(TCHAR)); 
		dwResult = lpfn_CommandFusionAPI( m_hInstFusionDLL, SELECT_AND_CONNECT_WLAN_PROFILE, &selNConn,sizeof (FAPI_SelectAndConnectParams), NULL, 0 ,NULL);
		if(dwResult != FAPI_SUCCESS)
		{
			FusionDisplayLastError();
			AddLog(1,_T("\nError connecting to profile!\n"));
			return FALSE;
		} else
		{
			AddLog(1,_T("\nConnecting to profile successed!\n"));
			return TRUE;
		}
	}

	int ExportProfile(TCHAR *szGUID, TCHAR * tcszExportFilename=NULL)
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
	
		//Default profile name
		wsprintf(szFileName,_T("FusionXML_%s.reg"),szGUID);
		

		if(tcszExportFilename!=NULL)
			if(_tcslen(tcszExportFilename)!=0)
				_tcscpy(szFileName,tcszExportFilename);
		
		_tcsncpy(exppro.pszFileName,&szFileName[0],wcslen(&szFileName[0]));
		_tcsncpy(exppro.pszFilePath,&szPath[0],wcslen(&szPath[0]));
		
		DWORD         dwResult;

		dwResult = FAPI_SUCCESS;
		dwResult = lpfn_CommandFusionAPI( m_hInstFusionDLL, 
					DATA_EXPORT_OPERATION_WLAN_PROFILE, &exppro, sizeof(FAPI_ExportProfile_1),  NULL, 0, NULL);

		if(dwResult != FAPI_SUCCESS) {
			FusionDisplayLastError();
			AddLog(1,_T("\nError exporting profile!\n"));
			return FALSE;
		}
		AddLog(0,_T("Exported profile %s successfully!\n"),szGUID);		
		return TRUE;	
	}



	int ExportAllProfiles( const TCHAR *CmdLine)
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
		{
			_tcsncpy(exppro.pszFileName,&szFileName[0],wcslen(&szFileName[0]));
			_tcsncpy(exppro.pszFilePath,&szPath[0],wcslen(&szPath[0]));

		}
		_tcsncpy(exppro.pszFileName,CmdLine,wcslen(CmdLine));
		_tcsncpy(exppro.pszFilePath,&szPath[0],wcslen(&szPath[0]));

		DWORD  dwResult = FAPI_SUCCESS;
		dwResult = lpfn_CommandFusionAPI( m_hInstFusionDLL, 
					DATA_EXPORT_OPERATION_WLAN_PROFILE, &exppro, sizeof(FAPI_ExportProfile_1),  NULL, 0, NULL);

		if(dwResult != FAPI_SUCCESS)
		{
			FusionDisplayLastError();
			AddLog(1,_T("\nError exporting profiles!\n"));
			return FALSE;
		}
		AddLog(0,_T("Exported profiles successfully!\n"));		
		return TRUE;	
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
	DWORD FindFirstWLANAdapter()
	{
		DWORD   dwAdapterBufLen, dwResult,dwReturn = 0;
		PBYTE   pFusionData = NULL;
		PFAPI_AdapterIDHeader pfapiAdapterHeader=NULL;
		PFAPI_AdapterLink  pfapiAdapterLink = NULL;
			

		dwResult = lpfn_CommandFusionAPI( m_hInstFusionDLL, 
										  ADAPTER_WLAN_GET_BUFFER_SIZE, 
										  NULL, 0, 
										  &dwAdapterBufLen, sizeof(DWORD), 
										  NULL);
		if( dwResult == FAPI_SUCCESS )
		{
			pFusionData = (PBYTE)calloc( 1, dwAdapterBufLen );
			if( pFusionData != NULL)
			{
				dwResult = lpfn_CommandFusionAPI( m_hInstFusionDLL, 
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
		dwResult = lpfn_CommandFusionAPI( m_hInstFusionDLL, 
									  DELETE_WLAN_PROFILE, 
									  pszGUID,FAPI_MAX_GUID_STRING_LENGTH*2, 
									  NULL, 0, 
									  NULL);
		

		if(dwResult==FAPI_SUCCESS)
			AddLog(0,_T("Successfully deleted profile %s"),pszGUID);
		else
		{
			FusionDisplayLastError();
			AddLog(0,_T("Error code %d , Unsuccessfully deleted profile %s"),dwResult,pszGUID);
		
		}

		return dwResult;
	}


	DWORD EnumerateAndDeleteProfiles()
	{
		DWORD   dwBufLen, dwResult,dwReturn = 0;
		PBYTE   pFusionData = NULL;
		PBYTE	pNextProfile = NULL;
		PFAPI_ProfileHeader	pfapiProfileheader = NULL;
		PFAPI_ProfileLink	pfapiProfileLink = NULL;
		PFAPI_WLANProfile	pfapiWLANProfile = NULL;

		dwResult = lpfn_CommandFusionAPI( m_hInstFusionDLL, 
										  ENUMERATE_PROFILES_WLAN_GET_BUFFER_SIZE, 
										  NULL, 0, 
										  &dwBufLen, sizeof(DWORD), 
										  NULL);

		if( dwResult == FAPI_SUCCESS )
		{
			pFusionData = (PBYTE)calloc( 1, dwBufLen );
			if( pFusionData != NULL)
			{
				dwResult = lpfn_CommandFusionAPI( m_hInstFusionDLL, 
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
	* SYNOPSIS:     DWORD FusionLoadAPILibrary()
	* DESCRIPTION:  Dynamically loads fusion public API dll and get required 
	*               function pointers
	* PARAMETERS:   None
	* RETURN VALUE: FUSION_SAMP_ERROR_SUCCESS or string tabel error ID
	*******************************************************************************/
	int LoadAPILibrary()
	{
		if(m_hInstFusionDLL==0)
		{
		
			m_hInstFusionDLL = (DWORD)LoadLibrary(L"FusionPublicAPI.DLL");
			if (!m_hInstFusionDLL)
			{
				return -1;
			}

			
			lpfn_OpenFusionAPI		= (LPFN_OPEN_FUSION_API)	GetProcAddress((HMODULE)m_hInstFusionDLL, _T("OpenFusionAPI"));
			lpfn_CloseFusionAPI		= (LPFN_CLOSE_FUSION_API)	GetProcAddress((HMODULE)m_hInstFusionDLL, _T("CloseFusionAPI"));
			lpfn_CommandFusionAPI	= (LPFN_COMMAND_FUSION_API)	GetProcAddress((HMODULE)m_hInstFusionDLL, _T("CommandFusionAPI"));

			if( (!lpfn_OpenFusionAPI) || (!lpfn_CloseFusionAPI) || (!lpfn_CommandFusionAPI)  )
			{
				FreeLibrary((HMODULE)m_hInstFusionDLL);
				m_hInstFusionDLL = 0;
				lpfn_OpenFusionAPI = NULL;
				lpfn_CloseFusionAPI = NULL;
				lpfn_CommandFusionAPI = NULL;
				return -2;
			}
		}
		
		return 0;

	}


	/******************************************************************************
	* SYNOPSIS:     DWORD FusionOpenAPILibrary()
	* DESCRIPTION:  Open Fusion Public API library. 
	* PARAMETERS:   None
	* RETURN VALUE: FUSION_SAMP_ERROR_SUCCESS or string tabel error ID
	*******************************************************************************/
	DWORD OpenAPILibrary()
	{
		if( lpfn_OpenFusionAPI(&m_hInstFusionDLL,COMMAND_MODE ,L"FusionXML") != FAPI_SUCCESS )	
			return -1;
		else
			return 0;
	}

	/******************************************************************************
	* SYNOPSIS:     void  FusionCloseAPILibrary()
	* DESCRIPTION:  Close Fusion Public API library. 
	* PARAMETERS:   None
	* RETURN VALUE: None
	*******************************************************************************/
	void  CloseAPILibrary()
	{
		if(m_hInstFusionDLL!=NULL)
			lpfn_CloseFusionAPI(m_hInstFusionDLL);
		return;
	}

	/******************************************************************************
	* SYNOPSIS:     void FusionSampleUnloadAPILibrary()
	* DESCRIPTION:  Unload Fusion Public API dll
	* PARAMETERS:   None
	* RETURN VALUE: None
	*******************************************************************************/
	void UnloadAPILibrary()
	{
		if(m_hInstFusionDLL)
		{
			FreeLibrary((HMODULE)m_hInstFusionDLL);
			m_hInstFusionDLL = 0;
			lpfn_OpenFusionAPI = NULL;
			lpfn_CloseFusionAPI = NULL;
			lpfn_CommandFusionAPI = NULL;
			
		}
	}

// Output the Last Error to the log and output console
	void  FusionDisplayLastError()
	{
		TCHAR szLastError[FAPI_ERROR_TEXT_LEN / sizeof(TCHAR)];
		
		lpfn_CommandFusionAPI( m_hInstFusionDLL, 
							   ERROR_INFO_GET_LAST_ERROR, 
							   NULL, 0,
							   szLastError, FAPI_ERROR_TEXT_LEN, 
							   NULL);
		
		AddLog(1,_T("%s"),szLastError);
	}

	/******************************************************************************
	* SYNOPSIS:     void FusionSampleGetWLANVersions( LPFUSION_SAMP_VERSION_LIST pVersionList)
	* DESCRIPTION:  Get the fusion component version list
	* PARAMETERS:   pVersionList - buffer to receive component versions
	* RETURN VALUE: None. Parameter pVersionList is updated with the component versions.
	*******************************************************************************/
	void GetWLANVersions( LPFUSION_SAMP_VERSION_LIST pVersionList)
	{
		DWORD dwResult,dwVersionBufLen;
		PBYTE pFusionData;
		PFAPI_FusionVersionInfo pfapiVerInfo;
		int i;


		dwResult = lpfn_CommandFusionAPI( m_hInstFusionDLL, 
										  GET_FUSION_VERSION_BUFFER_SIZE, 
										  NULL, 0, 
										  &dwVersionBufLen, sizeof(DWORD), 
										  NULL);
		
		if( dwResult == FAPI_SUCCESS )
		{
			pFusionData = (PBYTE)calloc( 1, dwVersionBufLen );
			if( pFusionData != NULL)
			{
				dwResult = lpfn_CommandFusionAPI( m_hInstFusionDLL, 
												  GET_FUSION_VERSION_DATA, 
												  NULL, 0, 
												  pFusionData, dwVersionBufLen, 
												  NULL);
				if( dwResult == FAPI_SUCCESS )
				{
					pVersionList->dwVersionCount =  ( (PFAPI_FusionVersionHeader)pFusionData ) -> dwNumVersionInfo;
					pfapiVerInfo =  (PFAPI_FusionVersionInfo) ( pFusionData + sizeof( FAPI_FusionVersionHeader  )  );
					for(i=0; i<(int)pVersionList->dwVersionCount; i++, pfapiVerInfo++)
					{
				
						_tcscpy(pVersionList->fapiVersionList[i].pszFriendlyCompName, pfapiVerInfo -> pszFriendlyCompName);
						_tcscpy(pVersionList->fapiVersionList[i].pszVersionStr, pfapiVerInfo -> pszVersionStr);
							
						if(i==0)
						 _tcscpy(m_pszFusionVersionStr, pfapiVerInfo -> pszVersionStr);

						AddLog(0,_T("%s %s"),pVersionList->fapiVersionList[i].pszFriendlyCompName,pVersionList->fapiVersionList[i].pszVersionStr);
					}
				}
				free( pFusionData );
			}
		}
	}

};
