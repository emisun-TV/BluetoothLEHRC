// 
// BLEHeartRateC.cpp : Defines the exported functions for the DLL application.
// 
// NOTE: Ensure that you have paired the HR BLE device with the computer
//


#include "stdafx.h"
#include "BLEHeartRateC.h"
#define AES128
#define ECB 1
#include "aes.hpp"

#include <stdio.h>
#include <iostream>
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <regstr.h>
#include <bthdef.h>
#include <Bluetoothleapis.h>
#include <string>
#include <chrono>
#include <comdef.h>
#include <system_error>


#pragma comment(lib, "SetupAPI")
#pragma comment(lib, "BluetoothApis.lib")

#define HEART_SERVICE_UUID "{0000180D-0000-1000-8000-00805F9B34FB}"
#define DEVICE_SERVICE_UUID "{0000180A-0000-1000-8000-00805F9B34FB}"
#define AUTH_MI_BAND_3_SERVICE_UUID "{0000FEE1-0000-1000-8000-00805F9B34FB}"


extern "C" {

	/////////////////////////////////////////////////////////////////////
	// For reporting and logging with exported functions
	/////////////////////////////////////////////////////////////////////

	std::string m_ProcessReport;

	void ReportLine(const char* line) {
		printf(line);
		printf("\n");
		m_ProcessReport.append("BLEHeartRateC Log: ");
		m_ProcessReport.append(line);
		m_ProcessReport.append("\n");
	}

	void ReportHr(const char* intro, HRESULT hr)
	{
		std::string h = std::system_category().message(hr);
		h.pop_back();
		std::string mh(intro);
		mh.append(h);
		ReportLine(mh.c_str());
	}

	void ReportNumber(const char* intro, const int number){
		ReportLine((std::string(intro) + std::to_string(number)).c_str());
	}

	void ClearReport() { 
		m_ProcessReport.clear();
	}

	int GetReportSize() {
		return m_ProcessReport.size();
	}

	//char* GetReport(bool clear) {
	//	ULONG ulSize = m_ProcessReport.length() + sizeof(char);
	//	char* pszReturn = NULL;

	//	pszReturn = (char*)::CoTaskMemAlloc(ulSize);

	//	strcpy_s(pszReturn, ulSize, m_ProcessReport.c_str());

	//	if (clear)
	//		m_ProcessReport.clear();

	//	return pszReturn;
	//}

	__declspec(dllexport) char* GetReport() {
		ULONG ulSize = m_ProcessReport.length() + sizeof(char);
		char* pszReturn = NULL;

		pszReturn = (char*)::CoTaskMemAlloc(ulSize);
		// Copy the contents of szSampleString
		// to the memory pointed to by pszReturn.
		strcpy_s(pszReturn, ulSize, m_ProcessReport.c_str());
		// Return pszReturn.
		m_ProcessReport.clear();
		return pszReturn;
	}

	/////////////////////////////////////////////////////////////////////
	// Variables for connecting ble device
	/////////////////////////////////////////////////////////////////////

	HANDLE m_BLEDevice = NULL;
	HANDLE m_AuthDevice = NULL;
	BLUETOOTH_GATT_EVENT_HANDLE m_NotificationEventHandle = NULL;

	int m_LastHeartRate = 0;	


	/////////////////////////////////////////////////////////////////////
	// Methods for connecting ble device
	/////////////////////////////////////////////////////////////////////

	// callbac function for heartrate event
	void CALLBACK Notify(BTH_LE_GATT_EVENT_TYPE EventType, PVOID EventOutParameter, PVOID Context)
	{
		PBLUETOOTH_GATT_VALUE_CHANGED_EVENT ValueChangedEventParameters = (PBLUETOOTH_GATT_VALUE_CHANGED_EVENT)EventOutParameter;

		HRESULT hr = S_OK;
		if (0 == ValueChangedEventParameters->CharacteristicValue->DataSize) {
			hr = E_FAIL;
		}
		else {
			if (0x01 == (ValueChangedEventParameters->CharacteristicValue->Data[0] & 0x01)) {
				m_LastHeartRate = ValueChangedEventParameters->CharacteristicValue->Data[1] * 256 + ValueChangedEventParameters->CharacteristicValue->Data[2];
			}
			else {
				m_LastHeartRate = ValueChangedEventParameters->CharacteristicValue->Data[1];
			}
		}

		if (m_ProcessReport.length() > 10)
			ClearReport();

		ReportNumber("Recieved heart rate update : ", m_LastHeartRate);
	}

	//this function works to get a handle for a BLE device based on its GUID
	//copied from http://social.msdn.microsoft.com/Forums/windowshardware/en-US/e5e1058d-5a64-4e60-b8e2-0ce327c13058/erroraccessdenied-error-when-trying-to-receive-data-from-bluetooth-low-energy-devices?forum=wdk
	//credits to Andrey_sh
	HANDLE GetHandle(__in GUID AGuid)
	{
		HDEVINFO hDI;
		SP_DEVICE_INTERFACE_DATA did;
		SP_DEVINFO_DATA dd;
		GUID BluetoothInterfaceGUID = AGuid;
		HANDLE hComm = NULL;

		hDI = SetupDiGetClassDevs(&BluetoothInterfaceGUID, NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
		
		if (hDI == INVALID_HANDLE_VALUE) return NULL;

		did.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
		dd.cbSize = sizeof(SP_DEVINFO_DATA);

		for (DWORD i = 0; SetupDiEnumDeviceInterfaces(hDI, NULL, &BluetoothInterfaceGUID, i, &did); i++)
		{
			SP_DEVICE_INTERFACE_DETAIL_DATA DeviceInterfaceDetailData;
			
			DeviceInterfaceDetailData.cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

			DWORD size = 0;

			if (!SetupDiGetDeviceInterfaceDetail(hDI, &did, NULL, 0, &size, 0))
			{
				int err = GetLastError();

				if (err == ERROR_NO_MORE_ITEMS) break;

				PSP_DEVICE_INTERFACE_DETAIL_DATA pInterfaceDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)GlobalAlloc(GPTR, size);
				
				pInterfaceDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

				if (!SetupDiGetDeviceInterfaceDetail(hDI, &did, pInterfaceDetailData, size, &size, &dd))
					break;

				hComm = CreateFile(pInterfaceDetailData->DevicePath, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

				GlobalFree(pInterfaceDetailData);
			}
		}

		SetupDiDestroyDeviceInfoList(hDI);
		return hComm;
	}

	USHORT GetServices(HANDLE device, PBTH_LE_GATT_SERVICE &serviceBuffer) {
		USHORT serviceBufferCount;

		HRESULT hr = BluetoothGATTGetServices(device, 0, NULL, &serviceBufferCount, BLUETOOTH_GATT_FLAG_NONE);

		if (HRESULT_FROM_WIN32(ERROR_MORE_DATA) != hr) {
			ReportHr("Service could not be found : ", hr);
			return 0;
		}

		serviceBuffer = (PBTH_LE_GATT_SERVICE)malloc(sizeof(BTH_LE_GATT_SERVICE) * serviceBufferCount);

		if (NULL == serviceBuffer) {
			ReportLine("Service buffer out of memory");
			return 0;
		}
		else
			RtlZeroMemory(serviceBuffer, sizeof(BTH_LE_GATT_SERVICE) * serviceBufferCount);

		USHORT numServices;

		hr = BluetoothGATTGetServices(device, serviceBufferCount, serviceBuffer, &numServices, BLUETOOTH_GATT_FLAG_NONE);

		if (S_OK != hr) {
			ReportHr("Unable to connect to service : ", hr);
			return false;
		}

		ReportNumber("Services search result: ", numServices);
		return numServices;
	}

	USHORT GetCharacteristics(HANDLE device, PBTH_LE_GATT_SERVICE serviceBuffer, PBTH_LE_GATT_CHARACTERISTIC &characteristicsBuffer) {

		USHORT charBufferSize;
		HRESULT hr = BluetoothGATTGetCharacteristics(device, serviceBuffer, 0, NULL, &charBufferSize, BLUETOOTH_GATT_FLAG_NONE);

		if (HRESULT_FROM_WIN32(ERROR_MORE_DATA) != hr) {
			ReportHr("Characteristics could not be found : ", hr);
			return 0;
		}
		else
			ReportNumber("Characteristics buffer result: ", charBufferSize);

		USHORT numChars = 0;
		if (charBufferSize > 0) {
			characteristicsBuffer = (PBTH_LE_GATT_CHARACTERISTIC)malloc(charBufferSize * sizeof(BTH_LE_GATT_CHARACTERISTIC));

			if (NULL == characteristicsBuffer) {
				ReportLine("Characteristic buffer out of memory");
				return 0;
			}
			else
				RtlZeroMemory(characteristicsBuffer, charBufferSize * sizeof(BTH_LE_GATT_CHARACTERISTIC));

			// Retrieve Characteristics

			hr = BluetoothGATTGetCharacteristics(device, serviceBuffer, charBufferSize, characteristicsBuffer, &numChars, BLUETOOTH_GATT_FLAG_NONE);

			if (S_OK != hr) {
				ReportHr("Unable to get characteristics : ", hr);
				return 0;
			}

			if (numChars != charBufferSize) {
				ReportHr("Characteristics buffer sizes don't match : ", hr);
				return 0;
			}
		}
		else {
			ReportLine("No characteristics was found");
			return 0;
		}

		ReportNumber("Characteristics search result: ", numChars);
		return numChars;
	}

	bool SetCharacteristicValue(HANDLE device, PBTH_LE_GATT_CHARACTERISTIC characteristic, PBTH_LE_GATT_CHARACTERISTIC_VALUE newValue)
	{
		// Set the new characteristic value
		HRESULT hr = BluetoothGATTSetCharacteristicValue(device, characteristic, newValue, NULL, BLUETOOTH_GATT_FLAG_NONE);

		if (hr != S_OK) {
			ReportHr("Unable to write characteristic : ", hr);
			return false;
		}
		ReportHr("Finish write to characteristic : ", hr);
		return true;
	}

	bool SetCharacteristicValueNoResponse(HANDLE device, PBTH_LE_GATT_CHARACTERISTIC characteristic, PBTH_LE_GATT_CHARACTERISTIC_VALUE newValue)
	{
		// Set the new characteristic value
		HRESULT hr = BluetoothGATTSetCharacteristicValue(device, characteristic, newValue, NULL, BLUETOOTH_GATT_FLAG_WRITE_WITHOUT_RESPONSE);

		if (hr != S_OK) {
			ReportHr("Unable to write characteristic : ", hr);
			return false;
		}
		ReportHr("Finish write to characteristic : ", hr);
		return true;
	}

	bool SetCharacteristicCallback(HANDLE device, PBTH_LE_GATT_CHARACTERISTIC characteristic, PFNBLUETOOTH_GATT_EVENT_CALLBACK callback, BLUETOOTH_GATT_EVENT_HANDLE *eventHandle)
	{
		// set the appropriate callback function when the descriptor change value
		if (characteristic->IsNotifiable) {
			BLUETOOTH_GATT_VALUE_CHANGED_EVENT_REGISTRATION EventParameterIn;
			EventParameterIn.Characteristics[0] = *characteristic;
			EventParameterIn.NumCharacteristics = 1;
			HRESULT hr = BluetoothGATTRegisterEvent(device, CharacteristicValueChangedEvent, (PVOID)&EventParameterIn, callback, NULL, eventHandle, BLUETOOTH_GATT_FLAG_NONE);

			if (S_OK != hr) {
				ReportHr("Failed to subscribe to notification : ", hr);
				return false;
			}
			ReportLine("Successfully subscribed to notification");
			return true;
		}
		ReportLine("Failed to subscribe to notification, characteristic is not notifiable");
		return false;
	}

	USHORT GetDescriptors(HANDLE device, PBTH_LE_GATT_CHARACTERISTIC characteristic, PBTH_LE_GATT_DESCRIPTOR &descriptorBuffer)
	{
		USHORT descriptorBufferSize;
		HRESULT hr = BluetoothGATTGetDescriptors(device, characteristic, 0, NULL, &descriptorBufferSize, BLUETOOTH_GATT_FLAG_NONE);

		if (HRESULT_FROM_WIN32(ERROR_MORE_DATA) != hr) {
			ReportHr("Descriptors could not be found : ", hr);
			return 0;
		}
		else
			ReportNumber("Descriptor buffer result: ", descriptorBufferSize);

		descriptorBuffer = (PBTH_LE_GATT_DESCRIPTOR)malloc(descriptorBufferSize * sizeof(BTH_LE_GATT_DESCRIPTOR));

		if (NULL == descriptorBuffer) {
			ReportLine("Descriptor buffer out of memory");
			return 0;
		}
		else
			RtlZeroMemory(descriptorBuffer, descriptorBufferSize);

		USHORT numDescriptors;
		hr = BluetoothGATTGetDescriptors(device, characteristic, descriptorBufferSize, descriptorBuffer, &numDescriptors, BLUETOOTH_GATT_FLAG_NONE);

		if (S_OK != hr) {
			ReportHr("Unable to get descriptors : ", hr);
			return 0;
		}

		if (numDescriptors != descriptorBufferSize) {
			ReportHr("Descriptors buffer sizes don't match : ", hr);
			return 0;
		}

		ReportNumber("Descriptor search results: ", numDescriptors);
		return numDescriptors;
	}

	USHORT GetDescriptorValues(HANDLE device, PBTH_LE_GATT_DESCRIPTOR descriptor, PBTH_LE_GATT_DESCRIPTOR_VALUE &descriptorValueBuffer)
	{
		USHORT descValueDataSize = 0;
		HRESULT hr = BluetoothGATTGetDescriptorValue(device, descriptor, 0, NULL, &descValueDataSize, BLUETOOTH_GATT_FLAG_NONE);

		if (HRESULT_FROM_WIN32(ERROR_MORE_DATA) != hr) {
			ReportHr("Descriptor could not be found : ", hr);
			return 0;
		}

		descriptorValueBuffer = (PBTH_LE_GATT_DESCRIPTOR_VALUE)malloc(descValueDataSize);

		if (NULL == descriptorValueBuffer) {
			ReportLine("Descriptor value buffer out of memory");
			return 0;
		}
		else
			RtlZeroMemory(descriptorValueBuffer, descValueDataSize);

		// Retrieve the Descriptor Values
		USHORT numDescriptorValues;
		hr = BluetoothGATTGetDescriptorValue(device, descriptor, (ULONG)descValueDataSize, descriptorValueBuffer, &numDescriptorValues, BLUETOOTH_GATT_FLAG_NONE);
		if (S_OK != hr) {
			ReportHr("Failed to get descriptor value : ", hr);
			return 0;
		}

		ReportNumber("DescriptorValue search results: ", numDescriptorValues);
		return numDescriptorValues;
	}

	bool SetDescriptorValue(HANDLE device, PBTH_LE_GATT_DESCRIPTOR descriptor, BTH_LE_GATT_DESCRIPTOR_VALUE newValue)
	{
		HRESULT hr = BluetoothGATTSetDescriptorValue(device, descriptor, &newValue, BLUETOOTH_GATT_FLAG_NONE);
		if (S_OK != hr) {
			ReportHr("Failed to set description value: ", hr);
			return false;
		}

		ReportLine("Success to set description value");
		return true;
	}

	void Encrypt(BYTE key[16], BYTE plain[16], BYTE *out16Bytes)
	{
		struct AES_ctx ctx;
		AES_init_ctx(&ctx, key);
		AES_ECB_encrypt(&ctx, plain);
		memcmp(out16Bytes, plain, 16);
	}

	void TryAuthenticateMiBand()
	{
		ReportLine("AUTHENTICATION MI BAND 3 ENTER");

		GUID AGuid;
		CLSIDFromString(TEXT(AUTH_MI_BAND_3_SERVICE_UUID), &AGuid);
		m_AuthDevice = GetHandle(AGuid);

		PBTH_LE_GATT_SERVICE serviceBuffer = NULL;
		USHORT servicesNum = GetServices(m_AuthDevice, serviceBuffer);
		if (servicesNum <= 0)
			return;

		PBTH_LE_GATT_CHARACTERISTIC characteristicsBuffer = NULL;
		USHORT characteristicsNum = GetCharacteristics(m_AuthDevice, serviceBuffer, characteristicsBuffer);
		if (characteristicsNum <= 0)
			return;

		for (int ii = 0; ii < characteristicsNum; ii++)
		{
			PBTH_LE_GATT_CHARACTERISTIC currentCharacteristic = &characteristicsBuffer[ii];
			if (currentCharacteristic->CharacteristicUuid.Value.ShortUuid == 9)
			{
				PBTH_LE_GATT_DESCRIPTOR descriptorBuffer = NULL;
				USHORT descriptorsNum = GetDescriptors(m_AuthDevice, currentCharacteristic, descriptorBuffer);
				if (descriptorsNum > 0)
				{
					// register notification for key response
					static BYTE byte16Key[16];
					static bool validated = false;
					static bool responded = false;
					static bool accepted = false;
					BLUETOOTH_GATT_EVENT_HANDLE responseHandle = NULL;
					SetCharacteristicCallback(m_AuthDevice, currentCharacteristic, [](BTH_LE_GATT_EVENT_TYPE EventType, PVOID EventOutParameter, PVOID Context) {

						PBLUETOOTH_GATT_VALUE_CHANGED_EVENT parameters = (PBLUETOOTH_GATT_VALUE_CHANGED_EVENT)EventOutParameter;

						BYTE authResponse = 0x10;
						BYTE authSendKey = 0x01;
						BYTE authRequestRandomAuthNumber = 0x02;
						BYTE authRequestEncryptedKey = 0x03;
						BYTE authSuccess = 0x01;
						BYTE authFail = 0x04;

						if (parameters->CharacteristicValue->Data[0] == authResponse) {
							if (parameters->CharacteristicValue->Data[1] == authSendKey && parameters->CharacteristicValue->Data[2] == authSuccess)
							{
								ReportLine("Touch verification success");
								validated = true;
							}
							else if (parameters->CharacteristicValue->Data[1] == authRequestRandomAuthNumber && parameters->CharacteristicValue->Data[2] == authSuccess)
							{
								int bytePos = 0;
								for (int ll = parameters->CharacteristicValue->DataSize - 16; ll < parameters->CharacteristicValue->DataSize; ll++)
									byte16Key[bytePos++] = parameters->CharacteristicValue->Data[ll];
								responded = true;
								ReportLine("Recieved random key success");
							}
							else if (parameters->CharacteristicValue->Data[1] == authRequestEncryptedKey && parameters->CharacteristicValue->Data[2] == authSuccess)
							{
								accepted = true;
								ReportLine("Authorization success");
							}
						}
					}, &responseHandle);

					{
						// pretty sure this is same as 2 byte sending to enable auth notifications
						BTH_LE_GATT_DESCRIPTOR_VALUE newValue;
						RtlZeroMemory(&newValue, sizeof(BTH_LE_GATT_DESCRIPTOR_VALUE));
						newValue.DescriptorType = ClientCharacteristicConfiguration;
						newValue.ClientCharacteristicConfiguration.IsSubscribeToNotification = TRUE;
						SetDescriptorValue(m_AuthDevice, descriptorBuffer, newValue);
					}
					{
						// sending out secret key
						BYTE byteData[]{ 0x01, 0x00, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45 };

						size_t required_size = sizeof(BTH_LE_GATT_CHARACTERISTIC_VALUE) + sizeof(byteData);
						PBTH_LE_GATT_CHARACTERISTIC_VALUE newValue = (PBTH_LE_GATT_CHARACTERISTIC_VALUE)malloc(required_size);
						RtlZeroMemory(newValue, required_size);
						newValue->DataSize = sizeof(byteData);
						memcpy(newValue->Data, byteData, sizeof(byteData));
						SetCharacteristicValueNoResponse(m_AuthDevice, currentCharacteristic, newValue);
					}

					// wait timeout 2 sec for response to auth level 1
					std::chrono::system_clock::time_point tp = std::chrono::system_clock::now();
					while (true) {
						if (validated || std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - tp).count() >= 6000)
							break;
					}

					{
						// request a random key
						BYTE byteData[]{ 0x02, 0x08 };
						size_t required_size = sizeof(BTH_LE_GATT_CHARACTERISTIC_VALUE) + sizeof(byteData);
						PBTH_LE_GATT_CHARACTERISTIC_VALUE newValue = (PBTH_LE_GATT_CHARACTERISTIC_VALUE)malloc(required_size);
						RtlZeroMemory(newValue, required_size);
						newValue->DataSize = sizeof(byteData);
						memcpy(newValue->Data, byteData, sizeof(byteData));
						SetCharacteristicValueNoResponse(m_AuthDevice, currentCharacteristic, newValue);
					}

					// wait timeout 2 sec for response to auth level 1
					tp = std::chrono::system_clock::now();
					while (true) {
						if (responded || std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - tp).count() >= 6000)
							break;
					}

					// if we have gained a response keep going otherwise exit
					if (responded) {
						BYTE keyData[]{ 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45 };
						BYTE * out16 = new BYTE[16];
						Encrypt(keyData, byte16Key, out16);

						// sending encrypted key
						BYTE byteData[18];
						byteData[0] = 0x03; byteData[1] = 0x08;
						for (int bb = 2; bb < 18; bb++) byteData[bb] = byte16Key[bb - 2];
						size_t required_size = sizeof(BTH_LE_GATT_CHARACTERISTIC_VALUE) + sizeof(byteData);
						PBTH_LE_GATT_CHARACTERISTIC_VALUE newValue = (PBTH_LE_GATT_CHARACTERISTIC_VALUE)malloc(required_size);
						RtlZeroMemory(newValue, required_size);
						newValue->DataSize = sizeof(byteData);
						memcpy(newValue->Data, byteData, sizeof(byteData));
						SetCharacteristicValueNoResponse(m_AuthDevice, currentCharacteristic, newValue);
					}

					// wait timeout 2 sec for response to auth level 1
					tp = std::chrono::system_clock::now();
					while (true) {
						if (accepted || std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - tp).count() >= 6000)
							break;
					}

					if (responseHandle != NULL)
						BluetoothGATTUnregisterEvent(responseHandle, BLUETOOTH_GATT_FLAG_NONE);
					break;
				}
			}
		}

		ReportLine("AUTHENTICATION MI BAND 3 EXIT");
	}

	void TryAuthenticate()
	{
		// we should check better for each devices here instead of just trying to auth mi bands
		TryAuthenticateMiBand();
	}

	// try to connect 
	bool ConnectToHeartDevice()
	{
		ClearReport();

		//////////////////////////////////////////////////////////////////////////////////////////////
		// Step 1: Get the BLE device handle
		GUID AGuid;
		CLSIDFromString(TEXT(HEART_SERVICE_UUID), &AGuid);
		m_BLEDevice = GetHandle(AGuid);

		//////////////////////////////////////////////////////////////////////////////////////////////
		// Step 2: Get services
		PBTH_LE_GATT_SERVICE serviceBuffer = NULL;
		USHORT servicesNum = GetServices(m_BLEDevice, serviceBuffer);
		if (servicesNum <= 0)
			return false;

		//////////////////////////////////////////////////////////////////////////////////////////////
		// Step 3: Get Charactersitics
		PBTH_LE_GATT_CHARACTERISTIC characteristicsBuffer = NULL;
		USHORT characteristicsNum = GetCharacteristics(m_BLEDevice, serviceBuffer, characteristicsBuffer);
		if (characteristicsNum <= 0)
			return false;

		//////////////////////////////////////////////////////////////////////////////////////////////
		// Step 4: Get Descriptors
		// For each found characteristic, search to find its descriptors
		for (int ii = 0; ii < characteristicsNum; ii++) {
			
			ReportNumber("Searching descriptors on characteristic index: ", ii);
			PBTH_LE_GATT_CHARACTERISTIC currentCharacteristic = &characteristicsBuffer[ii];

			PBTH_LE_GATT_DESCRIPTOR descriptorBuffer = NULL;
			USHORT descriptorsNum = GetDescriptors(m_BLEDevice, currentCharacteristic, descriptorBuffer);

			if (currentCharacteristic->IsNotifiable) {
				if (descriptorsNum > 0) {

					PBTH_LE_GATT_DESCRIPTOR currentDescriptor = &descriptorBuffer[0];

					PBTH_LE_GATT_DESCRIPTOR_VALUE descriptorValueBuffer = NULL;
					USHORT descriptorValuesNum = GetDescriptorValues(m_BLEDevice, currentDescriptor, descriptorValueBuffer);

					BTH_LE_GATT_DESCRIPTOR_VALUE newValue;
					RtlZeroMemory(&newValue, sizeof(BTH_LE_GATT_DESCRIPTOR_VALUE));
					newValue.DescriptorType = ClientCharacteristicConfiguration;
					newValue.ClientCharacteristicConfiguration.IsSubscribeToNotification = TRUE;
					if (!SetDescriptorValue(m_BLEDevice, currentDescriptor, newValue))
						return false;
				}

				SetCharacteristicCallback(m_BLEDevice, currentCharacteristic, Notify, &m_NotificationEventHandle);
			}

			if (currentCharacteristic->IsWritable) {
				//UCHAR valueData = '2';
				//BTH_LE_GATT_CHARACTERISTIC_VALUE newValue;
				//RtlZeroMemory(&newValue, (sizeof(newValue)));
				//newValue.DataSize = sizeof(valueData);
				//newValue.Data[0] = (UCHAR)&valueData;
				//SetCharacteristicValue(m_BLEDevice, currentCharacteristic, &newValue);
			}
		}

		return true;
	}

	void Disconnect() {
		if (m_NotificationEventHandle != NULL)
		{
			HRESULT hr = BluetoothGATTUnregisterEvent(m_NotificationEventHandle, BLUETOOTH_GATT_FLAG_NONE);
			if (S_OK != hr)
				ReportHr("Failed to unsubscribe notification : ", hr);
			else
				ReportLine("Successfully unsubscribe notification");
		}
		if (m_BLEDevice != NULL)
			CloseHandle(m_BLEDevice);
		if (m_AuthDevice != NULL)
			CloseHandle(m_AuthDevice);
	}

	bool Connect()
	{
		if (ConnectToHeartDevice())
			return true;
		Disconnect();
		TryAuthenticate();
		if (ConnectToHeartDevice())
			return true;
		Disconnect();
		return false;
	}

	int HeartRate() {
		return m_LastHeartRate;
	}
}