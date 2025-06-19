//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

#include <xdpapi.h>
#include <netiodef.h>
#include <winsock2.h>

#include <stdio.h>

//
// Directly include some C++ headers that produce benign compiler warnings.
//
#pragma warning(push)
#pragma warning(disable:5252) // Multiple different types resulted in the same XFG type-hash D275361C54538B70; the PDB will only record information for one of them
#include <xlocnum>
#include <xlocale>
#pragma warning(pop)

#include <CppUnitTest.h>
#include <fntrace.h>

#include "xdptest.h"
#include "tests.h"
#include "util.h"
#include "tests.tmh"
#include "netport.h"


//
// Define a test method for a feature not yet officially released.
// Unfortunately, the vstest.console.exe runner seems unable to filter on
// arbitrary properties, so mark prerelease as priority 1.
//
#define TEST_METHOD_PRERELEASE(_Name) \
    BEGIN_TEST_METHOD_ATTRIBUTE(_Name) \
        TEST_PRIORITY(1) \
    END_TEST_METHOD_ATTRIBUTE() \
    TEST_METHOD(_Name)

//
// Test suite(s).
//

//
// Ensure our build system is defaulting to the latest supported API version.
//
C_ASSERT(XDP_API_VERSION == XDP_API_VERSION_LATEST);

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

VOID
StopTest()
{
    Assert::Fail(L"Stop test execution.");
}

VOID
LogTestFailure(
    _In_z_ PCWSTR File,
    _In_z_ PCWSTR Function,
    INT Line,
    _Printf_format_string_ PCWSTR Format,
    ...
    )
{
    static const INT Size = 128;
    WCHAR Buffer[Size];

    UNREFERENCED_PARAMETER(File);
    UNREFERENCED_PARAMETER(Function);
    UNREFERENCED_PARAMETER(Line);

    va_list Args;
    va_start(Args, Format);
    _vsnwprintf_s(Buffer, Size, _TRUNCATE, Format, Args);
    va_end(Args);

    TraceError("%S", Buffer);
    Logger::WriteMessage(Buffer);
}

VOID
LogTestWarning(
    _In_z_ PCWSTR File,
    _In_z_ PCWSTR Function,
    INT Line,
    _Printf_format_string_ PCWSTR Format,
    ...
    )
{
    static const INT Size = 128;
    WCHAR Buffer[Size];

    UNREFERENCED_PARAMETER(File);
    UNREFERENCED_PARAMETER(Function);
    UNREFERENCED_PARAMETER(Line);

    va_list Args;
    va_start(Args, Format);
    _vsnwprintf_s(Buffer, Size, _TRUNCATE, Format, Args);
    va_end(Args);

    TraceWarn("%S", Buffer);
    Logger::WriteMessage(Buffer);
}

BOOL CompareEthHeader(void* ref, void* target) {
	if (ref == NULL || target == NULL) {
		return FALSE;
	}
	ETHERNET_HEADER* refHeader = (ETHERNET_HEADER*)ref;
	ETHERNET_HEADER* targetHeader = (ETHERNET_HEADER*)target;
	if (memcmp(&(refHeader->Destination), &(targetHeader->Destination), sizeof(refHeader->Destination)) != 0) {
		Assert::Fail(L"Destination MAC address mismatch.");
	}
	if (memcmp(&(refHeader->Source), &(targetHeader->Source), sizeof(refHeader->Source)) != 0) {
		Assert::Fail(L"Source MAC address mismatch.");
	}
	if (refHeader->Type != targetHeader->Type) {
		Assert::Fail(L"Ethernet Type mismatch.");
	}
	return TRUE;
}

BOOL CompareIpHeader(void* ref, void* target) 
{
	if (ref == NULL || target == NULL) {
		return FALSE;
	}
	IPV4_HEADER* refHeader = (IPV4_HEADER*)ref;
	IPV4_HEADER* targetHeader = (IPV4_HEADER*)target;
	if (refHeader->VersionAndHeaderLength != targetHeader->VersionAndHeaderLength) {
		Assert::Fail(L"VersionAndHeaderLength mismatch.");
	}
	if (refHeader->TypeOfServiceAndEcnField != targetHeader->TypeOfServiceAndEcnField) {
		Assert::Fail(L"TypeOfServiceAndEcnField mismatch.");
	}
	if (refHeader->TotalLength != targetHeader->TotalLength) {
		Assert::Fail(L"TotalLength mismatch.");
	}
	if (refHeader->Identification != targetHeader->Identification) {
		Assert::Fail(L"Identification mismatch.");
	}
	if (refHeader->FlagsAndOffset != targetHeader->FlagsAndOffset) {
		Assert::Fail(L"FlagsAndOffset mismatch.");
	}
	if (refHeader->TimeToLive != targetHeader->TimeToLive) {
		Assert::Fail(L"TimeToLive mismatch.");
	}
	if (refHeader->Protocol != targetHeader->Protocol) {
		Assert::Fail(L"Protocol mismatch.");
	}
	if (refHeader->HeaderChecksum != targetHeader->HeaderChecksum) {
		Assert::Fail(L"HeaderChecksum mismatch.");
	}
	if (memcmp(&(refHeader->SourceAddress), &(targetHeader->SourceAddress), sizeof(refHeader->SourceAddress)) != 0) {
		Assert::Fail(L"SourceAddress mismatch.");
	}
	if (memcmp(&(refHeader->DestinationAddress), &(targetHeader->DestinationAddress), sizeof(refHeader->DestinationAddress)) != 0) {
		Assert::Fail(L"DestinationAddress mismatch.");
	}
	return TRUE;
}

BOOL CompareUdpHeader(void* ref, void* target, BOOL skipchecksum=FALSE) {
	if (ref == NULL || target == NULL) {
		return FALSE;
	}
	UDP_HDR* refHeader = (UDP_HDR*)ref;
	UDP_HDR* targetHeader = (UDP_HDR*)target;
	if (refHeader->uh_sport != targetHeader->uh_sport) {
		Assert::Fail(L"Source port mismatch.");
	}
	if (refHeader->uh_dport != targetHeader->uh_dport) {
		Assert::Fail(L"Destination port mismatch.");
	}
	if (refHeader->uh_ulen != targetHeader->uh_ulen) {
		Assert::Fail(L"UDP length mismatch.");
	}
	//if(!skipchecksum && refHeader->uh_sum == 0 && targetHeader->uh_sum == 0) {
	if(!skipchecksum ) {
		// Both checksums are zero, which is valid for UDP packets without checksum.
		if (refHeader->uh_sum != targetHeader->uh_sum) {
			Assert::Fail(L"UDP checksum mismatch.");
		}
	}
	return TRUE;
}

namespace UnitTestExample
{
    TEST_CLASS(PacketTests)
    {
    public:
        TEST_METHOD(TestPacket_UDP_IPV4_InitUdpPacket) {
            char refBuffer[] = "123456789abccba98765432108004500003c000000000111a2d00a0201720a02016c10e104d20028d3090000000000000000000000000000000000000000000000000000000000000000\0";
            UINT32 refSize = (UINT32)strlen(refBuffer);
			BYTE* loadBuffer = (BYTE*)malloc(refSize/2);

            if (loadBuffer != NULL) {
                HexStringToByte(loadBuffer, refSize, refBuffer);
            }
            BYTE* mtuBuffer = NULL;
            UINT32 PacketLength = 0;
            mtuBuffer = (BYTE*)InitUdpPacket("cb-a9-87-65-43-21", "10.2.1.114", 4321, "12-34-56-78-9a-bc", "10.2.1.108", 1234, 32, PacketLength);

            Assert::IsNotNull(mtuBuffer);
            if (loadBuffer != NULL) {
				for (UINT32 i = 0; i < refSize/2; i++) {
                    Assert::AreEqual(loadBuffer[i], mtuBuffer[i]);
				}
                free(loadBuffer);
            }
            if (mtuBuffer != NULL) {
                free(mtuBuffer);
            }
        }
        
		TEST_METHOD(TestDynamicPacket_UDP_IPV4_Set_Assign) {
            const UINT32 kPacketSize = 74;
            const UINT32 kPayloadLength = 32;
			char refBuffer[] = "123456789abccba98765432108004500003c000000000111a2d00a0201720a02016c10e104d20028d3090000000000000000000000000000000000000000000000000000000000000000\0";
            UINT32 refSize = (UINT32)strlen(refBuffer);
            UINT32 mtuLength = refSize >> 1;
            UINT32 payloadLength = mtuLength - 42; // Ethernet + IPv4 header length
            BYTE loadBuffer[kPacketSize];
            memset((VOID*)loadBuffer, 0, kPacketSize);// = (BYTE*)malloc(refSize / 2);
			Assert::AreEqual(kPacketSize, refSize / 2);

            HexStringToByte(loadBuffer, refSize, refBuffer);

            UCHAR payload[kPayloadLength];
			memset(payload, 0, sizeof(payload));
            AdapterMeta localAdapter;
			localAdapter.SetTarget("10.2.1.108", "12-34-56-78-9a-bc", 1234);
			localAdapter.AssingLocal("10.2.1.114", "cb-a9-87-65-43-21", 4321);
            UINT32 packetSize=0;
            BYTE MtuBuffer[2048];
            localAdapter.MTUFromPayload(payload, payloadLength, MtuBuffer, packetSize, 1);
            Assert::AreEqual(packetSize, (UINT32)kPacketSize);
            
            Assert::IsTrue(CompareEthHeader(loadBuffer, MtuBuffer));
			Assert::IsTrue(CompareIpHeader(loadBuffer+ sizeof(ETHERNET_HEADER), 
                MtuBuffer + sizeof(ETHERNET_HEADER)));
			Assert::IsTrue(CompareUdpHeader(loadBuffer + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER), 
                MtuBuffer + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER)));
           /*
            char output[kPacketSize * 2 + 1] = { 0 };
            bytes_to_hex_string(MtuBuffer, kPacketSize, output, kPacketSize*2+1);
            Logger::WriteMessage(output);
            */

		}

        TEST_METHOD(TestDynamicPacket_2) {
            const UINT32 kPacketSize = 106;
            const UINT32 kPayloadLength = 64;
			char refBuffer[] = "123456789abc7c1e523ef5d808004500005c000000000111a2b00a0201720a02016c10e104d20048d2c900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\0";
            UINT32 refSize = (UINT32)strlen(refBuffer);

            UINT32 mtuLength = refSize >> 1;
            UINT32 payloadLength = mtuLength - 42; // Ethernet + IPv4 header length

            BYTE loadBuffer[kPacketSize];
            memset((VOID*)loadBuffer, 0, kPacketSize);// = (BYTE*)malloc(refSize / 2);
			Assert::AreEqual(kPacketSize, refSize / 2);

            HexStringToByte(loadBuffer, refSize, refBuffer);

            UCHAR payload[kPayloadLength];
			memset(payload, 0, sizeof(payload));
            AdapterMeta localAdapter;
			localAdapter.SetTarget("10.2.1.108", "12-34-56-78-9a-bc", 1234);
			localAdapter.AssingLocal("10.2.1.114", "7C-1E-52-3E-F5-D8", 4321);
            UINT32 packetSize=0;
            BYTE MtuBuffer[2048];
            localAdapter.MTUFromPayload(payload, payloadLength, MtuBuffer, packetSize, 1);
            Assert::AreEqual(packetSize, (UINT32)kPacketSize);
			
            Assert::IsTrue(CompareEthHeader(loadBuffer, MtuBuffer));
			Assert::IsTrue(CompareIpHeader(loadBuffer+ sizeof(ETHERNET_HEADER), 
                MtuBuffer + sizeof(ETHERNET_HEADER)));
			Assert::IsTrue(CompareUdpHeader(loadBuffer + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER), 
                MtuBuffer + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER)));
		}
        
        TEST_METHOD(TestDynamicPacket_TTL) {
            char refBuffer[] = "123456789ABC7C1E52232A870800450000B8000000008011DC920A0C060214A838EDD60711D700A44774638C2232E0E8DE3E95140000000C020D00000310810001800B0C4080000000000000008008090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F\0";
            UINT32 hexLength = (UINT32)strlen(refBuffer);
            UINT32 mtuLength = hexLength >> 1;
            UINT32 payloadLength = mtuLength - 42; // Ethernet + IPv4 header length
            BYTE* inputMtuBuffer = NULL;
            inputMtuBuffer = (BYTE*)malloc(mtuLength);

            if (inputMtuBuffer == NULL) {
                Assert::Fail(L"Failed to allocate memory for input MTU buffer.");
            }
            else {
                HexStringToByte(inputMtuBuffer, mtuLength, refBuffer);
            }
			BYTE* purePayload = inputMtuBuffer + 42; // Skip the first 42 bytes (Ethernet + IPv4 header)
            
            AdapterMeta localAdapter;
			localAdapter.SetTarget("20.168.56.237", "12-34-56-78-9a-bc", 4567);
			localAdapter.AssingLocal("10.12.6.2", "7C-1E-52-23-2a-87", 54791);
            
            UINT32 packetSize=0;
            BYTE MtuBuffer[2048];
            localAdapter.MTUFromPayload(purePayload, payloadLength, MtuBuffer, packetSize, 128);
			Assert::IsTrue(CompareEthHeader(inputMtuBuffer, MtuBuffer));
			Assert::IsTrue(CompareIpHeader(inputMtuBuffer + sizeof(ETHERNET_HEADER), 
                MtuBuffer + sizeof(ETHERNET_HEADER)));
			Assert::IsTrue(CompareUdpHeader(inputMtuBuffer + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER), 
                MtuBuffer + sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER)));

			free(inputMtuBuffer);
        }
   };
}

