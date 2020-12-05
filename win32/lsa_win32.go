// +build windows

package win32

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procLsaOpenPolicy                  = advapi32DLL.NewProc("LsaOpenPolicy")
	procLsaClose                       = advapi32DLL.NewProc("LsaClose")
	procLsaFreeMemory                  = advapi32DLL.NewProc("LsaFreeMemory")
	procLsaNtStatusToWinError          = advapi32DLL.NewProc("LsaNtStatusToWinError")
	procLsaAddAccountRights            = advapi32DLL.NewProc("LsaAddAccountRights")
	procLsaEnumerateAccountRights      = advapi32DLL.NewProc("LsaEnumerateAccountRights")
	procLsaRemoveAccountRights         = advapi32DLL.NewProc("LsaRemoveAccountRights")
	procLsaRegisterLogonProcess        = advapi32DLL.NewProc("LsaRegisterLogonProcess")
	procLsaLookupAuthenticationPackage = advapi32DLL.NewProc("LsaLookupAuthenticationPackage")
	procLsaLogonUser                   = advapi32DLL.NewProc("LsaLogonUser")
)

// typedef struct _LSA_OBJECT_ATTRIBUTES {
//   ULONG               Length;
//   HANDLE              RootDirectory;
//   PLSA_UNICODE_STRING ObjectName;
//   ULONG               Attributes;
//   PVOID               SecurityDescriptor;
//   PVOID               SecurityQualityOfService;
// } LSA_OBJECT_ATTRIBUTES, *PLSA_OBJECT_ATTRIBUTES;
type _LSA_OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            syscall.Handle
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

// typedef struct _LSA_UNICODE_STRING {
//   USHORT Length;
//   USHORT MaximumLength;
// } LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;
// https://docs.microsoft.com/en-us/windows/desktop/api/lsalookup/ns-lsalookup-_lsa_unicode_string
type _LSA_UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        unsafe.Pointer
}

const (
	_POLICY_VIEW_LOCAL_INFORMATION   uint32 = 0x0001
	_POLICY_VIEW_AUDIT_INFORMATION   uint32 = 0x0002
	_POLICY_GET_PRIVATE_INFORMATION  uint32 = 0x0004
	_POLICY_TRUST_ADMIN              uint32 = 0x0008
	_POLICY_CREATE_ACCOUNT           uint32 = 0x0010
	_POLICY_CREATE_SECRET            uint32 = 0x0020
	_POLICY_CREATE_PRIVILEGE         uint32 = 0x0040
	_POLICY_SET_DEFAULT_QUOTA_LIMITS uint32 = 0x0080
	_POLICY_SET_AUDIT_REQUIREMENTS   uint32 = 0x0100
	_POLICY_AUDIT_LOG_ADMIN          uint32 = 0x0200
	_POLICY_SERVER_ADMIN             uint32 = 0x0400
	_POLICY_LOOKUP_NAMES             uint32 = 0x0800
	_POLICY_READ                     uint32 = _STANDARD_RIGHTS_READ | 0x0006
	_POLICY_WRITE                    uint32 = _STANDARD_RIGHTS_WRITE | 0x07F8
	_POLICY_EXECUTE                  uint32 = _STANDARD_RIGHTS_EXECUTE | 0x0801
	_POLICY_ALL_ACCESS               uint32 = _STANDARD_RIGHTS_REQUIRED | 0x0FFF
)

func toLSAUnicodeString(str string) _LSA_UNICODE_STRING {
	wchars, _ := syscall.UTF16FromString(str)
	nc := len(wchars) - 1 // minus 1 to chop off the null termination
	sz := int(unsafe.Sizeof(uint16(0)))
	return _LSA_UNICODE_STRING{
		Length:        uint16(nc * sz),
		MaximumLength: uint16((nc + 1) * sz),
		Buffer:        unsafe.Pointer(&wchars[0]),
	}
}

// NTSTATUS values
// https://msdn.microsoft.com/en-us/library/cc704588.aspx
const (
	_STATUS_SUCCESS      uintptr = 0x00000000
	_STATUS_NO_SUCH_FILE uintptr = 0xC000000F
)

// NTSTATUS LsaOpenPolicy(
// 	PLSA_UNICODE_STRING    SystemName,
// 	PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
// 	ACCESS_MASK            DesiredAccess,
// 	PLSA_HANDLE            PolicyHandle
//   );
// https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/nf-ntsecapi-lsaopenpolicy
func lsaOpenPolicy(system string, access uint32) (*syscall.Handle, error) {
	// Docs say this is not used, but the structure needs to be
	// initialized to zero values, and the length must be set to sizeof(_LSA_OBJECT_ATTRIBUTES)
	var pSystemName *_LSA_UNICODE_STRING
	if system != "" {
		lsaStr := toLSAUnicodeString(system)
		pSystemName = &lsaStr
	}
	var attrs _LSA_OBJECT_ATTRIBUTES
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var hPolicy syscall.Handle
	status, _, _ := procLsaOpenPolicy.Call(
		uintptr(unsafe.Pointer(pSystemName)),
		uintptr(unsafe.Pointer(&attrs)),
		uintptr(access),
		uintptr(unsafe.Pointer(&hPolicy)),
	)
	if status == _STATUS_SUCCESS {
		return &hPolicy, nil
	}
	return nil, lsaNtStatusToWinError(status)
}

// NTSTATUS LsaClose(
//   LSA_HANDLE ObjectHandle
// );
// https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/nf-ntsecapi-lsaclose
func lsaClose(hPolicy syscall.Handle) error {
	status, _, _ := procLsaClose.Call(
		uintptr(hPolicy),
	)
	if status == _STATUS_SUCCESS {
		return nil
	}
	return lsaNtStatusToWinError(status)
}

// NTSTATUS LsaEnumerateAccountRights(
//   LSA_HANDLE          PolicyHandle,
//   PSID                AccountSid,
//   PLSA_UNICODE_STRING *UserRights,
//   PULONG              CountOfRights
// );
//https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/nf-ntsecapi-lsaenumerateaccountrights
func lsaEnumerateAccountRights(hPolicy syscall.Handle, sid *syscall.SID) ([]string, error) {
	var rights uintptr
	var count uint32
	status, _, _ := procLsaEnumerateAccountRights.Call(
		uintptr(hPolicy),
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&rights)),
		uintptr(unsafe.Pointer(&count)),
	)
	if status != _STATUS_SUCCESS {
		errno := lsaNtStatusToWinError(status)
		if errno == syscall.ERROR_FILE_NOT_FOUND { // user has no rights assigned
			return nil, nil
		}
		return nil, errno
	}
	defer lsaFreeMemory(rights)
	var userRights []string
	rs := (*[1 << 30]_LSA_UNICODE_STRING)(unsafe.Pointer(rights))[:count:count] //nolint
	for _, r := range rs {
		userRights = append(userRights, UTF16PtrToStringN((*uint16)(r.Buffer), int(r.Length/2)))
	}
	return userRights, nil
}

// NTSTATUS LsaAddAccountRights(
// 	LSA_HANDLE          PolicyHandle,
// 	PSID                AccountSid,
// 	PLSA_UNICODE_STRING UserRights,
// 	ULONG               CountOfRights
// );
// https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/nf-ntsecapi-lsaaddaccountrights
func lsaAddAccountRights(hPolicy syscall.Handle, sid *syscall.SID, rights []string) error {
	var lsaRights []_LSA_UNICODE_STRING
	for _, r := range rights {
		lsaRights = append(lsaRights, toLSAUnicodeString(r))
	}
	status, _, _ := procLsaAddAccountRights.Call(
		uintptr(hPolicy),
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&lsaRights[0])),
		uintptr(len(rights)),
	)
	if status != _STATUS_SUCCESS {
		return lsaNtStatusToWinError(status)
	}
	return nil
}

// NTSTATUS LsaRemoveAccountRights(
//   LSA_HANDLE          PolicyHandle,
//   PSID                AccountSid,
//   BOOLEAN             AllRights,
//   PLSA_UNICODE_STRING UserRights,
//   ULONG               CountOfRights
// );
//https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/nf-ntsecapi-lsaremoveaccountrights
func lsaRemoveAccountRights(hPolicy syscall.Handle, sid *syscall.SID, removeAll bool, rights []string) error {
	var lsaRights []_LSA_UNICODE_STRING
	if !removeAll {
		for _, r := range rights {
			lsaRights = append(lsaRights, toLSAUnicodeString(r))
		}
	}
	status, _, _ := procLsaRemoveAccountRights.Call(
		uintptr(hPolicy),
		uintptr(unsafe.Pointer(sid)),
		uintptr(toBOOL(removeAll)),
		uintptr(unsafe.Pointer(&lsaRights[0])),
		uintptr(len(lsaRights)),
	)
	if status != _STATUS_SUCCESS {
		return lsaNtStatusToWinError(status)
	}
	return nil
}

// ULONG LsaNtStatusToWinError(
//   NTSTATUS Status
// );
// https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/nf-ntsecapi-lsantstatustowinerror
func lsaNtStatusToWinError(status uintptr) error {
	ret, _, _ := procLsaNtStatusToWinError.Call(status)
	if ret == ERROR_MR_MID_NOT_FOUND {
		return syscall.EINVAL
	}
	return syscall.Errno(ret)
}

// NTSTATUS LsaFreeMemory(
// 	PVOID Buffer
// );
// https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/nf-ntsecapi-lsafreememory
func lsaFreeMemory(buf uintptr) error {
	status, _, _ := procLsaFreeMemory.Call(buf)
	if status == _STATUS_SUCCESS {
		return nil
	}
	return lsaNtStatusToWinError(status)
}

// typedef ULONG LSA_OPERATIONAL_MODE,*PLSA_OPERATIONAL_MODE;
// https://github.com/Alexpux/mingw-w64/blob/d0d7f784833bbb0b2d279310ddc6afb52fe47a46/mingw-w64-headers/include/ntsecapi.h#L19
type _LSA_OPERATIONAL_MODE uint32

// https://github.com/Alexpux/mingw-w64/blob/d0d7f784833bbb0b2d279310ddc6afb52fe47a46/mingw-w64-headers/include/ntsecapi.h#L630
const MSV1_0_PACKAGE_NAME = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"

// https://github.com/Alexpux/mingw-w64/blob/d0d7f784833bbb0b2d279310ddc6afb52fe47a46/mingw-w64-headers/include/ntsecapi.h#L968
const MICROSOFT_KERBEROS_NAME = "Kerberos"

// typedef enum _MSV1_0_LOGON_SUBMIT_TYPE {
//   MsV1_0InteractiveLogon = 2,
//   MsV1_0Lm20Logon,
//   MsV1_0NetworkLogon,
//   MsV1_0SubAuthLogon,
//   MsV1_0WorkstationUnlockLogon = 7,
//   MsV1_0S4ULogon = 12,
//   MsV1_0VirtualLogon = 82
// } MSV1_0_LOGON_SUBMIT_TYPE, *PMSV1_0_LOGON_SUBMIT_TYPE;
// https://github.com/Alexpux/mingw-w64/blob/d0d7f784833bbb0b2d279310ddc6afb52fe47a46/mingw-w64-headers/ddk/include/ddk/ntifs.h#L2619-L2627
type MSV1_0_LOGON_SUBMIT_TYPE uint32

const (
	MsV1_0InteractiveLogon       MSV1_0_LOGON_SUBMIT_TYPE = 2
	MsV1_0Lm20Logon              MSV1_0_LOGON_SUBMIT_TYPE = 3
	MsV1_0NetworkLogon           MSV1_0_LOGON_SUBMIT_TYPE = 4
	MsV1_0SubAuthLogon           MSV1_0_LOGON_SUBMIT_TYPE = 5
	MsV1_0WorkstationUnlockLogon MSV1_0_LOGON_SUBMIT_TYPE = 7
	MsV1_0S4ULogon               MSV1_0_LOGON_SUBMIT_TYPE = 12
	MsV1_0VirtualLogon           MSV1_0_LOGON_SUBMIT_TYPE = 82
)

// typedef enum _SECURITY_LOGON_TYPE {
// 	Interactive = 2,Network,Batch,Service,Proxy,Unlock,NetworkCleartext,NewCredentials,RemoteInteractive,CachedInteractive,
// 	CachedRemoteInteractive,CachedUnlock
// } SECURITY_LOGON_TYPE,*PSECURITY_LOGON_TYPE;
// https://github.com/Alexpux/mingw-w64/blob/d0d7f784833bbb0b2d279310ddc6afb52fe47a46/mingw-w64-headers/include/ntsecapi.h#L28-L31
type SECURITY_LOGON_TYPE uint32

const (
	Interactive             SECURITY_LOGON_TYPE = 2
	Network                 SECURITY_LOGON_TYPE = 3
	Batch                   SECURITY_LOGON_TYPE = 4
	Service                 SECURITY_LOGON_TYPE = 5
	Proxy                   SECURITY_LOGON_TYPE = 6
	Unlock                  SECURITY_LOGON_TYPE = 7
	NetworkCleartext        SECURITY_LOGON_TYPE = 8
	NewCredentials          SECURITY_LOGON_TYPE = 9
	RemoteInteractive       SECURITY_LOGON_TYPE = 10
	CachedInteractive       SECURITY_LOGON_TYPE = 11
	CachedRemoteInteractive SECURITY_LOGON_TYPE = 12
	CachedUnlock            SECURITY_LOGON_TYPE = 13
)

// typedef struct _MSV1_0_S4U_LOGON {
//   MSV1_0_LOGON_SUBMIT_TYPE MessageType;
//   ULONG Flags;
//   UNICODE_STRING UserPrincipalName;
//   UNICODE_STRING DomainName;
// } MSV1_0_S4U_LOGON, *PMSV1_0_S4U_LOGON;
// https://github.com/Alexpux/mingw-w64/blob/d0d7f784833bbb0b2d279310ddc6afb52fe47a46/mingw-w64-headers/ddk/include/ddk/ntifs.h#L2688-L2693
type _MSV1_0_S4U_LOGON struct {
	MessageType       MSV1_0_LOGON_SUBMIT_TYPE
	Flags             uint32
	UserPrincipalName _LSA_UNICODE_STRING
	DomainName        _LSA_UNICODE_STRING
}

// typedef struct _TOKEN_GROUPS {
//   DWORD              GroupCount;
//   SID_AND_ATTRIBUTES Groups[ANYSIZE_ARRAY];
// } TOKEN_GROUPS, *PTOKEN_GROUPS;
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_groups
type TOKEN_GROUPS struct {
	GroupCount uint32
	Groups     syscall.SIDAndAttributes
}

// typedef struct _TOKEN_SOURCE {
//   CHAR SourceName[TOKEN_SOURCE_LENGTH];
//   LUID SourceIdentifier;
// } TOKEN_SOURCE, *PTOKEN_SOURCE;
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_source
type TOKEN_SOURCE struct {
	SourceName       [8]byte
	SourceIdentifier windows.LUID
}

// typedef struct _QUOTA_LIMITS {
//   SIZE_T        PagedPoolLimit;
//   SIZE_T        NonPagedPoolLimit;
//   SIZE_T        MinimumWorkingSetSize;
//   SIZE_T        MaximumWorkingSetSize;
//   SIZE_T        PagefileLimit;
//   LARGE_INTEGER TimeLimit;
// } QUOTA_LIMITS, *PQUOTA_LIMITS;
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-quota_limits
type QUOTA_LIMITS struct {
	PagedPoolLimit        uintptr
	NonPagedPoolLimit     uintptr
	MinimumWorkingSetSize uintptr
	MaximumWorkingSetSize uintptr
	PagefileLimit         uintptr
	TimeLimit             uint64
}

// https://msdn.microsoft.com/en-us/library/windows/hardware/ff565436(v=vs.85).aspx
type NtStatus uint32

// NTSTATUS LsaRegisterLogonProcess(
//   PLSA_STRING           LogonProcessName,
//   PHANDLE               LsaHandle,
//   PLSA_OPERATIONAL_MODE SecurityMode
// );
// https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaregisterlogonprocess
func lsaRegisterLogonProcess(logonProcessName string) (syscall.Handle, error) {
	var lsaHandle syscall.Handle
	var securityMode _LSA_OPERATIONAL_MODE
	logonProcessNameString := toLSAUnicodeString(logonProcessName)
	status, _, _ := procLsaRegisterLogonProcess.Call(
		uintptr(unsafe.Pointer(&logonProcessNameString)),
		uintptr(unsafe.Pointer(&lsaHandle)),
		uintptr(unsafe.Pointer(&securityMode)),
	)
	if status == _STATUS_SUCCESS {
		return lsaHandle, nil
	}
	return syscall.InvalidHandle, lsaNtStatusToWinError(status)
}

// NTSTATUS LsaLookupAuthenticationPackage(
//   HANDLE      LsaHandle,
//   PLSA_STRING PackageName,
//   PULONG      AuthenticationPackage
// );
// https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalookupauthenticationpackage
func lsaLookupAuthenticationPackage(lsaHandle syscall.Handle, packageName string) (uint32, error) {
	var authenticationPackage uint32
	packageNameString := toLSAUnicodeString(packageName)
	status, _, _ := procLsaLookupAuthenticationPackage.Call(
		uintptr(lsaHandle),
		uintptr(unsafe.Pointer(&packageNameString)),
		uintptr(unsafe.Pointer(&authenticationPackage)),
	)
	if status == _STATUS_SUCCESS {
		return authenticationPackage, nil
	}
	return 0, lsaNtStatusToWinError(status)
}

// NTSTATUS LsaLogonUser(
//   HANDLE              LsaHandle,
//   PLSA_STRING         OriginName,
//   SECURITY_LOGON_TYPE LogonType,
//   ULONG               AuthenticationPackage,
//   PVOID               AuthenticationInformation,
//   ULONG               AuthenticationInformationLength,
//   PTOKEN_GROUPS       LocalGroups,
//   PTOKEN_SOURCE       SourceContext,
//   PVOID               *ProfileBuffer,
//   PULONG              ProfileBufferLength,
//   PLUID               LogonId,
//   PHANDLE             Token,
//   PQUOTA_LIMITS       Quotas,
//   PNTSTATUS           SubStatus
// );
// https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalogonuser
func lsaLogonUser(
	lsaHandle syscall.Handle,
	originName string,
	logonType SECURITY_LOGON_TYPE,
	authenticationPackage uint32,
	authenticationInformation *byte,
	authenticationInformationLength uint32,
	localGroups *TOKEN_GROUPS,
	sourceContext *TOKEN_SOURCE,
	profileBuffer *uintptr,
	profileBufferLength *uint32,
	logonId *windows.LUID,
	token *syscall.Handle,
	quotas *QUOTA_LIMITS,
	subStatus *NtStatus,
) error {
	originNameString := toLSAUnicodeString(originName)
	status, _, _ := procLsaLogonUser.Call(
		uintptr(lsaHandle),
		uintptr(unsafe.Pointer(&originNameString)),
		uintptr(logonType),
		uintptr(authenticationPackage),
		uintptr(unsafe.Pointer(authenticationInformation)),
		uintptr(authenticationInformationLength),
		uintptr(unsafe.Pointer(localGroups)),
		uintptr(unsafe.Pointer(sourceContext)),
		uintptr(unsafe.Pointer(profileBuffer)),
		uintptr(unsafe.Pointer(profileBufferLength)),
		uintptr(unsafe.Pointer(logonId)),
		uintptr(unsafe.Pointer(token)),
		uintptr(unsafe.Pointer(quotas)),
		uintptr(unsafe.Pointer(subStatus)),
	)
	if status == _STATUS_SUCCESS {
		return nil
	}
	return lsaNtStatusToWinError(status)
}
