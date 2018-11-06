using System;
using System.Runtime.InteropServices;
using DWORD = System.UInt32;
using BOOL = System.UInt32;

namespace wincatalogdotnet
{
    /// <summary>
    /// Contains all of the native Win32 stuff
    /// </summary>
    class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPTCATATTRIBUTE
        {
            private DWORD _cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszReferenceTag;
            private DWORD _dwAttrTypeAndAction;
            internal DWORD cbValue;
            internal System.IntPtr pbValue;
            private DWORD _dwReserved;
        };

        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPTCATMEMBER
        {
            internal DWORD cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszReferenceTag;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszFileName;
            internal GUID gSubjectType;
            internal DWORD fdwMemberFlags;
            internal IntPtr pIndirectData;
            internal DWORD dwCertVersion;
            internal DWORD dwReserved;
            internal IntPtr hReserved;
            internal CRYPT_ATTR_BLOB sEncodedIndirectData;
            internal CRYPT_ATTR_BLOB sEncodedMemberInfo;
        };

        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPT_ATTR_BLOB
        {
            /// DWORD->unsigned int
            public uint cbData;

            /// BYTE*
            public System.IntPtr pbData;
        }

        [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct GUID
        {
            /// unsigned int
            internal uint Data1;

            /// unsigned short
            internal ushort Data2;

            /// unsigned short
            internal ushort Data3;

            /// unsigned char[8]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            internal byte[] Data4;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SIP_INDIRECT_DATA
        {
            internal CRYPT_ATTRIBUTE_TYPE_VALUE Data;
            internal CRYPT_ALGORITHM_IDENTIFIER DigestAlgorithm;
            internal CRYPT_ATTR_BLOB Digest;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPT_ATTRIBUTE_TYPE_VALUE
        {
            [MarshalAs(UnmanagedType.LPStr)]
            internal string pszObjId;
            internal CRYPT_ATTR_BLOB Value;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        internal static extern IntPtr CryptCATOpen(
           [MarshalAs(UnmanagedType.LPWStr)]
            string pwszFilePath,
           DWORD fdwOpenFlags,
           IntPtr hProv,
           DWORD dwPublicVersion,
           DWORD dwEncodingType
        );

        [StructLayoutAttribute(LayoutKind.Sequential)]
        internal struct CRYPT_ALGORITHM_IDENTIFIER
        {
            /// LPSTR->CHAR*
            [MarshalAsAttribute(UnmanagedType.LPStr)]
            internal string pszObjId;

            /// CRYPT_OBJID_BLOB->_CRYPTOAPI_BLOB
            internal CRYPT_ATTR_BLOB Parameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPTCATSTORE
        {
            private DWORD _cbStruct;
            internal DWORD dwPublicVersion;
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszP7File;
            private IntPtr _hProv;
            private DWORD _dwEncodingType;
            private DWORD _fdwStoreFlags;
            private IntPtr _hReserved;
            private IntPtr _hAttrs;
            private IntPtr _hCryptMsg;
            private IntPtr _hSorted;
        };

        [DllImport("wintrust.dll")]
        internal static extern BOOL CryptCATClose(
            IntPtr hCatalog
        );

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        internal static extern IntPtr CryptCATEnumerateCatAttr(
             IntPtr hCatalog,
             IntPtr pPrevAttr
        );

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        internal static extern IntPtr CryptCATEnumerateMember(
            IntPtr hCatalog,
            IntPtr pPrevMember
        );
            
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        internal static extern IntPtr CryptCATEnumerateAttr(
            IntPtr hCatalog,
            IntPtr pCatMember,
            IntPtr pPrevAttr
        );

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        internal static extern IntPtr CryptCATStoreFromHandle(
            IntPtr hCatalog
        );

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        internal static extern bool CryptCATAdminAcquireContext2(
            ref IntPtr phCatAdmin,
            IntPtr pgSubsystem,
            [MarshalAs(UnmanagedType.LPWStr)]
                  string pwszHashAlgorithm,
            IntPtr pStrongHashPolicy,
            DWORD dwFlags
        );

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool CryptCATAdminCalcHashFromFileHandle2(
             IntPtr hCatAdmin,
             IntPtr hFile,
             [In, Out] ref DWORD pcbHash,
             IntPtr pbHash,
             DWORD dwFlags
        );

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern unsafe IntPtr CreateFile(
            string lpFileName,
            DWORD dwDesiredAccess,
            DWORD dwShareMode,
            DWORD lpSecurityAttributes,
            DWORD dwCreationDisposition,
            DWORD dwFlagsAndAttributes,
            IntPtr hTemplateFile
        );

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        internal static extern bool CryptCATAdminReleaseContext(
            IntPtr phCatAdmin,
            DWORD dwFlags
        );

        internal const string CloseHandleDllName = "api-ms-win-core-handle-l1-1-0.dll";                      /*32*/
        /// Return Type: BOOL->int
        ///hObject: HANDLE->void*
        [DllImportAttribute(CloseHandleDllName, EntryPoint = "CloseHandle")]
        [return: MarshalAsAttribute(UnmanagedType.Bool)]
        internal static extern bool CloseHandle([InAttribute()] System.IntPtr hObject);
    }
}
