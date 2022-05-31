$AdjustTokenPrivileges = @"
using System;
using System.Runtime.InteropServices;

public class TokenManipulator
{
[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
[DllImport("kernel32.dll", ExactSpelling = true)]
internal static extern IntPtr GetCurrentProcess();
[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
phtok);
[DllImport("advapi32.dll", SetLastError = true)]
internal static extern bool LookupPrivilegeValue(string host, string name,
ref long pluid);
[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct TokPriv1Luid
{
public int Count;
public long Luid;
public int Attr;
}
internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
internal const int TOKEN_QUERY = 0x00000008;
internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
public static bool AddPrivilege(string privilege)
{
try
{
bool retVal;
TokPriv1Luid tp;
IntPtr hproc = GetCurrentProcess();
IntPtr htok = IntPtr.Zero;
retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
tp.Count = 1;
tp.Luid = 0;
tp.Attr = SE_PRIVILEGE_ENABLED;
retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
return retVal;
}
catch (Exception ex)
{
throw ex;
}
}
public static bool RemovePrivilege(string privilege)
{
try
{
bool retVal;
TokPriv1Luid tp;
IntPtr hproc = GetCurrentProcess();
IntPtr htok = IntPtr.Zero;
retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
tp.Count = 1;
tp.Luid = 0;
tp.Attr = SE_PRIVILEGE_DISABLED;
retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
return retVal;
}
catch (Exception ex)
{
throw ex;
}
}
}
"@

Function Add-AclHC {
    <#
    .SYNOPSIS
        Add NTFS permissions on a folder.

    .DESCRIPTION
        Add an ACE (Access Control Entry) to the ACL (Access Control List) for 
        granting permissions on a folder.

        The 'Owner' will be changed to 'BUILTIN\Administrators' as this is 
        necessary to be able to do these changes.

        Keep in mind that the inheritance is not broken or changed, only new 
        permissions are added. In case you need to start clean, please use 
        'Remove-AclHC' first, then 'Add-AclHC' and afterwards 'Set-AclOwnerHC'.

    .PARAMETER SamAccountName
        The SamAccountName of the user or group in the active directory.

    .PARAMETER Grant
        The NTFS permissions to be granted to the SamAccountName:
        
        - ReadAndExecute     > Read only
        - Modify             > Change or Read/Write
        - FullControl        > Full control
        - ListFolderContents > List only
        - Write              > Users can access the folder but not change, 
                               delete or set permissions on it. They can do 
                               everything on it's subfolders and files.

    .PARAMETER Path
        The folder where the NTFS permission will be added

    .PARAMETER Domain
        The domain name in use

    .EXAMPLE
        Clear the ACL and only grant ReadAndExecute permissions to Bob
        Remove-AclHC -Path .\Documents

        Add-AclHC -Grant ReadAndExecute -SamAccountName Bob -Path .\Documents

    .EXAMPLE
        Add two ACE's to the ACL of folder 'Reports' with a hashtable.

        @{
            'bob'  = 'FullControl'
            'mike' = 'Modify'
        }.GetEnumerator() | Add-AclHC -Path .\Reports -Verbose
        #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $_ -PathType Container })]
        [String]$Path,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateScript({ 
                if (Get-ADObject -Filter { SamAccountName -eq $_ }) { $true } else { $false } }
        )]
        [Alias('Key')]
        [String]$SamAccountName,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet(
            'ReadAndExecute', 'Write', 'Modify', 'FullControl', 
            'ListFolderContents'
        )]
        [Alias('Value')]
        [String]$Grant,
        [String]$Domain = $env:USERDOMAIN
    )

    Begin {
        Try {
            #region Get super powers
            Add-Type $AdjustTokenPrivileges
            [void][TokenManipulator]::AddPrivilege('SeRestorePrivilege')
            [void][TokenManipulator]::AddPrivilege('SeBackupPrivilege')
            [void][TokenManipulator]::AddPrivilege('SeTakeOwnershipPrivilege')
            #endregion

            #region Create owner object
            $Owner = New-Object System.Security.AccessControl.DirectorySecurity
            $Admin = New-Object System.Security.Principal.NTAccount('BUILTIN\Administrators')
            $Owner.SetOwner($Admin)
            #endregion
        }
        Catch {
            throw "Failed adding permissions to '$Path': $_"
        }
    }

    Process {
        Try {
            $AdObject = Switch ($SamAccountName) {
                'Builtin\Administrators' {
                    'Builtin\Administrators'
                    break
                }
                default {
                    "$Domain\$SAMaccountName"
                }
            }

            #$Path = Resolve-Path $Path

            $Folder = Get-Item -LiteralPath $Path -Force

            # Set 'BUILTIN\Administrators' as owner
            $Folder.SetAccessControl($Owner)

            $ACL = Get-Acl -LiteralPath $Path

            #region Remove SamAccountName first
            $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($AdObject, 'Read', , , 'Allow')
            $ACL.RemoveAccessRuleAll($Rule)
            #endregion

            Switch ($Grant) {
                'ReadAndExecute' {
                    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($ADobject, 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
                    break
                }
                'Write' {
                    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($ADobject, @('CreateFiles', 'AppendData', 'DeleteSubdirectoriesAndFiles', ' ReadAndExecute', 'Synchronize'), 'None', 'InheritOnly', 'Allow') # This folder only
                    $ACL.AddAccessRule($Rule)
                    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($ADobject, @('DeleteSubdirectoriesAndFiles', 'Modify', 'Synchronize'), 'ContainerInherit, ObjectInherit', 'InheritOnly', 'Allow') # Subfolders and files only
                    break
                }
                'Modify' {
                    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($ADobject, 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
                    break
                }
                'FullControl' {
                    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($ADobject, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
                    break
                }
                'ListFolderContents' {
                    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($ADobject, 'ReadAndExecute', 'ContainerInherit', 'None', 'Allow')
                    break
                }
            }

            Write-Verbose "Added permission '$Grant' for '$SamAccountName' on '$Path'"
            $ACL.AddAccessRule($Rule)
            Set-Acl -LiteralPath $Path -AclObject $ACL
        }
        Catch {
            throw "Failed adding permission '$Grant' for '$SamAccountName' to '$Path': $_"
        }
    }
}
Function Add-LocalAdministratorAccountHC {
    <#
        .SYNOPSIS
            Add a user or group to the local 'Administrators' group.

        .DESCRIPTION
            Add a user or group to the local 'Administrators' group on a remote 
            computer.

        .Parameter ComputerName
            Name of the computer where to add a user or group to the local 
            'Administrators' group.

        .Parameter SamAccountName
            The SamAccountName of an active directory user or group object 
            that needs to be added to the local 'Administrators' group.

        .EXAMPLE
            $params = @{
                ComputerName   = @('pc1', 'pc2')
                SamAccountName = 'bob'
            }
            Add-LocalAdministratorAccountHC @params

            Add the user account 'bob' to the local 'Administrators' security 
            group.
        #>

    [CmdLetBinding()]
    Param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [String[]]$ComputerName,
        [String]$SamAccountName = 'SrvBatch',
        [Int]$JobThrottle = 10
    )

    Begin {
        Function Resolve-SamAccount {
            Param (
                [Parameter(Mandatory)]
                [String]$SamAccountName
            )
            Process {
                Try {
                    $D = ([AdsiSearcher]"(SamAccountName=$SamAccountName)").FindOne().Properties['SamAccountName']
                    'WinNT://', "$env:userdomain", '/', $($D) -join ''
                }
                Catch {
                    throw "SamAccountName '$SamAccountName' not found in AD"
                }
            }
        }

        $ADResolvedName = Resolve-SamAccount -SamAccountName $SamAccountName

        $Jobs = @()

        Write-Verbose "Add user '$SamAccountName' to the local administrator group"
    }

    Process {
        foreach ($C in $ComputerName) {
            $Jobs += Start-Job -Name $C -ScriptBlock {
                Try {
                    $VerbosePreference = $Using:VerbosePreference
                    $WarningPreference = $Using:WarningPreference

                    $Result = [PSCustomObject]@{
                        ComputerName   = $Using:C
                        SamAccountName = $Using:SamAccountName
                        Status         = $null
                        Error          = $null
                    }

                    ([ADSI]"WinNT://$Using:C/Administrators,group").Add($Using:ADResolvedName)
                    $Result.Status = 'Added'
                    Write-Verbose "'$Using:C': Added user"
                }
                Catch {
                    if ($_ -like '*account name is already a member of the group*') {
                        $Result.Status = 'Already member'
                        Write-Verbose "'$Using:C': Already member"
                    }
                    else {
                        $Result.Status = 'Error'
                        $Result.Error = $_

                        Write-Warning "'$Using:C': $_"
                    }
                }
                Finally {
                    $Result
                }
            }

            Wait-MaxRunningJobsHC -Name $Jobs -MaxThreads $JobThrottle
        }
    }

    End {
        $Null = Wait-Job -Job $Jobs
        Receive-Job -Job $Jobs | Select-Object * -ExcludeProperty 'RunSpaceId', 'PSComputerName', 'PSShowComputerName'
        Remove-Job -Job $Jobs -Force -EA Ignore
    }
}
Function Remove-LocalAdministratorAccountHC {
    <#
        .SYNOPSIS
            Remove a user or group from the local 'Administrators' group.

        .DESCRIPTION
            Remove a user or group from the local 'Administrators' group on
            a remote computer.

        .Parameter ComputerName
            Name of the computer where to remove a user or group to the local 
            'Administrators' group.

        .Parameter SamAccountName
            The SamAccountName of an active directory user or group object 
            that needs to be removed to the local 'Administrators' group.

        .EXAMPLE
            $params = @{
                ComputerName   = @('pc1', 'pc2')
                SamAccountName = 'bob'
            }
            Remove-LocalAdministratorAccountHC @params

            Remove the user account 'bob' from the local 'Administrators' 
            security group.
    #>

    Param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [String[]]$ComputerName,
        [Parameter(Mandatory)]
        [String]$SamAccountName
    )

    Begin {
        Function Resolve-SamAccount {
            Param (
                [Parameter(Mandatory)]
                [String]$SamAccountName
            )
            Process {
                Try {
                    $D = ([AdsiSearcher]"(SamAccountName=$SamAccountName)").FindOne().Properties['SamAccountName']
                    'WinNT://', "$env:userdomain", '/', $($D) -join ''
                }
                Catch {
                    throw "SamAccountName '$SamAccountName' not found in AD"
                }
            }
        }

        $ADResolvedName = Resolve-SamAccount -SamAccountName $SamAccountName
    }

    Process {
        foreach ($C in $ComputerName) {
            Try {
			    ([ADSI]"WinNT://$C/Administrators,group").Remove($ADResolvedName)
                Write-Host "$C : SamAccountName '$SamAccountName' removed as local admin." -ForegroundColor Green
            }
            Catch {
                if ($_ -like '*account name is not a member of the group*') {
                    Write-Host "$C : SamAccountName '$SamAccountName' is not local admin." -ForegroundColor Yellow
                }
                else {
                    Write-Warning "$C : $_"
                }
            }
        }
    }
}
Function Get-AccessBasedEnumerationHC {
    <#
    .SYNOPSIS
        Check if a shared folder has Access Based Enumeration enabled.

    .DESCRIPTION
        Check if a shared folder has Access Based Enumeration enabled.

    .PARAMETER ComputerName
        Specifies the target computer.

    PARAMETER ShareName
        Name of the share.

    .EXAMPLE
        Retrieve the Access Based Enumeration status for two shared folders on 
        PC1.    
    
        'Reports', 'Departments'| Get-AccessBasedEnumerationHC PC1

        ComputerName : PC1
        ShareName    : Reports
        EnabledABE   : False

        ComputerName : PC1
        ShareName    : Departments
        EnabledABE   : True
    #>

    [CmdLetBinding()]
    Param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [String[]]$ShareName,
        [ValidateNotNullOrEmpty()]
        [String]$ComputerName = $env:COMPUTERNAME
    )

    Begin {
        if (-not([System.Management.Automation.PSTypeName]'NetApi32').Type) {
            Add-Type -TypeDefinition @"
                using System;
                using System.Collections.Generic;
                using System.Runtime.InteropServices;
                using System.Text;


                public enum Share_Type : uint
                {
                    STYPE_DISKTREE = 0x00000000,   // Disk Drive
                    STYPE_PRINTQ = 0x00000001,   // Print Queue
                    STYPE_DEVICE = 0x00000002,   // Communications Device
                    STYPE_IPC = 0x00000003,   // InterProcess Communications
                    STYPE_SPECIAL = 0x80000000,   // Special share types (C$, ADMIN$, IPC$, etc)
                    STYPE_TEMPORARY = 0x40000000   // Temporary share
                }

                public enum Share_ReturnValue : int
                {
                    NERR_Success = 0,
                    ERROR_ACCESS_DENIED = 5,
                    ERROR_NOT_ENOUGH_MEMORY = 8,
                    ERROR_INVALID_PARAMETER = 87,
                    ERROR_INVALID_LEVEL = 124, // unimplemented level for info
                    ERROR_MORE_DATA = 234,
                    NERR_BufTooSmall = 2123, // The API return buffer is too small.
                    NERR_NetNameNotFound = 2310 // This shared resource does not exist.
                }

                [System.Flags]
                public enum Shi1005_flags
                {
                    SHI1005_FLAGS_DFS = 0x0001,  // Part of a DFS tree (Cannot be set)
                    SHI1005_FLAGS_DFS_ROOT = 0x0002,  // Root of a DFS tree (Cannot be set)
                    SHI1005_FLAGS_RESTRICT_EXCLUSIVE_OPENS = 0x0100,  // Disallow Exclusive file open
                    SHI1005_FLAGS_FORCE_SHARED_DELETE = 0x0200,  // Open files can be force deleted
                    SHI1005_FLAGS_ALLOW_NAMESPACE_CACHING = 0x0400,  // Clients can cache the namespace
                    SHI1005_FLAGS_ACCESS_BASED_DIRECTORY_ENUM = 0x0800,  // Only directories for which a user has FILE_LIST_DIRECTORY will be listed
                    SHI1005_FLAGS_FORCE_LEVELII_OPLOCK = 0x1000,  // Prevents exclusive caching
                    SHI1005_FLAGS_ENABLE_HASH = 0x2000,  // Used for server side support for peer caching
                    SHI1005_FLAGS_ENABLE_CA = 0X4000   // Used for Clustered shares
                }

                public static class NetApi32
                {

                    // ********** Structures **********

                    // SHARE_INFO_502
                    [StructLayout(LayoutKind.Sequential)]
                    public struct SHARE_INFO_502
                    {
                        [MarshalAs(UnmanagedType.LPWStr)]
                        public string shi502_netname;
                        public uint shi502_type;
                        [MarshalAs(UnmanagedType.LPWStr)]
                        public string shi502_remark;
                        public Int32 shi502_permissions;
                        public Int32 shi502_max_uses;
                        public Int32 shi502_current_uses;
                        [MarshalAs(UnmanagedType.LPWStr)]
                        public string shi502_path;
                        public IntPtr shi502_passwd;
                        public Int32 shi502_reserved;
                        public IntPtr shi502_security_descriptor;
                    }

                    // SHARE_INFO_1005
                    [StructLayout(LayoutKind.Sequential)]
                    public struct SHARE_INFO_1005
                    {
                        public Int32 Shi1005_flags;
                    }



                    private class unmanaged
                    {

                        //NetShareGetInfo
                        [DllImport("Netapi32.dll", SetLastError = true)]
                        internal static extern int NetShareGetInfo(
                            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
                            [MarshalAs(UnmanagedType.LPWStr)] string netName,
                            Int32 level,
                            ref IntPtr bufPtr
                        );

                        [DllImport("Netapi32.dll", SetLastError = true)]
                        public extern static Int32 NetShareSetInfo(
                            [MarshalAs(UnmanagedType.LPWStr)] string servername,
                            [MarshalAs(UnmanagedType.LPWStr)] string netname, Int32 level,IntPtr bufptr, out Int32 parm_err);


                    }

                    // ***** Functions *****
                    public static SHARE_INFO_502 NetShareGetInfo_502(string ServerName, string ShareName)
                    {
                        Int32 level = 502;
                        IntPtr lShareInfo = IntPtr.Zero;
                        SHARE_INFO_502 shi502_Info = new SHARE_INFO_502();
                        Int32 result = unmanaged.NetShareGetInfo(ServerName, ShareName, level, ref lShareInfo);
                        if ((Share_ReturnValue)result == Share_ReturnValue.NERR_Success)
                        {
                            shi502_Info = (SHARE_INFO_502)Marshal.PtrToStructure(lShareInfo, typeof(SHARE_INFO_502));
                        }
                        else
                        {
                            throw new Exception("Unable to get 502 structure.  Function returned: " + (Share_ReturnValue)result);
                        }
                        return shi502_Info;
                    }

                    public static SHARE_INFO_1005 NetShareGetInfo_1005(string ServerName, string ShareName)
                    {
                        Int32 level = 1005;
                        IntPtr lShareInfo = IntPtr.Zero;
                        SHARE_INFO_1005 shi1005_Info = new SHARE_INFO_1005();
                        Int32 result = unmanaged.NetShareGetInfo(ServerName, ShareName, level, ref lShareInfo);
                        if ((Share_ReturnValue)result == Share_ReturnValue.NERR_Success)
                        {
                            shi1005_Info = (SHARE_INFO_1005)Marshal.PtrToStructure(lShareInfo, typeof(SHARE_INFO_1005));
                        }
                        else
                        {
                            throw new Exception("Unable to get 1005 structure.  Function returned: " + (Share_ReturnValue)result);
                        }
                        return shi1005_Info;
                    }

                    public static int NetShareSetInfo_1005(string ServerName, string ShareName, SHARE_INFO_1005 shi1005_Info) //  Int32 Shi1005_flags
                    {
                        Int32 level = 1005;
                        Int32 err;

                        IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(shi1005_Info));
                        Marshal.StructureToPtr(shi1005_Info, ptr, false);

                        var result = unmanaged.NetShareSetInfo(ServerName, ShareName, level, ptr, out err);

                        return result;
                    }

                }
"@
        }
    }

    Process {
        foreach ($S in $ShareName) {
            Try {
                $ShareInfo = [NetApi32]::NetShareGetInfo_1005($ComputerName, $S)

                if ($ShareInfo.Shi1005_flags -eq ($ShareInfo.Shi1005_flags -bor [Shi1005_flags]::SHI1005_FLAGS_ACCESS_BASED_DIRECTORY_ENUM)) {
                    Write-Verbose "Access Based Enumeration is enabled on share '$S' for '$ComputerName'"
                    [PSCustomObject]@{
                        ComputerName = $ComputerName
                        ShareName    = $S
                        EnabledABE   = $true
                    }
                }
                else {
                    Write-Verbose "Access Based Enumeration is disabled on share '$S' for '$ComputerName'"
                    [PSCustomObject]@{
                        ComputerName = $ComputerName
                        ShareName    = $S
                        EnabledABE   = $false
                    }
                }
            }
            Catch {
                throw "Failed retrieving Access Based Enumeration status on share '$S' for '$ComputerName': $_"
            }
        }
    }
}
Workflow Get-DFSDetailsHC {
    <#
    .SYNOPSIS
        Gets DNS details for a UNC path.

    .DESCRIPTION
        The Get-DFSDetails CmdLet gets DFS details like DFS Server name, DFS 
        Share name and the local path on the DFS Server for a specific UNC path.

    .PARAMETER Credentials
        PowerShell credential object used to connect to the DNS Server to 
        retrieve the local path on the server.

    .PARAMETER Path
        Specifies a UNC path for the folder.

    .EXAMPLE
        Gets the DNS details for two UNC paths.

        '\\contoso.net\HOME\Mike', '\\contoso.net\HOME\Jake' | Get-DFSDetails

        Path         : \\contoso.net\HOME\Mike
        ComputerName : SERVER1.CONTOSO.NET
        ComputerPath : E:\HOME

        Path         : \\contoso.net\HOME\Jake
        ComputerName : SERVER1.CONTOSO.NET
        ComputerPath : E:\HOME
    #>

    [CmdLetBinding()]
    Param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [String[]]$Path
    )

    Sequence {
        $Signature = @'
using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Runtime.InteropServices;

public class Win32Api {
    [DllImport("netapi32.dll", SetLastError = true)]
    private static extern int NetApiBufferFree(IntPtr buffer);

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int NetDfsGetClientInfo (
    [MarshalAs(UnmanagedType.LPWStr)] string EntryPath,
    [MarshalAs(UnmanagedType.LPWStr)] string ServerName,
    [MarshalAs(UnmanagedType.LPWStr)] string ShareName,
    int Level,
    ref IntPtr Buffer
    );
    public struct DFS_INFO_3 {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string EntryPath;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Comment;
        public UInt32 State;
        public UInt32 NumberOfStorages;
        public IntPtr Storages;
    }
    public struct DFS_STORAGE_INFO {
        public Int32 State;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string ServerName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string ShareName;
    }

    public static List<PSObject> NetDfsGetClientInfo(string DfsPath) {
        IntPtr buffer = new IntPtr();
        List<PSObject> returnList = new List<PSObject>();

        try {
            int result = NetDfsGetClientInfo(DfsPath, null, null, 3, ref buffer);

            if (result != 0) {
                throw (new SystemException("Error getting DFS information"));
            }
            else {
                DFS_INFO_3 dfsInfo = (DFS_INFO_3)Marshal.PtrToStructure(buffer, typeof(DFS_INFO_3));

                for (int i = 0; i < dfsInfo.NumberOfStorages; i++) {
                    IntPtr storage = new IntPtr(dfsInfo.Storages.ToInt64() + i * Marshal.SizeOf(typeof(DFS_STORAGE_INFO)));

                    DFS_STORAGE_INFO storageInfo = (DFS_STORAGE_INFO)Marshal.PtrToStructure(storage, typeof(DFS_STORAGE_INFO));

                    PSObject psObject = new PSObject();

                    psObject.Properties.Add(new PSNoteProperty("State", storageInfo.State));
                    psObject.Properties.Add(new PSNoteProperty("ServerName", storageInfo.ServerName));
                    psObject.Properties.Add(new PSNoteProperty("ShareName", storageInfo.ShareName));

                    returnList.Add(psObject);
                }
            }
        }
        catch (Exception e) {
            throw(e);
        }
        finally {
            NetApiBufferFree(buffer);
        }
        return returnList;
    }
}
'@

        $DFS = foreach -parallel ($P in $Path) {
            InlineScript {
                Try {
                    $P = $Using:P

                    Write-Verbose "Get DFS client info for '$P'"

                    if (-not (Test-Path -LiteralPath $P -PathType Container)) {
                        throw 'Path not found'
                    }

                    if (-not ('Win32Api' -as [Type])) {
                        Add-Type -TypeDefinition $Using:Signature
                    }

                    # State 6 indicates that the DFS path is online and active
                    [Win32Api]::NetDfsGetClientInfo($P) | Where-Object State -EQ 6 |
                    Select-Object @{N = 'Path'; E = { $P } }, ServerName, ShareName
                }
                Catch {
                    Write-Error "Failed retrieving DFS details for path '$P': $_"
                }
            }
        }

        $Shares = InlineScript {
            foreach ($ServerName in ($Using:DFS.ServerName | Sort-Object -Unique)) {
                foreach ($ShareName in (($Using:DFS | 
                            Where-Object { $_.ServerName -eq $ServerName }).ShareName |
                        Sort-Object -Unique)) {
                    Try {
                        Write-Verbose "Get local path for share '$ShareName' on '$ServerName'"

                        $Params = @{
                            ComputerName        = $ServerName
                            ClassName           = 'Win32_Share'
                            OperationTimeoutSec = 20
                            Verbose             = $false
                            ErrorAction         = 'Stop'
                        }
                        Get-CimInstance @Params | 
                        Where-Object { $_.Name -EQ $ShareName } |
                        Select-Object @{N = 'ComputerName'; E = { $_.PSComputerName } },
                        @{N = 'ComputerPath'; E = { $_.Path } },
                        @{N = 'ShareName'; E = { $ShareName } }
                    }
                    Catch {
                        Write-Error "Failed retrieving DFS details for path '$ShareName' on '$ServerName': $_"
                    }
                }
            }
        }

        foreach -parallel ($D in $DFS) {
            InlineScript {
                Try {
                    $D = $Using:D
                    $Shares = $Using:Shares

                    foreach ($S in $Shares) {
                        $Result = $D | Where-Object {
                            ($_.ServerName -eq $S.ComputerName) -and
                            ($_.ShareName -eq $S.ShareName)
                        } |
                        Select-Object Path, @{N = 'ComputerName'; E = { $_.ServerName } },
                        @{N = 'ComputerPath'; E = { $S.ComputerPath + '\' + (Split-Path $_.Path -Leaf) } }

                        if ($Result) {
                            Write-Verbose "'$($Result.Path)', '$($Result.ComputerName)', '$($Result.ComputerPath)'"
                            $Result
                        }
                    }
                }
                Catch {
                    Write-Error "Failed retrieving DFS details: $_"
                }
            }
        }
    }
}

Workflow Out-PermissionsOnFolderHC {
    <#
    .SYNOPSIS
        Retrieve permissions for a specific user on a specific folder and export
        them to a file.

    .DESCRIPTION
        Retrieve the permissions set on a folder for a specific users based on 
        SamAccountName. The tool AccessCheck from SysInternals is used. The 
        results are saved in a file per user name and per location.

    .PARAMETER AccessChk
        Full path to the AccessChk executable from SysInternals.

    .PARAMETER SamAccountName
        Name of the user in active directory.

    .PARAMETER Path
        Path where to check the permissions.

    .EXAMPLE
        Generates one output file per folder per user with only the read and 
        read/write permissions in them.
    
        $PermParams = @{
            Path = @(Get-ChildItem '\\contoso.net\bnl\Departments' | 
                Where-Object {Test-Path $_.FullName} |
                Select-Object -ExpandProperty FullName) + '\\contoso.net\bnl'
            SamAccountName = @('bob','mike')
            LogFolder = 'T:\Log'
        }
        Out-PermissionsOnFolderHC @PermParams -Verbose

    .NOTES
        Accesschk v6.10 - Reports effective permissions for securable objects
        Copyright (C) 2006-2016 Mark Russinovich
        Sysinternals - www.sysinternals.com

        usage: accesschk [-s][-e][-u][-r][-w][-n][-v]-[f <account>,...][[-a]|[-k]|[-m]|[-p [-f] [-t]]|[-h][-o [-t <obje
        ct type>]][-c]|[-d]] [[[-l|-L] [-i]]|[username]] <file, directory, event log, registry key, process, service, o
        bject>
           -a     Name is a Windows account right. Specify '*' as the name to show all
                  rights assigned to a user. Note that when you specify a specific
                  right, only groups and accounts directly assigned the right are
                  displayed.
           -c     Name is a Windows Service e.g. ssdpsrv. Specify '*' as the
                  name to show all services and 'scmanager' to check the security
                  of the Service Control Manager.
           -d     Only process directories or top level key.
           -e     Only show explicitly set Integrity Levels (Windows Vista and
                  higher only).
           -f     If following -p, shows full process token information including
                  groups and privileges. Otherwise is a list of comma-separated
                  accounts to filter from the output.
           -h     Name is a file or printer share. Specify '*' as the name to show
                  all shares.
           -i     Ignore objects with only inherited ACEs when dumping full access
                  control lists.
           -k     Name is a Registry key e.g. hklm\software
           -l     Show full security descriptor. Add -i to ignore inherited ACEs.
                  Specify upper-case L to have the output format as SDDL.
           -m     Name is an event log (specify '*' as the name to show all event logs.
           -n     Show only objects that have no access.
           -o     Name is an object in the Object Manager namespace (default is root).
                  To view the contents of a directory, specify the name with a trailing
                  backslash or add -s. Add -t and an object type (e.g. section) to
                  see only objects of a specific type.
           -p     Name is a process name or PID e.g. cmd.exe (specify '*' as the
                  name to show all processes). Add -f to show full process
                  token information including groups and privileges. Add -t to show
                  threads.
           -nobanner
                  Do not display the startup banner and copyright message.
           -r     Show only objects that have read access.
           -s     Recurse.
           -t     Object type filter e.g. "section"
           -u     Suppress errors.
           -v     Verbose (includes Windows Vista Integrity Level).
           -w     Show only objects that have write access.

        If you specify a user or group name and path AccessChk will report the
        effective permissions for that account; otherwise it will show the effective
        access for accounts referenced in the security descriptor.

        By default the path name is interpreted as a file system path (use the
        "\pipe\" prefix to specify a named pipe path). For each object AccessChk
        prints R if the account has read access, W for write access and nothing if
        it has neither. The -v switch has AccessChk dump the specific
        accesses granted to an account.
    #>

    [CmdLetBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path -Path $_ -Type Leaf })]
        [String]$AccessChk = 'D:\Sysinternals\AccessChk\accessChk64.exe',
        [Parameter(Mandatory)]
        [ValidateScript({ Get-ADObject -Filter { SamAccountName -eq $_ } })]
        [String[]]$SamAccountName,
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $_ -Type Container })]
        [String[]]$Path,
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path $_ -Type Container })]
        [String]$LogFolder
    )

    foreach -parallel ($S in $SamAccountName) {
        $Details = Get-ADObject -Filter { SamAccountName -eq $S }

        foreach -parallel ($P in $Path) {
            Write-Verbose "SamAccountName '$S' check folder '$P'"

            InlineScript {
                Try {
                    $P = Get-Item $Using:P
                    $LogFile = Join-Path $Using:LogFolder ($Using:Details.Name + ' ' + $P.BaseName + ' .txt')

                    if (Test-Path $LogFile) {
                        throw "Log file '$LogFile' already exists"
                    }

                    $Intro = @"
Name: $($Using:Details.Name)
SamAccountName: $Using:S
Path: $P
Date: $((Get-Date).ToString('dd/MM/yyyy HH:mm'))

"@
                    $Intro | Out-File $LogFile
                    &$Using:AccessChk $Using:S $P -usd -nobanner | Where-Object { $_ -match '^R|^RW' } | Out-File $LogFile -Append
                }
                Catch {
                    throw "Failed getting the permissions for user '$($Using:S)' on folder '$P': $_"
                }
            }

            Write-Verbose "SamAccountName '$S' check folder '$P' done"
        }
    }
}
Function Push-AclInheritanceHC {
    <#
    .SYNOPSIS
        Apply the permissions from the top folder to all its subfolders 
        and files.

    .DESCRIPTION
        Permissions of subfolders and files are removed and inheritance is 
        enabled. The local administrator is added with 'Full control' 
        permissions on every subfolder and file, and is also added as 'Owner'.

    .PARAMETER Target
        The parent folder from which all the subfolders and files will inherit 
        their permissions.

    .EXAMPLE
        Remove all permissions from the folders within 'Reports' folder and
        enabled inheritance.
        
        Push-AclInheritanceHC 'T:\Departments\Finance\Reports'
    #>

    [CmdletBinding(SupportsShouldProcess = $True)]
    Param (
        [parameter(Mandatory = $true, HelpMessage = 'The path where we need to activate inheritance on all of its subfolders')]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [String]$Target
    )

    Begin {
        $ReadFolder = New-Item -Type Directory -Path "$env:TEMP\ACLfolder"
        $ReadFile = New-Item -Type File -Path "$env:TEMP\ACLfile"

        $AdjustTokenPrivileges = @"
using System;
using System.Runtime.InteropServices;

 public class TokenManipulator
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
  ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  [DllImport("kernel32.dll", ExactSpelling = true)]
  internal static extern IntPtr GetCurrentProcess();
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
  phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name,
  ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool AddPrivilege(string privilege)
  {
   try
   {
    bool retVal;
    TokPriv1Luid tp;
    IntPtr hproc = GetCurrentProcess();
    IntPtr htok = IntPtr.Zero;
    retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
    tp.Count = 1;
    tp.Luid = 0;
    tp.Attr = SE_PRIVILEGE_ENABLED;
    retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
    retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    return retVal;
   }
   catch (Exception ex)
   {
    throw ex;
   }
  }
  public static bool RemovePrivilege(string privilege)
  {
   try
   {
    bool retVal;
    TokPriv1Luid tp;
    IntPtr hproc = GetCurrentProcess();
    IntPtr htok = IntPtr.Zero;
    retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
    tp.Count = 1;
    tp.Luid = 0;
    tp.Attr = SE_PRIVILEGE_DISABLED;
    retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
    retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    return retVal;
   }
   catch (Exception ex)
   {
    throw ex;
   }
  }
 }
"@
    }

    Process {
        # Folders
        Get-ChildItem -Path $Target -Directory -Recurse | 
        Select-Object -ExpandProperty FullName |
        ForEach-Object {
            Write-Verbose $_
            Add-Type $AdjustTokenPrivileges
            $Folder = Get-Item $_
            [void][TokenManipulator]::AddPrivilege('SeRestorePrivilege')
            [void][TokenManipulator]::AddPrivilege('SeBackupPrivilege')
            [void][TokenManipulator]::AddPrivilege('SeTakeOwnershipPrivilege')
            $Owner = New-Object System.Security.AccessControl.DirectorySecurity
            $Admin = New-Object System.Security.Principal.NTAccount('BUILTIN\Administrators')
            $Owner.SetOwner($Admin)
            $Folder.SetAccessControl($Owner)

            # Add folder Admins to ACL with Full Control to descend folder structure
            $acl = Get-Acl -Path $ReadFolder
            $aclr = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'BUILTIN\Administrators', 'FullControl', 'Allow')
            $acl.SetAccessRule($aclr)
            Set-Acl $_ $acl
        }
        Remove-Item $ReadFolder


        # Files
        Get-ChildItem -Path $Target -File -Recurse | Select-Object -ExpandProperty FullName |
        ForEach-Object {
            Write-Verbose $_
            $Admin = New-Object System.Security.Principal.NTAccount('BUILTIN\Administrators')
            $Owner = New-Object System.Security.AccessControl.FileSecurity
            $Owner.SetOwner($Admin)
            [System.IO.File]::SetAccessControl($_, $Owner)

            # Add file Admins to ACL with Full Control and activate inheritance
            $acl = Get-Acl -Path $ReadFile
            $aclr = New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators', 'FullControl', 'Allow')
            $acl.SetAccessRule($aclr)
            Set-Acl $_ $acl
        }
        Remove-Item $ReadFile
    }
}
Function Remove-AclHC {
    <#
    .SYNOPSIS
        Remove all NFTS permissions from a file or folder

    .DESCRIPTION
        Remove all NTFS permissions from a file or folder and remove the inheritance flag. Afterwards only the
        'BUILTIN\Administrators' group is added with 'FullControl'.

    .PARAMETER Path
        FullName of the file or folder

    .EXAMPLE
        Remove all permissions from the path 'Reports'
        Remove-AclHC -Path '\\contoso.net\Share\Reports'

    .EXAMPLE
        Remove the permissions from two folders
        @('T:\Test\Input_Test\SafeQ\New folder', 
        'T:\Test\Input_Test\SafeQ\New folder (2)') | Remove-AclHC -Verbose

    .EXAMPLE
        Remove the permissions from all the subfolders of the folder 'SafeQ'
        Get-ChildItem 'T:\Test\Input_Test\SafeQ' -Recurse | Remove-AclHC -Verbose
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        #[ValidateScript({Test-Path -Path $_})]
        [Alias('FullName')]
        [String[]]$Path
    )

    Begin {
        Function Remove-Permissions {
            $ACL.Access | ForEach-Object { 
                $ACL.PurgeAccessRules($_.IdentityReference) 
            }
            $ACL.SetAccessRuleProtection($true, $false)
        }

        Add-Type $AdjustTokenPrivileges
        [void][TokenManipulator]::AddPrivilege('SeRestorePrivilege')
        [void][TokenManipulator]::AddPrivilege('SeBackupPrivilege')
        [void][TokenManipulator]::AddPrivilege('SeTakeOwnershipPrivilege')
    }

    Process {
        foreach ($P in $Path) {
            Try {
                #$P = Resolve-Path $P
                $Item = Get-Item -LiteralPath $P -Force

                if ($Item.Mode -like 'd*') {
                    # Directory
                    # Become owner
                    $Admin = New-Object System.Security.Principal.NTAccount('BUILTIN\Administrators')
                    $Owner = New-Object System.Security.AccessControl.DirectorySecurity
                    $Owner.SetOwner($Admin)
                    $Item.SetAccessControl($Owner)

                    $ACL = Get-Acl -LiteralPath $P

                    Remove-Permissions

                    # Add local admin
                    $Account = 'BUILTIN\Administrators'
                    $Rights = [System.Security.AccessControl.FileSystemRights]::FullControl
                    $Inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
                    $Propagation = [System.Security.AccessControl.PropagationFlags]::None
                    $AllowDeny = [System.Security.AccessControl.AccessControlType]::Allow
                }
                else {
                    # File
                    # Become owner
                    $Admin = New-Object System.Security.Principal.NTAccount('BUILTIN\Administrators')
                    $Owner = New-Object System.Security.AccessControl.FileSecurity
                    $Owner.SetOwner($Admin)
                    $Item.SetAccessControl($Owner)

                    $ACL = Get-Acl -LiteralPath $P

                    Remove-Permissions

                    # Add local admin
                    $Account = 'BUILTIN\Administrators'
                    $Rights = [System.Security.AccessControl.FileSystemRights]::FullControl
                    $Inheritance = [System.Security.AccessControl.InheritanceFlags]::None
                    $Propagation = [System.Security.AccessControl.PropagationFlags]::None
                    $AllowDeny = [System.Security.AccessControl.AccessControlType]::Allow
                }

                $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule ($Account, $Rights, $Inheritance, $Propagation, $AllowDeny)
                $ACL.AddAccessRule($Rule)

                Set-Acl -LiteralPath $P -AclObject $ACL -ErrorAction Stop
                Write-Verbose "Removed all permissions from '$P' and set 'BUILTIN\Administrators' with 'FullControl'"
            }
            Catch {
                throw "Failed removing permissions from '$P': $_"
            }
        }
    }
}
Function Set-AccessBasedEnumerationHC {
    <#
    .SYNOPSIS
        Set Access Based Enumeration (ABE) on a shared folder.

    .DESCRIPTION
        Set Access Based Enumeration (ABE) on a shared folder to 'Enabled' or 
        'Disabled'.

    .PARAMETER ComputerName
        Specifies the target computer.

    .PARAMETER ShareName
        Name of the share.

    .PARAMETER Type
        Type can be 'Enabled' then ABE will be set to TRUE or 'Disabled' then
        ABE will be set to FALSE.

    .EXAMPLE
        'Finance', 'Reports'| Set-AccessBasedEnumerationHC PC1 -Type Enabled
        Sets the Access Based Enumeration to 'Enabled' for two shared folders on <ComputerName>

        ComputerName : PC1
        ShareName    : Finance
        EnabledABE   : True

        ComputerName : PC1
        ShareName    : Reports
        EnabledABE   : True
    #>

    [CmdLetBinding()]
    Param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [String]$ShareName,
        [Parameter(Mandatory)]
        [ValidateSet('Enabled', 'Disabled')]
        $Type,
        [ValidateNotNullOrEmpty()]
        [String]$ComputerName = $env:COMPUTERNAME
    )

    Begin {
        if (-not([System.Management.Automation.PSTypeName]'NetApi32').Type) {
            Add-Type -TypeDefinition @"
                using System;
                using System.Collections.Generic;
                using System.Runtime.InteropServices;
                using System.Text;


                public enum Share_Type : uint
                {
                    STYPE_DISKTREE = 0x00000000,   // Disk Drive
                    STYPE_PRINTQ = 0x00000001,   // Print Queue
                    STYPE_DEVICE = 0x00000002,   // Communications Device
                    STYPE_IPC = 0x00000003,   // InterProcess Communications
                    STYPE_SPECIAL = 0x80000000,   // Special share types (C$, ADMIN$, IPC$, etc)
                    STYPE_TEMPORARY = 0x40000000   // Temporary share
                }

                public enum Share_ReturnValue : int
                {
                    NERR_Success = 0,
                    ERROR_ACCESS_DENIED = 5,
                    ERROR_NOT_ENOUGH_MEMORY = 8,
                    ERROR_INVALID_PARAMETER = 87,
                    ERROR_INVALID_LEVEL = 124, // unimplemented level for info
                    ERROR_MORE_DATA = 234,
                    NERR_BufTooSmall = 2123, // The API return buffer is too small.
                    NERR_NetNameNotFound = 2310 // This shared resource does not exist.
                }

                [System.Flags]
                public enum Shi1005_flags
                {
                    SHI1005_FLAGS_DFS = 0x0001,  // Part of a DFS tree (Cannot be set)
                    SHI1005_FLAGS_DFS_ROOT = 0x0002,  // Root of a DFS tree (Cannot be set)
                    SHI1005_FLAGS_RESTRICT_EXCLUSIVE_OPENS = 0x0100,  // Disallow Exclusive file open
                    SHI1005_FLAGS_FORCE_SHARED_DELETE = 0x0200,  // Open files can be force deleted
                    SHI1005_FLAGS_ALLOW_NAMESPACE_CACHING = 0x0400,  // Clients can cache the namespace
                    SHI1005_FLAGS_ACCESS_BASED_DIRECTORY_ENUM = 0x0800,  // Only directories for which a user has FILE_LIST_DIRECTORY will be listed
                    SHI1005_FLAGS_FORCE_LEVELII_OPLOCK = 0x1000,  // Prevents exclusive caching
                    SHI1005_FLAGS_ENABLE_HASH = 0x2000,  // Used for server side support for peer caching
                    SHI1005_FLAGS_ENABLE_CA = 0X4000   // Used for Clustered shares
                }

                public static class NetApi32
                {

                    // ********** Structures **********

                    // SHARE_INFO_502
                    [StructLayout(LayoutKind.Sequential)]
                    public struct SHARE_INFO_502
                    {
                        [MarshalAs(UnmanagedType.LPWStr)]
                        public string shi502_netname;
                        public uint shi502_type;
                        [MarshalAs(UnmanagedType.LPWStr)]
                        public string shi502_remark;
                        public Int32 shi502_permissions;
                        public Int32 shi502_max_uses;
                        public Int32 shi502_current_uses;
                        [MarshalAs(UnmanagedType.LPWStr)]
                        public string shi502_path;
                        public IntPtr shi502_passwd;
                        public Int32 shi502_reserved;
                        public IntPtr shi502_security_descriptor;
                    }

                    // SHARE_INFO_1005
                    [StructLayout(LayoutKind.Sequential)]
                    public struct SHARE_INFO_1005
                    {
                        public Int32 Shi1005_flags;
                    }



                    private class unmanaged
                    {

                        //NetShareGetInfo
                        [DllImport("Netapi32.dll", SetLastError = true)]
                        internal static extern int NetShareGetInfo(
                            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
                            [MarshalAs(UnmanagedType.LPWStr)] string netName,
                            Int32 level,
                            ref IntPtr bufPtr
                        );

                        [DllImport("Netapi32.dll", SetLastError = true)]
                        public extern static Int32 NetShareSetInfo(
                            [MarshalAs(UnmanagedType.LPWStr)] string servername,
                            [MarshalAs(UnmanagedType.LPWStr)] string netname, Int32 level,IntPtr bufptr, out Int32 parm_err);


                    }

                    // ***** Functions *****
                    public static SHARE_INFO_502 NetShareGetInfo_502(string ServerName, string ShareName)
                    {
                        Int32 level = 502;
                        IntPtr lShareInfo = IntPtr.Zero;
                        SHARE_INFO_502 shi502_Info = new SHARE_INFO_502();
                        Int32 result = unmanaged.NetShareGetInfo(ServerName, ShareName, level, ref lShareInfo);
                        if ((Share_ReturnValue)result == Share_ReturnValue.NERR_Success)
                        {
                            shi502_Info = (SHARE_INFO_502)Marshal.PtrToStructure(lShareInfo, typeof(SHARE_INFO_502));
                        }
                        else
                        {
                            throw new Exception("Unable to get 502 structure.  Function returned: " + (Share_ReturnValue)result);
                        }
                        return shi502_Info;
                    }

                    public static SHARE_INFO_1005 NetShareGetInfo_1005(string ServerName, string ShareName)
                    {
                        Int32 level = 1005;
                        IntPtr lShareInfo = IntPtr.Zero;
                        SHARE_INFO_1005 shi1005_Info = new SHARE_INFO_1005();
                        Int32 result = unmanaged.NetShareGetInfo(ServerName, ShareName, level, ref lShareInfo);
                        if ((Share_ReturnValue)result == Share_ReturnValue.NERR_Success)
                        {
                            shi1005_Info = (SHARE_INFO_1005)Marshal.PtrToStructure(lShareInfo, typeof(SHARE_INFO_1005));
                        }
                        else
                        {
                            throw new Exception("Unable to get 1005 structure.  Function returned: " + (Share_ReturnValue)result);
                        }
                        return shi1005_Info;
                    }

                    public static int NetShareSetInfo_1005(string ServerName, string ShareName, SHARE_INFO_1005 shi1005_Info) //  Int32 Shi1005_flags
                    {
                        Int32 level = 1005;
                        Int32 err;

                        IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(shi1005_Info));
                        Marshal.StructureToPtr(shi1005_Info, ptr, false);

                        var result = unmanaged.NetShareSetInfo(ServerName, ShareName, level, ptr, out err);

                        return result;
                    }

                }
"@
        }
    }

    Process {
        foreach ($S in $ShareName) {
            Try {
                $ShareInfo = [NetApi32]::NetShareGetInfo_1005($ComputerName, $S)

                Switch ($Type) {
                    'Enabled' {
                        if ($ShareInfo.Shi1005_flags -eq ($ShareInfo.Shi1005_flags -bor [Shi1005_flags]::SHI1005_FLAGS_ACCESS_BASED_DIRECTORY_ENUM)) {
                            Write-Verbose "Access Based Enumeration is already enabled on share '$S' for '$ComputerName'"
                            [PSCustomObject]@{
                                ComputerName = $ComputerName
                                ShareName    = $S
                                EnabledABE   = $true
                            }
                        }
                        else {
                            $ShareInfo.Shi1005_flags = ($ShareInfo.Shi1005_flags -bor [Shi1005_flags]::SHI1005_FLAGS_ACCESS_BASED_DIRECTORY_ENUM)

                            if (([NetApi32]::NetShareSetInfo_1005($ComputerName, $S, $ShareInfo)) -eq 0) {
                                Write-Verbose "Access Based Enumeration enabled on share '$S' for '$ComputerName'"
                                [PSCustomObject]@{
                                    ComputerName = $ComputerName
                                    ShareName    = $S
                                    EnabledABE   = $true
                                }
                            }
                            else {
                                throw "Couldn't verify the Access Based Enumeration permissions"
                            }
                        }
                    }
                    'Disabled' {
                        if (-not($ShareInfo.Shi1005_flags -eq ($ShareInfo.Shi1005_flags -bor [Shi1005_flags]::SHI1005_FLAGS_ACCESS_BASED_DIRECTORY_ENUM))) {
                            Write-Verbose "Access Based Enumeration is already disabled on share '$S' for '$ComputerName'"
                            [PSCustomObject]@{
                                ComputerName = $ComputerName
                                ShareName    = $S
                                EnabledABE   = $false
                            }
                        }
                        else {
                            $ShareInfo.Shi1005_flags = 0

                            if (([NetApi32]::NetShareSetInfo_1005($ComputerName, $S, $ShareInfo)) -eq 0) {
                                Write-Verbose "Access Based Enumeration disabled on share '$S' for '$ComputerName'"
                                [PSCustomObject]@{
                                    ComputerName = $ComputerName
                                    ShareName    = $S
                                    EnabledABE   = $false
                                }
                            }
                            else {
                                throw "Couldn't verify the Access Based Enumeration permissions"
                            }
                        }
                    }
                }
            }
            Catch {
                throw "Failed setting Access Based Enumeration to '$Type' on share '$S' for '$ComputerName': $_"
            }
        }
    }
}

Export-ModuleMember -Function * -Alias *