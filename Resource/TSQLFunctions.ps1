#region Server Level Logins and Permission
function Get-SQLServerLevelPermission
{
    PARAM()
$ListServerLevelPermission = @"
    SELECT b.name,
        a.type,
        a.permission_name,
        a.state_desc 
    FROM sys.server_permissions a  
        INNER JOIN sys.server_principals b 
        ON a.grantee_principal_id = b.principal_id 
    WHERE b.name NOT LIKE '%#%' 
    ORDER BY b.name 
"@
    return $ListServerLevelPermission
}
# List Sys Admins
function Get-SQLServerSysAdmins
{
    PARAM()
$ListSysAdmins = @"
    SELECT a.name as Login, 
            a.type_desc,
            CASE a.is_disabled  
                when 1 THEN 'Disable' 
                when 0 THEN 'Enable' 
                End AS IsEnabled
    FROM sys.server_principals a  
      INNER JOIN sys.server_role_members b 
      ON a.principal_id = b.member_principal_id 
    WHERE b.role_principal_id = 3 
    ORDER BY a.name 
"@
    return $ListSysAdmins
}
# List Sys Admins
function Get-SQLServerSecurityLoginPasswordPolicyAudit
{
    $SecurityLoginPasswordPolicyAudit =@"
    SELECT a.name AS SQLServerLogin,
        a.type_desc PolicyDescription,  
        CASE b.is_policy_checked  
            WHEN 1 THEN 'Password Policy Applied' 
            ELSE 
            'Password Policy Not Applied' 
            END AS PolicyStatus, 
        CASE b.is_expiration_checked  
            WHEN 1 THEN 'Password Expiration Check Applied' 
            ELSE 
            'Password Expiration Check Not Applied' 
            END AS ExpirationCheckStatus  
    FROM sys.server_principals a 
        INNER JOIN sys.sql_logins b 
        ON a.principal_id = b.principal_id  
    WHERE a.name NOT LIKE '%#%' 
    ORDER BY a.name 
"@
    return $SecurityLoginPasswordPolicyAudit
}

#endregion Server Level Permission

#region ErrorLog

function Get-ErrorLogConfiguration
{
    PARAM()
    $ListErrorLogConfiguration =@'
    SELECT is_enabled, 
        [path],
        max_size, 
        max_files
    FROM sys.dm_os_server_diagnostics_log_configurations WITH (NOLOCK) OPTION (RECOMPILE);
'@
    return $ListErrorLogConfiguration
}

function Search-SQLErrorLog {
    [CmdletBinding(SupportsShouldProcess=$true, 
                  ConfirmImpact='Medium')]
    PARAM(
    # Arhive file number. 0 = Current
    [Parameter(
        Mandatory=$false,
        ValueFromPipeline=$false,
        Position=0
    )] 
    [int]$Archive = 0,

    # Start Date for search
    [Parameter(
        Mandatory=$false,
        ValueFromPipeline=$false,
        Position=1
    )]
    [ValidateSet("SQL Error Log","SQL Agent")] 
    [string]$ErrorLogType = "SQL Error Log",

    # Primary Search Keyword
    [Parameter(
        Mandatory=$false,
        ValueFromPipeline=$false,
        Position=2
    )]
    [string]$PrimarySearch = $null,

    # Secondary Search for precision filtering
    [Parameter(
        Mandatory=$false,
        ValueFromPipeline=$false,
        Position=3
    )]
    [string]$SecondarySearch = $null,

    # Start Date for search
    [Parameter(
        Mandatory=$false,
        ValueFromPipeline=$false,
        Position=4
    )]
    [DateTime]$StartDate,

    # End Date for search
    [Parameter(
        Mandatory=$false,
        ValueFromPipeline=$false,
        Position=5
    )]
    [DateTime]$EndDate,

    # Results Order: ‘asc’= ascendant, ‘desc’= descendent
    [Parameter(
        Mandatory=$false,
        ValueFromPipeline=$false,
        Position=6
    )]
    [ValidateSet("ASC","DESC")] 
    [string]$ResultOrder = "ASC"
    )
<#
    ERROR LOG PARAMETERS
1.       Error log file you want to read: 0 = Actual, 1 = Archive #1, 2= Archive #2, and so on.
2.       Type of error log you want to read: 1 or NULL = SQL Error Log, 2= SQL Agent.
3.       String Lookup 1; string of characters to filter the show results.
4.       String Lookup 2; secondary string of characters to filter the show results, an do a precise lookup
5.       Beginning Date/Hour lookup: to look from this date and hour
6.       Ending Date/Hour lookup: to look until this date and hour
7.       Results Order: ‘asc’= ascendant, ‘desc’= descendent
#>
    [int]$LogType = 1 
    if($ErrorLogType -EQ 'SQL Agent'){$LogType = 2}

    # This query will search only the SQL Error Log thus parameter #2 is hardcoded to 1
    $SearchErrorlogQuery = "EXEC master.sys.xp_readerrorlog $Archive, $LogType, "
    if($PrimarySearch){$SearchErrorlogQuery += "'$PrimarySearch', " }else{ $SearchErrorlogQuery += "NULL, "}
    if($SecondarySearch){$SearchErrorlogQuery += "'$SecondarySearch',"}else{ $SearchErrorlogQuery += "NULL, "}
    if($StartDate){$SearchErrorlogQuery += "'$StartDate',"}else{ $SearchErrorlogQuery += "NULL, "}
    if($EndDate){$SearchErrorlogQuery += "'$EndDate',"}else{ $SearchErrorlogQuery += "NULL, "}
    $SearchErrorlogQuery += "'$ResultOrder'"

    return $SearchErrorlogQuery
}

#endregion Errorlog

#region DatabaseInfo

function Get-SQLDatabaseProperties
{
    PARAM()

    $DatabaseProperties = @'
    SELECT db.[name] AS [DatabaseName], 
        db.recovery_model_desc AS [RecoveryModel], 
        db.state_desc, 
        db.log_reuse_wait_desc AS [Log Reuse Wait Description], 
        CONVERT(DECIMAL(18,2), ls.cntr_value/1024.0) AS [LogSizeInMB], 
        CONVERT(DECIMAL(18,2), lu.cntr_value/1024.0) AS [LogUsedInMB)],
        CAST(CAST(lu.cntr_value AS FLOAT) / CAST(ls.cntr_value AS FLOAT)AS DECIMAL(18,2)) * 100 AS [PercentLogUsed], 
        db.[compatibility_level] AS [DB Compatibility Level], 
        db.page_verify_option_desc AS [PageVerifyOption], 
        db.is_auto_create_stats_on, 
        db.is_auto_update_stats_on,
        db.is_auto_update_stats_async_on, 
        db.is_parameterization_forced, 
        db.snapshot_isolation_state_desc, 
        db.is_read_committed_snapshot_on,
        db.is_auto_close_on, 
        db.is_auto_shrink_on, 
        db.target_recovery_time_in_seconds, 
        db.is_cdc_enabled
    FROM sys.databases AS db WITH (NOLOCK)
        INNER JOIN sys.dm_os_performance_counters AS lu WITH (NOLOCK)
            ON db.name = lu.instance_name
        INNER JOIN sys.dm_os_performance_counters AS ls WITH (NOLOCK)
            ON db.name = ls.instance_name
    WHERE lu.counter_name LIKE N'Log File(s) Used Size (KB)%' 
        AND ls.counter_name LIKE N'Log File(s) Size (KB)%'
        AND ls.cntr_value > 0 OPTION (RECOMPILE);
'@

    return $DatabaseProperties
}

function Get-SQLListDatabaseOrphanedUsers
{
    PARAM()
    $ListDatabaseOrphanedUsers = @"
    EXEC sp_change_users_login 'report'
"@
    return $ListDatabaseOrphanedUsers
}

function Get-SQLLinkDatabaseOrphanedUser
{
    PARAM(
    # Database Account Name
    [Parameter(
        Mandatory=$true,
        ValueFromPipeline=$false,
        Position=0
    )]
    [string]$DatbaseUser,

    # SQL Account Login
    [Parameter(
        Mandatory=$true,
        ValueFromPipeline=$false,
        Position=1
    )]
    [string]$Login
    )

    $LinkDatabaseOrphanedUser = @"
    sp_change_users_login @Action='update_one', @UserNamePattern='$DatbaseUser', 
    @LoginName='$Login';
"@
    return $LinkDatabaseOrphanedUser
}

function Get-SQLRelinkDatabaseOrphanedUser
{
    PARAM(
        # Database Account Name
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$false,
            Position=0
        )]
        [string]$DatbaseUser
    )
    $RelinkDatabaseOrphanedUser =@"
    EXEC sp_change_users_login 'Auto_Fix', '$DatabaseUser'
"@
    return $RelinkDatabaseOrphanedUser
}

function Get-SQLDatabaseSize
{
    PARAM()
    $DatabaseSizes = @'
        SELECT f.name AS [File Name] , 
                f.physical_name AS [Physical Name], 
                CAST((f.size/128.0) AS DECIMAL(15,2)) AS [Total Size in MB],
                CAST(f.size/128.0 - CAST(FILEPROPERTY(f.name, 'SpaceUsed') AS int)/128.0 AS DECIMAL(15,2)) 
                    AS [Available Space In MB], [file_id], fg.name AS [Filegroup Name]
        FROM sys.database_files AS f WITH (NOLOCK) 
            LEFT OUTER JOIN sys.data_spaces AS fg WITH (NOLOCK) 
            ON f.data_space_id = fg.data_space_id OPTION (RECOMPILE);
'@
    return $DatabaseSizes
}

function Get-SQLIOStatsByFile
{
    PARAM()
    $IOStatsByFile = @'
        SELECT DB_NAME(DB_ID()) AS [Database Name], 
                df.name AS [Logical Name], 
                vfs.[file_id], 
                df.physical_name AS [Physical Name], 
                vfs.num_of_reads, vfs.num_of_writes, 
                vfs.io_stall_read_ms, 
                vfs.io_stall_write_ms,
                CAST(100. * vfs.io_stall_read_ms/(vfs.io_stall_read_ms + vfs.io_stall_write_ms) AS DECIMAL(10,1)) AS [IO Stall Reads Pct],
                CAST(100. * vfs.io_stall_write_ms/(vfs.io_stall_write_ms + vfs.io_stall_read_ms) AS DECIMAL(10,1)) AS [IO Stall Writes Pct],
                (vfs.num_of_reads + vfs.num_of_writes) AS [Writes + Reads], 
                CAST(vfs.num_of_bytes_read/1048576.0 AS DECIMAL(10, 2)) AS [MB Read], 
                CAST(vfs.num_of_bytes_written/1048576.0 AS DECIMAL(10, 2)) AS [MB Written],
                CAST(100. * vfs.num_of_reads/(vfs.num_of_reads + vfs.num_of_writes) AS DECIMAL(10,1)) AS [# Reads Pct],
                CAST(100. * vfs.num_of_writes/(vfs.num_of_reads + vfs.num_of_writes) AS DECIMAL(10,1)) AS [# Write Pct],
                CAST(100. * vfs.num_of_bytes_read/(vfs.num_of_bytes_read + vfs.num_of_bytes_written) AS DECIMAL(10,1)) AS [Read Bytes Pct],
                CAST(100. * vfs.num_of_bytes_written/(vfs.num_of_bytes_read + vfs.num_of_bytes_written) AS DECIMAL(10,1)) AS [Written Bytes Pct]
        FROM sys.dm_io_virtual_file_stats(DB_ID(), NULL) AS vfs
            INNER JOIN sys.database_files AS df WITH (NOLOCK)
            ON vfs.[file_id]= df.[file_id]
        OPTION (RECOMPILE);
'@
    return $IOStatsByFile
}



#endregion

#region Instance Info

function Get-SQLListDatabaseNames 
{
    PARAM()
    $ListAllDatabases = @"
    SELECT name 
    FROM sys.databases WITH(NOLOCK)
    OPTION(RECOMPILE);
"@
return $ListAllDatabases
}

function Get-SQLListAllDatabaseOwners
{
    PARAM()
    $ListAllDatabaseOwners = @'
        SELECT name, 
            SUSER_sNAME(owner_sid) as DatabaseOwner 
        FROM sys.databases WITH(NOLOCK) 
        ORDER BY name ASC
        OPTION(RECOMPILE);
'@
 return $ListAllDatabaseOwners
}

function Get-SQLListUserDatabaseNames 
{
    PARAM()
    $ListAllUserDatabases = @"
    SELECT name 
    FROM sys.databases WITH(NOLOCK)
    WHERE name NOT IN ('master', 'model', 'tempdb', 'msdb', 'Resource')
    OPTION(RECOMPILE);
"@

}

function Get-SQLListInstanceProperties
{
    PARAM()
$Query = @'
    --Adapted From - Copyright (C) 2014 Glenn Berry, SQLskills.com
    SELECT ServerName = CONVERT(NVARCHAR(128),SERVERPROPERTY('SERVERNAME'))
    , InstanceName = SERVERPROPERTY('InstanceName')
    , NetBios = CONVERT(NVARCHAR(128),SERVERPROPERTY('COMPUTERNAMEPHYSICALNETBIOS'))  
    , MAXDOP = (SELECT VALUE_IN_USE FROM SYS.CONFIGURATIONS WHERE NAME='MAX DEGREE OF PARALLELISM')   
    , SQLMemory = (SELECT VALUE_IN_USE FROM SYS.CONFIGURATIONS WHERE NAME='MAX SERVER MEMORY (MB)')  
    , Edition = CONVERT(NVARCHAR(128),SERVERPROPERTY('EDITION'))  
    , Collation = CONVERT(NVARCHAR(128),SERVERPROPERTY('COLLATION'))  
    , IsClustered = CONVERT(BIT,SERVERPROPERTY('ISCLUSTERED'))  
    , IsFullTextInstalled = CONVERT(BIT,SERVERPROPERTY('ISFULLTEXTINSTALLED'))  
    , ISIntegratedSecurityOnly = CONVERT(BIT,SERVERPROPERTY('ISINTEGRATEDSECURITYONLY'))  
    , FilestreamConfiguredLevel = CONVERT(TINYINT,SERVERPROPERTY('FILESTREAMCONFIGUREDLEVEL'))  
    , FileStreamEffectiveLevel = CONVERT(TINYINT,SERVERPROPERTY('FILESTREAMEFFECTIVELEVEL'))
    , IsHadrEnabled = SERVERPROPERTY('IsHadrEnabled') 
    , ProductVersion = CONVERT(NVARCHAR(128),SERVERPROPERTY('PRODUCTVERSION'))  
    , SqlCharSetName = CONVERT(NVARCHAR(128),SERVERPROPERTY('SQLCHARSETNAME'))  
    , SqlSortOrderName = CONVERT(NVARCHAR(128),SERVERPROPERTY('SQLSORTORDERNAME')) 
'@
    return $Query
}

function Get-SQLGetServerVersion 
{
    PARAM()
$ListServerVersion =  @'
SELECT @@SERVERNAME AS [ServerName], @@VERSION AS [SQLServerOSVersionInfo];
'@
return $ListServerVersion
}

function Get-SQLGetWindowsOSInfo
{
    PARAM()
    $ListWindowsOSInfo = @'
    --Adapted From Glenn Berry's Diagnostic Information Queries, Copyright (C) 2014 SQLskills.com
    SELECT windows_release AS WindowsRelease, 
        windows_service_pack_level AS WindowsServicePackLevel, 
       windows_sku AS WindowsSKU, 
       os_language_version AS LanguageVersion
    FROM sys.dm_os_windows_info WITH(NOLOCK) 
    OPTION(RECOMPILE);
'@
    return $ListWindowsOSInfo
}

function Get-SQLGetServiceInfo
{
    PARAM()
$SQLServiceInfo = @'
    --Adapted From Glenn Berry's Diagnostic Information Queries, Copyright (C) 2014 SQLskills.com
    SELECT servicename, 
        process_id, 
        startup_type_desc, 
        status_desc, 
        last_startup_time, 
        service_account, 
        is_clustered, 
        cluster_nodename, 
        [filename]
    FROM sys.dm_server_services 
    WITH (NOLOCK) OPTION (RECOMPILE);
'@
    return $SQLServiceInfo
}

function Get-SQLListHostHardwareInfo
{
    PARAM()
$ListSQLHostHardwareInfo = @'
    --Adapted From Glenn Berry's Diagnostic Information Queries, Copyright (C) 2014 SQLskills.com
    SELECT cpu_count AS [LogicalCPUCount], 
        scheduler_count, hyperthread_ratio AS [HyperthreadRatio],
        cpu_count/hyperthread_ratio AS [PhysicalCPUCount], 
        physical_memory_kb/1024 AS [PhysicalMemoryMB], 
        committed_kb/1024 AS [Committed Memory (MB)],
        committed_target_kb/1024 AS [Committed Target Memory (MB)],
        max_workers_count AS [Max Workers Count], 
        affinity_type_desc AS [Affinity Type], 
        sqlserver_start_time AS [SQL Server Start Time], 
        virtual_machine_type_desc AS [Virtual Machine Type]  
    FROM sys.dm_os_sys_info WITH (NOLOCK) OPTION (RECOMPILE);
'@
    return $ListSQLHostHardwareInfo
}

function Get-SQLGetSystemManufacturerAndModel
{
    PARAM()
    $ListSystemManufacturerAndModel = @'
        EXEC xp_readerrorlog 0, 1, "Manufacturer"; 
'@
    return $ListSystemManufacturerAndModel
}

function Get-SQLListSQLCongfigs
{
    PARAM()
    $ListSQLConfiguration = @'
        SELECT name,
			[description], 
               value, 
               value_in_use, 
               minimum, 
               maximum, 
               is_dynamic, 
               is_advanced
        FROM sys.configurations WITH(NOLOCK)
        ORDER BY name 
        OPTION (RECOMPILE);
'@
    return $ListSQLConfiguration
}

function Get-SQLDatabaseFileInfo
{
    PARAM()
    $ListAllDatabaseFileInfo = @'
        --Adapted From Glenn Berry's Diagnostic Information Queries, Copyright (C) 2014 SQLskills.com
        SELECT DB_NAME([database_id]) AS [DatabaseName], 
            [file_id], name, physical_name, type_desc, state_desc,
	        is_percent_growth, growth,
	        CONVERT(bigint, growth/128.0) AS [Growth in MB], 
            CONVERT(bigint, size/128.0) AS [Total Size in MB]
        FROM sys.master_files WITH (NOLOCK)
        WHERE [database_id] > 4 
        AND [database_id] <> 32767
        OR [database_id] = 2
        ORDER BY DB_NAME([database_id]) OPTION (RECOMPILE);
'@
    return $ListAllDatabaseFileInfo
}

function Get-SQLListSqlLUNSpaceInfo
{
    PARAM()
    $ListSqlLUNsSpaceInfo = @'
        --Adapted From Glenn Berry's Diagnostic Information Queries, Copyright (C) 2014 SQLskills.com
        SELECT DISTINCT vs.volume_mount_point, vs.file_system_type, 
        vs.logical_volume_name, CONVERT(DECIMAL(18,2),vs.total_bytes/1073741824.0) AS [Total Size (GB)],
        CONVERT(DECIMAL(18,2),vs.available_bytes/1073741824.0) AS [Available Size (GB)],  
        CAST(CAST(vs.available_bytes AS FLOAT)/ CAST(vs.total_bytes AS FLOAT) AS DECIMAL(18,2)) * 100 AS [Space Free %] 
        FROM sys.master_files AS f WITH (NOLOCK)
        CROSS APPLY sys.dm_os_volume_stats(f.database_id, f.[file_id]) AS vs OPTION (RECOMPILE);
'@
    return $ListSqlLUNsSpaceInfo
}


#endregion

#region Backup Restore

function Get-SQLDatabaseBackupHistory
{
    PARAM($Database)

    $DatabaseBackupHistory = @"
    --Adapted From Glenn Berry's Diagnostic Information Queries, Copyright (C) 2014 SQLskills.com
    SELECT s.database_name as DatabaseName,
    m.physical_device_name as PhysicalDeviceName,
    CAST(CAST(s.backup_size / 1000000 AS INT) AS VARCHAR(14))  AS SizeMB,
    s.backup_start_date AS BackupStartDate,
    CAST(s.first_lsn AS VARCHAR(50)) AS FirstLSN,
    CAST(s.last_lsn AS VARCHAR(50)) AS LastLSN,
    CASE s.[type]
        WHEN 'D' THEN 'Full'
        WHEN 'I' THEN 'Differential'
        WHEN 'L' THEN 'Transaction Log'
        END AS BackupType,
    s.server_name As ServerName,
    s.recovery_model AS RecoveryModel
    FROM msdb.dbo.backupset s
        INNER JOIN msdb.dbo.backupmediafamily m 
            ON s.media_set_id = m.media_set_id
    WHERE s.database_name = '$DatabaseName') 
    ORDER BY  backup_finish_date
"@
    return $DatabaseBackupHistory
}

function Get-SQLAllDatabaseBackupHistory
{
    $DatabaseBackupHistory = @'
    --Adapted From Glenn Berry's Diagnostic Information Queries, Copyright (C) 2014 SQLskills.com
    SELECT s.database_name as DatabaseName,
    m.physical_device_name as PhysicalDeviceName,
    CAST(CAST(s.backup_size / 1000000 AS INT) AS VARCHAR(14))  AS SizeMB,
    s.backup_start_date AS BackupStartDate,
    CAST(s.first_lsn AS VARCHAR(50)) AS FirstLSN,
    CAST(s.last_lsn AS VARCHAR(50)) AS LastLSN,
    CASE s.[type]
        WHEN 'D' THEN 'Full'
        WHEN 'I' THEN 'Differential'
        WHEN 'L' THEN 'Transaction Log'
        END AS BackupType,
    s.server_name As ServerName,
    s.recovery_model AS RecoveryModel
    FROM msdb.dbo.backupset s
        INNER JOIN msdb.dbo.backupmediafamily m 
            ON s.media_set_id = m.media_set_id
    ORDER BY  backup_finish_date
'@
    return $DatabaseBackupHistory
}
#endregion Backup Restore

#region SQL Agent

function Get-SQLAgentJobInfo 
{
    PARAM()
    $ListSQLAgentJobs = @'
        --Copyright (C) 2014 Glenn Berry, SQLskills.com
        SELECT sj.name AS JobName, 
            sj.[description] AS JobDescription, 
            SUSER_SNAME(sj.owner_sid) AS JobOwner,
            sj.date_created AS DateCreated, 
            sj.[enabled] AS IsEnabled, 
            sj.notify_email_operator_id AS NotifyEmailOperatorID, 
            sc.name AS [CategoryName]
        FROM msdb.dbo.sysjobs AS sj WITH (NOLOCK)
            INNER JOIN msdb.dbo.syscategories AS sc WITH (NOLOCK)
            ON sj.category_id = sc.category_id
        ORDER BY sj.name OPTION (RECOMPILE);
'@
    return $ListSQLAgentJobs
}

function Get-SQLAgentAlertInfo
{
    PARAM()
    $ListSQLAgentAlerts = @'
        --Copyright (C) 2014 Glenn Berry, SQLskills.com
        SELECT name, 
            event_source, 
            message_id, 
            severity, 
            [enabled], 
            has_notification, 
            delay_between_responses, 
            occurrence_count, 
            last_occurrence_date, 
            last_occurrence_time
        FROM msdb.dbo.sysalerts WITH (NOLOCK)
        ORDER BY name OPTION (RECOMPILE);
'@
    return $ListSQLAgentAlerts
}

#endregion SQL Agent

#region Instance Performance
function Get-SQLPendingMemoryGrants {
    PARAM()
    $MemoryGrantsPending = @'
        --Adapted From Glenn Berry's Diagnostic Information Queries, Copyright (C) 2014 SQLskills.com
        SELECT @@SERVERNAME AS [ServerName], 
            [object_name] AS ObjectName, 
            cntr_value AS MemoryGrantsPending                                                                                                       
        FROM sys.dm_os_performance_counters WITH (NOLOCK)
        WHERE [object_name] LIKE N'%Memory Manager%' -- Handles named instances
            AND counter_name = N'Memory Grants Pending' OPTION (RECOMPILE);
'@
    return $MemoryGrantsPending
}

function Get-SQLAdHocQueries
{
    PARAM()
    $AdhocQueries = @'
        --Adapted From Glenn Berry's Diagnostic Information Queries, Copyright (C) 2014 SQLskills.com
        SELECT TOP(50) [text] AS [QueryText], 
                cp.cacheobjtype, 
                cp.objtype, 
                cp.size_in_bytes 
        FROM sys.dm_exec_cached_plans AS cp WITH (NOLOCK)
        CROSS APPLY sys.dm_exec_sql_text(plan_handle) 
        WHERE cp.cacheobjtype = N'Compiled Plan' 
            AND cp.objtype IN (N'Adhoc', N'Prepared') 
            AND cp.usecounts = 1
        ORDER BY cp.size_in_bytes DESC OPTION (RECOMPILE);
'@
    return $AdhocQueries
}

#endregion Instance Performance

#region Query Analysis

function Get-SQLAllCUrrentlyRunningQueries
{
    PARAM()
    $AllCurrentlyRunningQueries =@'
    --Adapted From Glenn Berry's Diagnostic Information Queries, Copyright (C) 2014 SQLskills.com
    SELECT r.session_id AS SessionID,
        s.host_name AS HostName,
        s.login_name AS LoginName,
        s.original_login_name As OriginalLoginName,
        r.status As QueryStatus,
        r.command AS Command,
        r.cpu_time AS CPUTime,
        r.total_elapsed_time As TotalElapsedTime,
        t.text as Query_Text AS Query
    FROM sys.dm_exec_requests r
        CROSS APPLY sys.dm_exec_sql_text(sql_handle) t
        INNER JOIN sys.dm_exec_sessions s ON r.session_id = s.session_id
'@
    return $AllCurrentlyRunningQueries
}

function Get-SQLBlockingQueries 
{
    PARAM()
    $BlockingQueries = @'
    --Adapted From Glenn Berry's Diagnostic Information Queries, Copyright (C) 2014 SQLskills.com
    SELECT r.session_id,
        r.blocking_session_id,
        DB_NAME(r.database_id) AS DatabaseName,
        s.host_name AS HostNAme,
        s.login_name AS LoginName,
        s.original_login_name AS OriginalLoginName,
        r.status AS QueryStatus,
        r.command AS Command,
        r.cpu_time AS CPUTime,
        r.total_elapsed_time AS TotalElapsedTime,
        t.text as Query_Text AS Query
    FROM sys.dm_exec_requests r
        CROSS APPLY sys.dm_exec_sql_text(sql_handle) t
        INNER JOIN sys.dm_exec_sessions s ON r.session_id = s.session_id
    WHERE r.blocking_session_id <> 0
'@
    return $BlockingQueries
}

function Get-SQLCachedQueryExecutionCount 
{
    PARAM()
    $CachedQueryExecutionCount = @'
        --Adapted From Glenn Berry's Diagnostic Information Queries, Copyright (C) 2014 SQLskills.com
        SELECT TOP (100) qs.execution_count, 
                qs.total_rows, qs.last_rows, 
                qs.min_rows, qs.max_rows,
                qs.last_elapsed_time, 
                qs.min_elapsed_time, 
                qs.max_elapsed_time,
                total_worker_time, 
                total_logical_reads, 
                SUBSTRING(qt.TEXT,qs.statement_start_offset/2 +1,
                (CASE WHEN qs.statement_end_offset = -1
			        THEN LEN(CONVERT(NVARCHAR(MAX), qt.TEXT)) * 2
	                ELSE qs.statement_end_offset END - qs.statement_start_offset)/2) 
                    AS query_text 
        FROM sys.dm_exec_query_stats AS qs WITH (NOLOCK)
            CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) AS qt
        ORDER BY qs.execution_count DESC OPTION (RECOMPILE);
'@
    return $CachedQueryExecutionCount
}

#endregion Query Analysis

#region SQL Connection

function Get-SQLConnectedLoginCount
{
    PARAM()
    $ConnectedSqlLogins = @'
        --Adapted From Glenn Berry's Diagnostic Information Queries, Copyright (C) 2014 SQLskills.com
        SELECT login_name, 
                [program_name], 
                COUNT(session_id) AS [session_count] 
        FROM sys.dm_exec_sessions WITH (NOLOCK)
        GROUP BY login_name, [program_name]
        ORDER BY COUNT(session_id) DESC OPTION (RECOMPILE);
'@
    return $ConnectedSqlLogins
}

function Get-SQLConnectedClientsIP 
{
    PARAM()
    $ListConnectedClientsIP = @"
        SELECT CONVERT(NVARCHAR(128),SERVERPROPERTY('SERVERNAME')) AS ServerName
        ,LOCAL_NET_ADDRESS AS IPAddressOfSQLServer 
        ,CLIENT_NET_ADDRESS AS ClientIPAddress 
         FROM SYS.DM_EXEC_CONNECTIONS 
"@
    return $ListConnectedClientsIP
}
function Get-SQLTcpInfo 
{
$ListSqlTcpInfo = @'
    --Adapted From Glenn Berry's Diagnostic Information Queries, Copyright (C) 2014 SQLskills.com
    SELECT listener_id, 
        ip_address, 
        is_ipv4, 
        port, 
        type_desc, 
        state_desc, 
        start_time
    FROM sys.dm_tcp_listener_states WITH (NOLOCK) OPTION (RECOMPILE);
'@
    return $ListSqlTcpInfo
}

#endregion SQL COnnection

#region Index

    function Get-IndexMissingInfo {
        $SQLInstanceMissingIndexes = @'
            --Adapted From Glenn Berry's Diagnostic Information Queries, Copyright (C) 2014 SQLskills.com
            SELECT CONVERT(decimal(18,2), user_seeks * avg_total_user_cost * (avg_user_impact * 0.01)) AS [index_advantage], 
                migs.last_user_seek, 
                mid.[statement] AS [Database.Schema.Table],
                mid.equality_columns, 
                mid.inequality_columns, 
                mid.included_columns,
                migs.unique_compiles, 
                migs.user_seeks, 
                migs.avg_total_user_cost, 
                migs.avg_user_impact
            FROM sys.dm_db_missing_index_group_stats AS migs WITH (NOLOCK)
                INNER JOIN sys.dm_db_missing_index_groups AS mig WITH (NOLOCK)
                ON migs.group_handle = mig.index_group_handle
                INNER JOIN sys.dm_db_missing_index_details AS mid WITH (NOLOCK)
                ON mig.index_handle = mid.index_handle
            ORDER BY index_advantage DESC OPTION (RECOMPILE);
'@
        return $SQLInstanceMissingIndexes
    }

#endregion Index

#region TSQL Counters

#endregion TSQL Counters