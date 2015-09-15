﻿
#Load Module Resources
. "$PSScriptRoot\Resource\TSQLFunctions.ps1"
#. "$PSScriptRoot\Resource\SessionFunctions.ps1"

#Set Private Variables...still working on securely storing session related info
 # $UserConfigDirectory = "$PSScriptRoot\Config\" 
 # $UserConfigFile = "$PSScriptRoot\Config\Sessions.sec"

#region PRIVATE FUNCTIONS
function New-Connection
{
    [CmdletBinding(SupportsShouldProcess=$true, 
                  ConfirmImpact='Medium')]
    Param
    (
        # Named instance of the SQP Server
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$ServerInstance,

        # Database to connect to
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$Database,

        # User Credential to access Database
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$false,
                   Position=3)]
        [PSCredential]$Credential,

        # Select between Integrated Security or SQL Account Authentication
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$false,
                   Position=2)]
        [ValidateSet("Integrated","SQLAccount")] 
        [string]$Security = "Integrated",
        
        # Port if needed
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$false,
                   Position=4)]
        [AllowNull()]
        [int]$Port
    )

    BEGIN
    {
     if($Port)
     {
        if($Port -LE 0 -or $Port -GT 65535)
        {
            Write-Error "Port out of range"
            return;
        }
     }
     if($Security -EQ "SQLAccount")
     {

     }
    }
    PROCESS
    {
        if($Security -EQ 'SQLAccount')
        {
            $Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($($Credential.Password)))
            $UserName = $Credential.UserName
            if($Port)
            {
                 [string]$ConnectionString = "Server=$ServerInstance,$Port; Database=$Database; Integrated Security=false; User ID=$Username; PWD=$Password"
            } 
            else
            {
                [string]$ConnectionString = "Server=$ServerInstance; Database=$Database; Integrated Security=false; User ID=$Username; PWD=$Password"
            }
        }
        elseif($Security = 'Integrated')
        {
            if($Port)
            {
                [string]$ConnectionString = "Server=$ServerInstance,$Port; Database=$Database; Integrated Security=true"
            }
            else
            {
                [string]$ConnectionString = "Server=$ServerInstance; Database=$Database; Integrated Security=true"
            }
        }
        $SqlConnection = New-Object System.Data.SqlClient.SqlConnection($ConnectionString)
        try 
        {
            $SqlConnection.Open()
            $SqlConnection.Close()
        }
        catch [System.Exception]
        {
            Write-Error "Failed to connect to SQL Server. `r`n $_"
            return
        }
    }

    END
    {
        return $SqlConnection
    }
}# end New-Connection

function Run-Query
{
[CmdletBinding(SupportsShouldProcess=$true, 
                  ConfirmImpact='Medium')]
    Param
    (
        # SQL Connection
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SqlClient.SqlConnection]$SqlConnection,

        # Query to run
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$Query
    )
            $cmd = New-Object system.Data.SqlClient.SqlCommand($Query,$SqlConnection) 
            $SqlConnection.Open()
            $ds = New-Object system.Data.DataSet 
            $da = New-Object system.Data.SqlClient.SqlDataAdapter($cmd) 
            [void]$da.fill($ds) 
            $SqlConnection.Close()
            $SqlConnection.Dispose()
            return $ds.Tables[0]
}#end Run-Query

### Have not implemented this function yet in the New-SqlServerClient Object
function Get-SqlExecutionPlan 
{
    [CmdletBinding(SupportsShouldProcess=$true, 
                  ConfirmImpact='Medium')]
    Param
    (
        # SQL Connection
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        [System.Data.SqlClient.SqlConnection]$SqlConnection,

        # Query to run
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$Query
    )
    $QueryPlan =  "set showplan_xml on;`ngo`n$Query"
    return ([xml] (Run-Query -SqlConnection $SqlConnection -Query $QueryPlan).Item( 0)) 
 }

function New-SqlServerClient 
{
<#
.Synopsis
   PowerShell MS SQL DBA Tool based on OOP Design
   allowing SQL connection and methods for quick
   discovery and troubleshooting for DBAs.
.DESCRIPTION
   New-SQLServerClient creates an instance of the 
   SQL Server Client toolkit. Use this advanced
   function to create an object to connect into 
   the target SQL Server and call SQLServerClient methods.
.EXAMPLE
   Create Connection to SQL Server using SQL Account with secure credential
   $Creds = Get-Credential
   $sqlClient = New-SqlServerClient -ServerInstance MyDatabaseServer -Database MyDataBase `
    -Credential $Creds -Security SQLAccount -Port 1433
.EXAMPLE
   Create Connection to SQL Server using current Windows Credentials and default port
   $sqlClient = New-SqlServerClient -ServerInstance MyDatabaseServer -Database MyDataBase
.NOTES
  Many of the queries were adapted from Glen Berry's SQLSKills.com queries.   
  
  Version History
  0.0.1 - 9/12/2015 - Added New-SQLServerClient documentation
  0.0.2 - 9/14/2015 - Added Help Function removed long description

  TODO
   - Complete documentation
   - Add .Help() method calling Get-SqlServerClientHelp
   - Test SQL Agent and Alerts
   - Test Missing Index Query
   - Test .SearchErrorLog


#>
    [CmdletBinding(SupportsShouldProcess=$true, 
                  ConfirmImpact='Medium')]
    [OutputType([pscustomobject])]
    PARAM
    (
        # Named instance of the SQP Server
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$ServerInstance,

        # Database to connect to
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$false,
                   Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$Database,

        # User Credential to access Database
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$false,
                   Position=3)]
        [PSCredential]$Credential,

        # Select between Integrated Security or SQL Account Authentication
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$false,
                   Position=2)]
        [ValidateSet("Integrated","SQLAccount")] 
        [string]$Security = "Integrated",
        
        # Port if needed
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$false,
                   Position=4)]
        [AllowNull()]
        [int]$Port

    )#end PARAM

    BEGIN
    {
        # verify port is within range
        if($Port)
        {
            if($Port -LE 0 -or $Port -GT 65535)
            {
                Write-Error "Parameter Validation Error: specified port $Port is out of range" -ErrorAction Stop
            }
        }

    }#end BEGIN

    PROCESS
    {
        $SqlClient = new-object psobject -Property @{
            _serverInstance = $null
            _database = $null
            _credential = $null
            _security = $null
            _port = $null
        }

        #region {get;set;}
        $SqlClient |Add-Member -MemberType ScriptMethod -Name ServerInstance -Value {
            param
            (
                [Parameter(Mandatory=$false, Position=0)]
                $ServerInstance
            )
            if ($ServerInstance) 
            {
                $this._serverInstance = $ServerInstance.ToString()
            } 
            else 
            {
                $this._serverInstance
            }
        } 
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name Database -Value {
            param
            (
                [Parameter(Mandatory=$false, Position=0)]
                $Database
            )
            if ($Database) 
            {
                $this._database = $Database
            } 
            else 
            {
                $this._database
            }
        }
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name Credential -Value {
            param
            (
                [Parameter(Mandatory=$false, Position=0)]
                $Credential
            )
            if ($Credential) 
            {
                $this._credential = [System.Management.Automation.PSCredential]$Credential
            } 
            else 
            {
                $this._credential
            }
        } 
        
        $SqlClient | Add-Member  -MemberType ScriptMethod -Name Security -Value {
            param
            (
                [Parameter(Mandatory=$false, Position=0)]
                $Security
            )
            if ($Security) 
            {
                $this._security= $Security
            } 
            else 
            {
                $this._security
            }
        } 
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name Port -Value {
            param
            (
                [Parameter(Mandatory=$false, Position=0)]
                $Port
            )
            if ($Port) 
            {
                try
                {
                    [int]$intPort = $Port
                    if(($intPort -GT 0) -AND ($intPort -LT 655536))
                    {
                        $this._port = $intPort
                    }
                    else
                    {
                        write-error "Port not in range" -ErrorAction stop
                    }
                }
                catch
                {
                    write-error "port needs to be an integer" -ErrorAction Stop
                }
            } 
            else 
            {
                $this._port
            }
        }  
        #endregion {get;set;}

        $SqlClient | Add-Member -MemberType ScriptMethod -Name _GetConnection  -Value {
            if($this._port){
                if($this._credential -NE $null)
                {
                    [System.Data.SqlClient.SqlConnection]$Connection = New-Connection -ServerInstance $($this._serverInstance) -Database $($this._database) -Credential $this._credential -Security $this._security -Port $this._port 
                }
                else
                {
                    [System.Data.SqlClient.SqlConnection]$Connection = New-Connection -ServerInstance $this._serverInstance -Database $this._database -Security $this._security
                }
            }
            else
            {
                if($this._credential -NE $null)
                {
                    [System.Data.SqlClient.SqlConnection]$Connection = New-Connection -ServerInstance $this._serverInstance -Database $this._database -Credential $this._credential -Security $this._security
                }
                else
                {
                     [System.Data.SqlClient.SqlConnection]$Connection = New-Connection -ServerInstance $($this._serverInstance) -Database $($this._database) -Security $($this._security)
                }
            }
            return $Connection
        }<#end _GetConnection #> 
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name Execute  -Value {
            PARAM(
                # Queries or query to be executed that will not return a value
                [Parameter(Mandatory=$true,
                       ValueFromPipeline=$false,
                       Position=0)]
                $Query
            )
            try
            {
                [System.Data.SqlClient.SqlConnection]$Connect = $this._GetConnection()
            }
            catch
            {
                Write-Error $_ -ErrorAction Stop
            }
            try
            {
               $results = Run-Query -SqlConnection $Connect -Query $Query
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            #cleanup 
            rv -Name $Connect
            # return the results
            $results
        }<#end Execute #> 
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetDatabases -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLListDatabaseNames
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetDatbases #> 
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetDatabaseOwners -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLListAllDatabaseOwners
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetDatbaseOwners #> 
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetUserDatabaseNames -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLListUserDatabaseNames 
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetUserDatabaseNames #> 
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetServerVersion -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLGetServerVersion 
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetServerVersion #> 
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetWindowsOSInfo -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLGetWindowsOSInfo
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetWindowsOSInfo #> 
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetServiceInfo -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLGetServiceInfo
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetServiceInfo #> 

        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetHostHardwareInfo -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLListHostHardwareInfo
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetHostHardwareInfo #>  
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetSQLCongfigs -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLListSQLCongfigs
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetSQLCongfigs #> 
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetDatabaseFileInfo  -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLDatabaseFileInfo 
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetDatabaseFileInfo #> 
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetSQLLUNInfo  -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLListSqlLUNSpaceInfo 
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetSQLLUNInfo #> 
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetErrorLogConfig  -Value {
            PARAM()
            try
            {
                [string]$Query = Get-ErrorLogConfiguration 
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetErrorLogConfig  #> 

        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetConnectedClientsIP -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLConnectedClientsIP 
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetConnectedClientsIP #> 

        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetTcpInfo  -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLTcpInfo  
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetTcpInfo #> 

        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetConnectedLoginCount  -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLConnectedLoginCount  
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetConnectedLoginCount #>

        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetAllDatabaseBackupHistory  -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLAllDatabaseBackupHistory 
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetAllDatabaseBackupHistory  #> 
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetDatabaseProperties  -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLDatabaseProperties
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetDatabaseProperties #> 
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetDatabaseOrphanedUsers  -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLListDatabaseOrphanedUsers
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetDatabaseOrphanedUsers #> 

        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetAgentAlertInfo  -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLAgentAlertInfo
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetAgentAlertInfo #> 
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetAgentJobInfo -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLAgentJobInfo
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetAgentJobInfo #>

        $SqlClient | Add-Member -MemberType ScriptMethod -Name SearchSQLErrorLog  -Value {
            PARAM(
                # Arhive file number. 0 = Current
                [Parameter(
                    Mandatory=$false,
                    ValueFromPipeline=$false,
                    Position=0
                )] 
                $Archive,

                # Primary Search Keyword
                [Parameter(
                    Mandatory=$false,
                    ValueFromPipeline=$false,
                    Position=1
                )]
                $PrimarySearch,

                # Secondary Search for precision filtering
                [Parameter(
                    Mandatory=$false,
                    ValueFromPipeline=$false,
                    Position=2
                )]
                $SecondarySearch,

                # Start Date for search
                [Parameter(
                    Mandatory=$false,
                    ValueFromPipeline=$false,
                    Position=3
                )]
                $StartDate,

                # End Date for search
                [Parameter(
                    Mandatory=$false,
                    ValueFromPipeline=$false,
                    Position=4
                )]
                $EndDate,

                # Results Order: ‘ASC’= ascendant, ‘DESC’= descendent
                [Parameter(
                    Mandatory=$false,
                    ValueFromPipeline=$false,
                    Position=5
                )]
                $ResultOrder
            )
           
            if(!($Archive)){$IntArchive = 0}
            else
            {
                try{[int]$IntArchive = $Archive}
                catch{Write-Error "First parameter 'Archive' needs to be integer data type"; return}
            }

            $ErrorLogType = "SQL Error Log"
            [string]$Command = "Search-SQLErrorLog -Archive $IntArchive -ErrorLogType 'SQL Error Log' "
            if($PrimarySearch)
            {
                $Command += " -PrimarySearch '$PrimarySearch' "
                if($SecondarySearch) 
                {
                    $Command += " -SecondarySearch '$SecondarySearch' "
                }
            }
            if($StartDate)
            {
                $Command += " -StartDate '$StartDate' "
                if($EndDate)
                {
                    $Command += " -EndDate '$EndDate' "
                }
            }
            if($ResultOrder)
            {
                if($ResultOrder -IN ("ASC", "DESC"))
                {
                    $Command += " -ResultOrder '$ResultOrder' "
                }
                else
                {
                    Write-Error "last parameter -ResultOrder needs to be ASC or DESC"
                }
            }

            try
            {
                [string]$Query = &$Command
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end SearchSQLErrorLog  #>
        
        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetIndexMissing  -Value {
            PARAM()
            try
            {
                [string]$Query = Get-IndexMissingInfo
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetIndexMissingInfo #>

        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetPendingMemoryGrants -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLPendingMemoryGrants
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetPendingMemoryGrants #>

        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetInstanceProperties -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLListInstanceProperties
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetInstanceProperties #>

        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetAdHocQueries -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLAdHocQueries
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetAdHocQueries #>

        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetDatabaseSize -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLDatabaseSize
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetDatabaseSize #>

        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetIOStatsByFile -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLIOStatsByFile
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetIOStatsByFile #>

        $SqlClient | Add-Member -MemberType ScriptMethod -Name GetCachedQueryExecCnt -Value {
            PARAM()
            try
            {
                [string]$Query = Get-SQLCachedQueryExecutionCount
                $results = $this.Execute($Query)
            }
            catch
            {
                write-error $_ -ErrorAction stop
            }
            # return the results
            $results
        }<#end GetCachedQueryExecCnt #>

        #region CONSTRUCTOR
        if($ServerInstance)
        {
        $SqlClient.ServerInstance($ServerInstance)
        }
        if($Database)
        {
            $SqlClient.Database($Database)
        }
        if($Credential)
        {
            $SqlClient.Credential($Credential)
        }
        if($Security)
        {
            $SqlClient.Security($Security)
        }
        if($Port)
        {
            $SqlClient.Port($Port)
        }
        
        #endregion CONSTRUCTOR

    }#end PROCESS

    END
    {   
        return $SqlClient
    }#end END

}#end New-SqlServerClient

Export-ModuleMember -Function New-SqlServerClient

function Get-SqlServerClientHelp
{
    PARAM()

    $AllHelpMessage = @"
    Sql Server Client Methods:
        .Database()
            Returns current database attribute for SQL connection

        .Database("[NewDatabase]")
            Change the current database connection property

        .Execute('[Read-Only TSQL Statement...]')
            User supplies any read-only t-sql query to execute

        .GetAdHocQueries()
            Get the cached AdHoc Queries
            Properties: cacheobjtype
                        objtype
                        QueryText
                        size_in_bytes

        .GetAgentAlertInfo()
            Get information about the SQL Server Agent
            Alert History

        .GetAgentJobInfo()
            Retrieve information About SQL Agent
            Job History

        .GetAllDatabaseBackupHistory()
            Get all backups the SQL instance is tracking.
                The returned result can be large depending
                on the history kept.
            Properties: DatabaseName
                        PhysicalDeviceName
                        SizeMB
                        BackupStartDate
                        FirstLSN
                        LastLSN
                        BackupType
                        ServerName
                        RecoveryModel

        .GetCachedQueryExecCnt()
            Retrieves information about the Cached Queries
                utilized by the SQL Engine.
            Properties: execution_count
                        last_elapsed_time
                        last_rows
                        max_elapsed_time
                        max_rows
                        min_elapsed_time
                        min_rows
                        query_text
                        total_logical_reads
                        total_rows
                        total_worker_time

        .GetConnectedClientsIP()
            Get list of current connected client IPs to the 
                SQL instance
            Properties: ClientIPAddress
                        IPAddressOfSQLServer
                        ServerName

        .GetConnectedLoginCount()
            Returns the login name, program name, and
                session count for the current connections
            Properties: login_name
                        program_name
                        session_count

        .GetDatabases()
            Retrieves all databases on the instance
                Returns System.Data.DataRow
            Properties: name          
            
        .GetDatabaseFileInfo()
            Retrieves information on the data and log files for 
                all databases. Examples of the files are
                .mdf, .ndf, .ldf file location, growth, 
            Properties: DatabaseName
                        file_id
                        growth
                        GrowthInMB
                        is_percent_growth
                        LogicalName
                        PhysicalName
                        state_desc
                        TotalSizeInMB
                        type_desc

        .GetDatabaseProperties()
            Returns list of database properties
            Properties: DatabaseName                   
                        DB Compatibility Level         
                        is_auto_close_on               
                        is_auto_create_stats_on        
                        is_auto_shrink_on              
                        is_auto_update_stats_async_on  
                        is_auto_update_stats_on        
                        is_cdc_enabled                 
                        is_parameterization_forced     
                        is_read_committed_snapshot_on  
                        Log Reuse Wait Description     
                        LogSizeInMB                    
                        LogUsedInMB                   
                        PageVerifyOption               
                        PercentLogUsed                 
                        RecoveryModel                  
                        snapshot_isolation_state_desc  
                        state_desc                     
                        target_recovery_time_in_seconds

        .GetDatabaseOrphanedUsers()
            Get information about database user accounts
            under the connected catalog regarding any
            oprhaned users. Method uses stored procedure
            sp_change_users_login with param 'report'

        .GetDatbaseOwners()
            Retrieves databases and their respective owners
            Properties: DatabaseName
                        DatabaseOwner

        .GetDatabaseProperties()
            Retrieve properties for all databases on the connected SQL instance.
            Properties: DatabaseName
                        DBCompatibilityLevel
                        is_auto_close_on
                        is_auto_create_stats_on
                        is_auto_shrink_on
                        is_auto_update_stats_async_on
                        is_auto_update_stats_on
                        is_cdc_enabled
                        is_parameterization_forced
                        is_read_committed_snapshot_on
                        Log Reuse Wait Description
                        LogSizeInMB
                        LogUsedInMB
                        PageVerifyOption
                        PercentLogUsed
                        RecoveryModel
                        snapshot_isolation_state_desc
                        state_desc
                        target_recovery_time_in_seconds

        .GetDatabaseSize()
            Returns the file size information for current connected database.
            Properties: AvailableSpaceInMB
                        FileName
                        FileGroupName
                        file_id
                        PhysicalName
                        TotalSizeMB

        .GetErrorLogConfig()
            Get the error log configuration to incldue 
                location of the file
            Properties: is_enabled
                        max_files
                        max_size
                        path

        .GetHostHardwareInfo()
            Get Host hardware information for active SQL node
            Properties: AffinityType
                        CommittedMemoryMB
                        CommittedTargetMemoryMB
                        HyperthreadRatio
                        LogicalCPUCount
                        Max Workers Count
                        PhysicalCPUCount
                        PhysicalMemoryMB
                        scheduler_count
                        SQLServerStartTime
                        VirtualMachineType
        .GetServerVersion()
            Retrieve SQL Server Version and Build information
            Properties: ServerName
                        SQLVersion   

        .GetServiceInfo()
            Retrieves the service accounts running SQL Server
            Properties: service_account 
                        servicename 
                        startup_type_desc 
                        status_desc
                        last_startup_time
                        process_id
                        filename
                        is_clustered
                        cluster_nodename

        .GetSQLCongfigs()
            Retrieve the current SQL Server configurations 
            for the instance
            Properties: description
                        is_advanced
                        is_dynamic
                        maximum
                        minimum
                        name
                        value
                        value_in_use

        .GetSQLLUNInfo()
            Retrieve the LUN information where SQL Server 
                active node is accessing and storing the data
            Properties: AvailableSizeGB
                        file_system_type
                        logical_volume_name
                        PercentSpaceFree
                        TotalSizeGB
                        volume_mount_point
        
        .GetTcpInfo()
            Get the TCP information for the SQL Server 
                instance active node
            Properties: ip_address
                        is_ipv4
                        listener_id
                        port
                        start_time
                        state_desc
                        type_desc

        .GetIndexMissing()

        .GetPendingMemoryGrants()
            Retrieve information regarding Pending Memory Grants
                on the connected instance
            Properties: MemoryGrantsPending
                        ObjectName
                        ServerName

        .GetInstanceProperties()
            Returns SQL instance properties.
            Properties: Collation
                        Edition
                        FilestreamConfiguredLevel
                        FileStreamEffectiveLevel
                        InstanceName
                        IsClustered
                        IsFullTextInstalled
                        IsHadrEnabled
                        ISIntegratedSecurityOnly
                        MAXDOP
                        NetBios
                        ProductVersion
                        ServerName
                        SqlCharSetName
                        SQLMemory
                        SqlSortOrderName

        .GetIOStatsByFile()
            Query is specific for current connected database.
                Retrieves I/O data for database files
            Properties: DatabaseName
                        file_id
                        IOStallReadsPct
                        IOStallWritesPct
                        io_stall_read_ms
                        io_stall_write_ms
                        LogicalName
                        ReadMB
                        WrittenMB
                        NumberReadsPct
                        NumberWritePct
                        num_of_reads
                        num_of_writes
                        PhysicalName
                        ReadBytesPct
                        WritesAndReads
                        WrittenBytesPct

        .SearchSQLErrorLog()

        .GetWindowsOSInfo()
            Get host operating system of active SQL Node
            Properties: WindowsRelease
                        WindowsServicePackLevel
                        WindowsSKU
                        LanguageVersion
"@

 $AllHelpMessage
}

Export-ModuleMember -Function Get-SqlServerClientHelp