# MSSQLDBA PowerShell Module
PowerShell OOP solution for MS SQL Server DBA using only TSQL for portability on Windows operating systems. The sql client can be initialized by importing the module then using the New-SqlServerClient creating an object for the connection to be stored and reused. 

Currently this only supports read queries; however additional capabilities are being added for basic configuration settings, query tuning, etc.

Example:

Create a credential object to store either windows credential or SQL Account
```Powershell 
$Creds = Get-Credential
```
note: if you are using Windows account which you are running powershell under, you will not need to supply a credential.

Instantiate the object supplying your SQL connection information
```Powershell

$Local = New-SqlServerClient -ServerInstance myComp -Database myDatabase  -Credential $Creds -Security SQLAccount -Port 1433

```

List all database
```Powershell
$Local.ListDatabases()
```

Find orphaned users
```Powershell
$Local.GetDatabaseOrphanedUsers()
```
View current database connected to
```Powershell
$Local.Database()
```
Change database connection
```Powershell
$Local.Database('MyNewDatabase')
```
 
