#Create OUs

        New-ADOrganizationalUnit CHA

#Create Users, add attributes, and add to OU

        $ADUsers = Import-Csv C:\BULKUSERS.csv

   ForEach($User in $ADUsers)
  {
        $displayname = $user.displayname
        $firstname = $user.firstname
        $lastname = $user.lastname
        $city = $user.city
        $ou = $user.ou
        $password = $user.password
        $cn = $user.cn
        

                     New-ADUser -DisplayName $displayname -GivenName $firstname -Surname -$lastname -City $city -Path $ou -Name $cn -Enabled true
       }
       
       

 #Create Groups with same title as OU

       New-ADGroup -Name ATL -GroupCategory Security -GroupScope Universal
       New-ADGroup -Name CHA -GroupCategory Security -GroupScope Universal
       New-ADGroup -Name NY -GroupCategory Security -GroupScope Universal 


       
 #Add each member in group corresponding to city

       $ATLUsers = "Lance Harris", "Alex Harris", "Imani Harris", "Amari Harris"
       $CHAUsers = "Dev Brown", "Abby Harris"
       $NYUsers = "Carline Harris", "Pete Harris"

       Add-ADGroupMember -Identity ATL -Members $ATLUsers
       Add-ADGroupMember -Identity CHA -Members $CHAUsers
       Add-ADGroupMember -Identity NY -Members $NYUsers


#Create and move disablesd users into Disabled Users OU
        New-ADOrganizationalUnit -Name "Disabled Users"
        $newOU = "OU=Disabled Users,DC=Adatum,DC=com"

        Search-ADAccount -AccountDisabled -UsersOnly |
        Select Name,Distinguishedname |

        foreach { 
        Move-ADObject -Identity $_.DistinguishedName -TargetPath $newOU 
                }


#Retrieve all locked accounts
        Search-ADAccount -UsersOnly -LockedOut


#Unlock locked accounts
        Unlock-ADAccount -Identity "Alex Harris"

#Enumerate Expired user accounts
        Search-ADAccount -AccountExpired
       
#Disable user accounts that have that have not been used to logon with in 30 or more days
         get-ADUser -Filter *  -Properties Name,Lastlogontimestamp,PasswordNeverExpires | Where-Object {([datetime]::FromFileTime($_.lastlogontimestamp) -le (Get-Date).adddays(-90)) -and ($_.passwordNeverExpires -ne "true") }
       
#Create list of computers with a particular operating system installed
        Get-ADComputer -Filter 'operatingsystem -like "*server*"'

#Create script to remote restart computer
        Restart-Computer -ComputerName lon-svr1 -Credential ADATUM\administrator -Force

#Create list of computers that have not logged onto the network within 30 days
        $date = (Get-Date).AddDays(-30)
        Get-ADuser -Filter * | where {'lastlogon' -gt $date} | select name

#Stop and start services on remote host
        $name = Read-Host "What computer do you wnat to remote to ?"
        $service = Read-Host "Which service to stop?"        
        get-Service -Name $service -ComputerName $name | stop-service

#Stop and start services on remote host
        $name = Read-Host "What computer do you wnat to remote to ?"
        $process = Read-Host "Which service to stop?"        
        (Get-WmiObject Win32_Process -ComputerName $name | where { $_.ProcessName -match "$process" }).Terminate()

 #List Ip address for a remote host
        $comp =  Read-Host "Host"
        Get-CimInstance -ComputerName $comp -ClassName win32_networkadapterconfiguration | select -Property IPaddress, caption
               
#Retrieve network Adapter properties for remote computers
        $comp =  Read-Host "Host"
        Get-CimInstance -ComputerName $comp -ClassName win32_networkadapterconfiguration | select -Property *  | Out-GridView

#Retrieve disk size and amount of free space on a remote host
        $comp = Read-Host "Host"
        Get-WmiObject -Class win32_logicaldisk -ComputerName $comp | select -Property DeviceID,@{name="DiskSize"; expression={[math]::Truncate(($_.size/1GB))}},@{name="FreeSpace"; expression={[math]::Truncate($_.freespace/1GB)}} 

#Enumerate expired user accounts
        Search-ADAccount -AccountExpired -UsersOnly | select name | measure -property name | Out-GridView
       
       
#Retrieve a list of printers installed on a computer
        $comp = Read-Host "Host"
        Get-Printer -ComputerName $comp | select Name, ComputerName,DeviceType | Out-GridView


#Release and renew DHCP leases on Adapters
        $comp = Read-Host "Host"
        $dhcp = read-host "(1)renewdhcplease or (2)releasedhcplease"


        switch ($dhcp)
             {
                1{ (get-WmiObject  -ComputerName $comp -ClassName win32_networkaDapterconfiguration) | Invoke-WmiMethod -name renewdhcplease}
                2{ (get-WmiObject  -ComputerName $comp -ClassName win32_networkaDapterconfiguration) | Invoke-WmiMethod -name releasedhcplease}
             }

       
        

      
 
