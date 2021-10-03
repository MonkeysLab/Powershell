
Import-Module ActiveDirectory

$loctn        = Get-Location

$ConfPath     = Join-Path $loctn -ChildPath "conf.json"

if(Test-Path $ConfPath){}
else{

    $CreateConf = [PSCustomObject]@{
  
        ZabbixIP           = ''
        Token              = ''
        DCIP               = ''
        ADOrganizationUnit = ''

    }

    $CreateConf | ConvertTo-Json | Out-File  $ConfPath

}

Set-Location $loctn.Path #  for using remote function to create token

$Configuration = Get-Content $ConfPath | ConvertFrom-Json

$ctype = "application/json"

$url   = "http://$($Configuration.ZabbixIP)/api_jsonrpc.php"

if('' -eq $Configuration.Token){

    $Configuration.Token = .\zabbixtoken.ps1 -url $url -ctype $ctype

    $Configuration | ConvertTo-Json | Out-File  $ConfPath

}

$token        = $Configuration.Token

$DaysInactive = 30

$InactiveDays = (Get-Date).Adddays(-($DaysInactive))

$ASBPCs       = foreach(
    $pc in (

        Get-ADComputer -SearchBase $Configuration.ADOrganizationUnit -Filter {

            LastLogonTimeStamp -gt $InactiveDays
        
        } -Properties * -Server $Configuration.DCIP)
        
    ){

    [PSCustomObject]@{
    
        name  = $pc.name
        ip    = $pc.IPv4Address

    }       

}

function api {

    param($func, $token, $ip, $hstnm , $ZabbixGroupID, $ZabbixTemplateID)

    switch($func){

        host.get {
            
            @{
                jsonrpc = "2.0"
                method  = "host.get"
                id      = 1
                auth    = $Token
                params  = @{} 

            } | ConvertTo-Json -Depth 20

        }

        hostgroup.get {
            
            @{
                jsonrpc = "2.0"
                method  = "hostgroup.get"
                id      = 1
                auth    = $Token
                params  = @{

                    output = "extend"
                    filter = @{}

                } 

            } | ConvertTo-Json -Depth 20

        }

        template.get {
            
            @{
                jsonrpc = "2.0"
                method  = "template.get"
                id      = 1
                auth    = $Token
                params  = @{

                    output = "extend"
                    filter = @{}

                } 

            } | ConvertTo-Json -Depth 20

        }

        host.create {

            @{

                jsonrpc = '2.0'
                method  = 'host.create'
                auth    = $token
                id      = '1'
                params  = @{
                
                    host       = $hstnm
                    interfaces = @{

                        type  = '1' #1 = agent, 2 = snmp, 3 = ipmi, 4 = jmx
                        main  = '1'
                        useip = '1'
                        ip    = $ip
                        dns   = ''
                        port  = '10050'

                    }
                    groups = @{

                        groupid = $ZabbixGroupID
                    
                    }
                    templates = @{

                        templateid = $ZabbixTemplateID

                    }

                }
        
            } | ConvertTo-Json -Depth 20
                
        }

    }

}

$ZabbixHosts      = Invoke-RestMethod -Uri $url -Body $(api -func "host.get" -token $token) -Method Post -ContentType $ctype

$ZabbixGroupID    = ((Invoke-RestMethod -Uri $url -Body $(api -func "hostgroup.get" -token $token) -Method Post -ContentType $ctype).result.where({$_.name -eq 'Windows'})).groupid

$ZabbixTemplateID = (((Invoke-RestMethod -Uri $url -Body $(api -func "template.get" -token $token) -Method Post -ContentType $ctype)).result | Where-Object {$_.host -eq "Windows by Zabbix agent active"}).templateid

$FiltrPCs         = (Compare-Object $ZabbixHosts.result.host -DifferenceObject $ASBPCs.name | Where-Object {$_.SideIndicator -eq '=>'}).InputObject

if([bool]$FiltrPCs){

    foreach($FiltrPC in $FiltrPCs){

        Invoke-RestMethod -Uri $url -Body $(api -func "host.create" -token $token -ip $($ASBPCs.where({$_.name -eq $FiltrPC})).ip -hstnm $FiltrPC ZabbixGroupID $ZabbixGroupID ZabbixTemplateID $ZabbixTemplateID) -Method Post -ContentType $ctype
    
        #.\remote_install_zabbix.ps1 -name $FiltrPC
    
    }
    
    # for unavailable hosts try to fix
    
    foreach($thost in ($ZabbixHosts.result | Where-Object {$_.available -eq "2"})){
    
        if(Test-Connection -ComputerName $thost.name -Count 1 -Quiet){
    
            try{
    
                $thostservice = Get-Service -ComputerName $thost.name -Name "Zabbix Agent 2"
    
                if($thostservice.status -eq 'Stopped'){
    
                    "For host: $($thost.name) service is $($thostservice.Status)"
    
                    (get-wmiobject -ComputerName $thost.name win32_service -filter "name='Zabbix Agent 2'").startService()
        
                }
                if($thostservice.status -eq 'Running'){
    
                    "For host: $($thost.name) service is $($thostservice.Status)"
    
                    (get-wmiobject -ComputerName $thost.name win32_service -filter "name='Zabbix Agent 2'").StopService()
                    (get-wmiobject -ComputerName $thost.name win32_service -filter "name='Zabbix Agent 2'").startService()
    
                    "After restart agent service status is $((Get-Service -ComputerName $thost.name -Name 'Zabbix Agent 2').Status)"
    
                }
    
            }
            catch{
    
                $error[0]
    
            }
    
        }
        else{
    
            "host $($thost.name) off"
    
        }
    
    }
    

}
else{

    "All fine"

}

pause
