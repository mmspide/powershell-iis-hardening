# configure-iis.ps1
# Version: 1.2
# Author: kking124 (https://github.com/kking124)
#
# Copyright 2016, 2017
#
# License: MIT
# .SYNOPSIS
#    Tries to configure IIS as a minimal, secure installation on Windows Server 2008 and later
#
# .DESCRIPTION
#     IMPORTANT: Script must be run from Administrator mode.
#     
#     Available Switches:
#       * Retail
#           * Enable IIS Retail Mode
#       * MediumTrust
#           * Set Application Trust Level to Medium and block override
#       * AppPoolConfig
#       * CSP
#           * Set HTTP Header - Content-Security-Policy: default-src 'self'
#           * Set HTTP Header - X-Content-Security-Policy: default-src 'self'
#       * RequireHttpCookies
#           * Adds to HTTP Header - Set-Cookie: httpOnly
#       * SecureCookies
#           * Adds to HTTP Header - Set-Cookie: secure
#       * AppPoolConfig
#           * Install - URL Rewrite (if necessary)
#           * Change HTTP Header - Server: Apache
#           * Set HTTP Header - Cache-Control: no-cache,no-store
#           * Set HTTP Header - X-Content-Type-Options: nosniff
#           * Set HTTP Header - X-Frame-Options: SAMEORIGIN
#           * Set HTTP Header - X-XSS-Protection: 1;mode-block 
#           * Remove HTTP Header - X-Powered-By
#           * Disable Directory Indexing
#       * IisCrypto
#           * Configures TLS to FIPS140
#       * IisSetup
#           * Remove WebDAV, FTP
#       * FTP - Requires IisSetup flag
#           * Installs FTP
#
# .NOTES
#
#     IN CODE COMMENT DESCRIPTORS
#
#     SEE: => reasoning
#     TODO: => functionality to implement
#     REF: => help to implement
#     NOTE: => informative comment
#
#     CHANGELOG
#      1.2
#       - Fixed bug in removal of X-Powered-By header
#       - Moved installation of URL Rewrite to AppPoolConfig from IisSetup
#       - Add switch to install Web Platform Tools 5.0
#      1.1
#       - Converted switches from exclusive to inclusive
#      1.0
#       - Initial Release
#

param(
     #machine config changes
     [switch] $Retail
     #setting trust level
     , [switch] $MediumTrust

     #modify applicationHost.config
     , [switch] $AppPoolConfig

     #set CSP headers
     , [switch] $CSP

     #set cookie headers
     , [switch] $RequireHttpCookies
     , [switch] $SecureCookies

     #iis Crypto
     , [switch] $IisCrypto

     #Setup IIS Environment
     , [switch] $IisSetup
     #Allow FTP - Requires IisSetup
     , [switch] $Ftp
     #Installs Web Platform Tools 5.0
     , [switch] $InstallWebPlatformTools
)
process {
    #region internal functions
    #

    Function Write-Log {
        Param([string] $message, [string] $logfile)
        #$logfile = (Get-Date).ToString("yyyyMMdd")+".log"
        Write-Host ([String]::Format("[{0}]`t{1}", (Get-Date).ToString("yyyy-MM-dd hh:mm:ss"), $message)).ToString()
        ([String]::Format("[{0}]`t{1}", (Get-Date).ToString("yyyy-MM-dd hh:mm:ss"), $message)).ToString() >> $logfile
    }

    Function Test-CommandExists {
        Param($command)
        try {
            $result = Get-Command -Name $command -ListImported
            return $true
        } catch {
            return $false
        }
    }

    Function Get-ServerInfo {
        Param()
        $q = servermanagercmd -query
        $type = "Role"
        $o = @()
        foreach($i in $q) {
            $i = $i.Trim()
            if($i -match "^Servermanagercmd" -or $i.Length -eq 0) {
                continue
            }
            if($i -match "^----- [\w]* -----$") {
                $regex = [regex] '^----- ([\w]*) -----$'
                $type = $regex.Match($i).Groups[1].Value
            } else {
                $i = $i.Split("[]") | Where-Object { $_.Length -gt 0 }
                $state = if ($i[0] -eq "X") {"Enabled"} else {"Disabled"}
                $o+= @{
                    "Installed" = $i[0] -eq "X";
                    "Type"= $type;
                    "State"= $state;
                    "DisplayName"=$i[1].Trim();
                    "FeatureName"= $i[2].Trim();
                }
            }

        }
        return (New-Object –TypeName:PSObject –Prop $o) | Format-Table -Property FeatureName, State, DisplayName, Type, Installed
    }

    Function Install-ServerOption {
        Param($name)
        servermanagercmd -install $name
    }

    Function Remove-ServerOption {
        Param($name)
        servermanagercmd -remove $name
    }
    #endregion

    #region script setup

    $logfilename = (Split-Path -parent $MyInvocation.MyCommand.Definition).ToString() + "\" + (Get-Date).ToString("yyyyMMdd") + ".log" 
    Write-Host "Log file at" $logfilename
    Write-Log "==============================" $logfilename
    Write-Log "Configure IIS Script" $logfilename
    Write-Log "==============================" $logfilename

    #elevated check
    if((whoami /all | select-string S-1-16-12288) -eq $null ) {
        Write-Log "Administrator Mode Required." $logfilename
        throw (new-object System.Management.Automation.PSSecurityException);
    }

    # create tools directory for downloads if it doesn't exist
    pushd (Split-Path -parent $MyInvocation.MyCommand.Definition) -StackName ConfigureIIS
    if(-not (Test-Path .\tools)) {
        New-Item -Path . -Name tools -ItemType directory
        Write-Log ([String]::Format("tools folder created at {0}.", (Resolve-Path .\tools\).Path)).ToString() $logfilename
    }
    popd -StackName ConfigureIIS
    #endregion

    #region Server Configuration
    #

    if($IisSetup) {
        Write-Log "Begin IIS Setup" $logfilename
        Write-Log "Getting Available PS Modules" $logfilename
        $psModules = Get-Module -ListAvailable
        Write-Log "Available PS Module List Retrieved" $logfilename
        #Server 2012+
        if( (Test-CommandExists Get-WindowsOptionalFeature) -and (Test-CommandExists Enable-WindowsOptionalFeature) -and (Test-CommandExists Disable-WindowsOptionalFeature) ) {
            Write-Log "Windows 6.2+ Detected" $logfilename
            $features = Get-WindowsOptionalFeature -Online | Where-Object { -not $_.State.ToString().Equals("Disabled", [System.StringComparison]::CurrentCultureIgnoreCase) }
            Write-Log "Installed Features Retrieved" $logfilename

            if(($features | Where-Object { $_.FeatureName -eq "IIS-WebServerRole" }).Count -eq 0) {
                Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole
                Write-Log "IIS-WebServerRole Enabled" $logfilename
            }

            if($ftp) {
                if(($features | Where-Object { $_.FeatureName -eq "IIS-FTPServer" }).Count -eq 0) {
                    Enable-WindowsOptionalFeature -Online -FeatureName IIS-FTPServer
                    Write-Log "IIS-FTPServer Enabled" $logfilename
                }
            } else {
                if(($features | Where-Object { $_.FeatureName -eq "IIS-FTPServer" }).Count -gt 0) {
                    Disable-WindowsOptionalFeature -Online -FeatureName IIS-FTPServer
                    Write-Log "IIS-FTPServer Disabled" $logfilename
                }
            }

            if(($features | Where-Object { $_.FeatureName -eq "IIS-WebDAV" }).Count -gt 0) {
                Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebDAV
                Write-Log "IIS-WebDAV Disabled" $logfilename
            }
        } 
        elseif ( ($psModules | Where-Object { $_.Name -match "ServerManager" }) -ne $null ) {
            # Windows 2008 R2 way of doing things 
            Write-Log "Windows 6.1 Detected" $logfilename
            Import-Module ServerManager 
            Write-Log "Installed Features Retrieved" $logfilename

            $features = Get-WindowsFeature | Where-Object { $_.Installed } 

            if(($features | Where-Object { $_.Name -eq "Web-Server" }).Count -eq 0) {
                Add-WindowsFeature Web-Server
                Write-Log "IIS-WebServerRole Enabled" $logfilename
            }
            if($ftp) {
                if(($features | Where-Object { $_.Name -eq "Web-Ftp-Server" }).Count -eq 0) {
                    Add-WindowsFeature Web-Ftp-Server
                    Write-Log "IIS-FTPServer Enabled" $logfilename
                }
            } else {
                if(($features | Where-Object { $_.Name -eq "Web-Ftp-Server" }).Count -gt 0) {
                    Remove-WindowsFeature Web-Ftp-Server
                    Write-Log "IIS-FTPServer Disabled" $logfilename
                }
            }

            if(($features | Where-Object { $_.Name -eq "Web-DAV-Publishing" }).Count -gt 0) {
                Remove-WindowsFeature Web-DAV-Publishing
                Write-Log "IIS-WebDAV Disabled" $logfilename
            }
        } 
        else {
            # Windows 2008 way of doing things (see Get-ServerInfo, et. al. functions)
            Write-Log "Windows 6.0 Detected" $logfilename
            $features = Get-ServerInfo | Where-Object { -not $_.State.ToString().Equals("Disabled", [System.StringComparison]::CurrentCultureIgnoreCase) }
            Write-Log "Installed Features Retrieved" $logfilename

            if(($features | Where-Object { $_.FeatureName -eq "Web-Server" }).Count -eq 0) {
                Install-ServerOption Web-Server
                Write-Log "IIS-WebServerRole Enabled" $logfilename
            }
            if($ftp) {
                if(($features | Where-Object { $_.FeatureName -eq "Web-Ftp-Server" }).Count -eq 0) {
                    Install-ServerOption Web-Ftp-Server
                    Write-Log "IIS-FTPServer Enabled" $logfilename
                }
            } else {
                if(($features | Where-Object { $_.FeatureName -eq "Web-Ftp-Server" }).Count -gt 0) {
                    Remove-ServerOption -remove Web-Ftp-Server
                    Write-Log "IIS-FTPServer Disabled" $logfilename
                }
            }

            if(($features | Where-Object { $_.FeatureName -eq "Web-DAV-Publishing" }).Count -gt 0) {
                Remove-ServerOption Web-DAV-Publishing
                Write-Log "IIS-WebDAV Disabled" $logfilename
            }

        }

        #TODO?: Install Administration Pack 1.0 on IIS 7 Machines http://go.microsoft.com/?linkid=9655657

        Write-Log "End IIS Setup"
    } #endif IisSetup

    #region IISCrypto
    #

    if($IisCrypto) {
        Write-Log "Begin SSL Configuration" $logfilename
        pushd (Split-Path -parent $MyInvocation.MyCommand.Definition) -StackName ConfigureIIS
        
        $iisCryptoPath = ".\tools\IISCryptoCli40.exe"
        if(-not (Test-Path $iisCryptoPath)) {
            $client = New-Object System.Net.WebClient
            $client.DownloadFile("https://www.nartac.com/Downloads/IISCrypto/IISCryptoCli40.exe", ((Resolve-Path .\tools).ToString()+"\IISCryptoCli40.exe"))
            Write-Log "IISCrypto Downloaded" $logfilename
        }

        Invoke-Expression (".\tools\IISCryptoCli40.exe /fips140")
        Write-Log "IISCrypto run with /fips140" $logfilename

        popd -StackName ConfigureIIS
        Write-Log "End SSL Configuration" $logfilename
    }
    #endregion

    #endregion

    pushd $env:SystemRoot\System32\inetsrv -StackName ConfigureIIS

    #region Application Host Configuration
    #

    if($AppPoolConfig) {
        Write-Log "Begin applicationHost.config changes" $logfilename
        # remove X-Powered-By
        .\appcmd.exe set config /section:httpProtocol /-customHeaders.["name='X-Powered-By'"] /commit:apphost
        Write-Log "Removed X-Powered-By Header" $logfilename

        # X-AspNetMvc-Version
        # Can't block AspNetMvc at the server level - it's an app level thing.
        #SEE: https://azure.microsoft.com/en-us/blog/removing-standard-server-headers-on-windows-azure-web-sites/

        # Server
        # Can't block Server header at the server level by default. Can be done in web.config from the app level in later versions of IIS
        #SEE: https://azure.microsoft.com/en-us/blog/removing-standard-server-headers-on-windows-azure-web-sites/

        # Set up URL rewrite rule to empty server header. Works in IIS 6 and beyond
        #SEE: http://www.iis.net/learn/extensions/url-rewrite-module/creating-outbound-rules-for-url-rewrite-module
        #SEE: http://stackoverflow.com/questions/1178831/remove-server-response-header-iis7
        #REQUIRE: mod_rewrite
        #check for url_rewrite
        $norewrite = (Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match “IIS URL Rewrite Module”}).Name -eq $null

        if($norewrite) {
            pushd (Split-Path -parent $MyInvocation.MyCommand.Definition) -StackName ConfigureIIS
            #get url_rewrite module
            $client = new-object System.Net.WebClient
            $client.DownloadFile("https://download.microsoft.com/download/6/7/D/67D80164-7DD0-48AF-86E3-DE7A182D6815/rewrite_2.0_rtw_x64.msi", ((Resolve-Path .\tools).ToString()+"\rewrite_2.0_rtw_x64.msi"))
            #install it
            msiexec.exe /i (Resolve-Path .\tools\rewrite_2.0_rtw_x64.msi).Path /qn
            Write-Log "IIS URL Rewrite Module 2 Installed" $logfilename
            popd -StackName ConfigureIIS
        }

        .\appcmd.exe set config -section:system.webServer/rewrite/outboundRules /+["name='server_response'"] /commit:apphost
        .\appcmd.exe set config -section:system.webServer/rewrite/outboundRules /["name='server_response'"].match.serverVariable:"RESPONSE_Server" /["name='server_response'"].match.pattern:".*" /commit:apphost
        #set alternate value here
        .\appcmd.exe set config -section:system.webServer/rewrite/outboundRules /["name='server_response'"].action.type:'Rewrite' /["name='server_response'"].action.value:'Apache' /commit:apphost
        Write-Log "Added Rewrite Rule to Set Server Header to Apache" $logfilename

        # Cache-Control
        .\appcmd.exe set config /section:httpProtocol /+customHeaders.["name='Cache-Control',value='no-cache,no-store'"] /commit:apphost
        Write-Log "Added Cache-Control Header" $logfilename

        # Content-Type-Options
        .\appcmd.exe set config /section:httpProtocol /+customHeaders.["name='X-Content-Type-Options',value='nosniff'"] /commit:apphost
        Write-Log "Added X-Content-Type-Options Header" $logfilename

        # Frame-Options
        .\appcmd.exe set config /section:httpProtocol /+customHeaders.["name='X-Frame-Options',value='SAMEORIGIN'"] /commit:apphost
        Write-Log "Added X-Frame-Options Header" $logfilename

        # XSS-Protection
        .\appcmd.exe set config /section:httpProtocol /+customHeaders.["name='X-XSS-Protection',value='1;mode=block'"] /commit:apphost
        Write-Log "Added X-XSS-Protection Header" $logfilename

        #region hide important .NET folders
        #

        #additional segments to deny
        .\appcmd.exe set config /section:requestFiltering /+hiddenSegments.["segment='global.asax'"] /commit:apphost

        #default IIS denied segments
        .\appcmd.exe set config /section:requestFiltering /+hiddenSegments.["segment='App_Browsers'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+hiddenSegments.["segment='App_Code'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+hiddenSegments.["segment='App_Data'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+hiddenSegments.["segment='App_GLobalResources'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+hiddenSegments.["segment='App_LocalResources'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+hiddenSegments.["segment='Bin'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+hiddenSegments.["segment='web.config'"] /commit:apphost

        #additional file extensions to deny
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.log',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.dll',allowed='false'"] /commit:apphost

        #default IIS denied file extensions
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.vb',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.cs',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.config',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.master',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.resx',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.asax',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.ascx',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.skin',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.browser',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.sitemap',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.csproj',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.vbproj',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.webinfo',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.licx',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.resources',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.mdb',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.vjsproj',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.java',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.jsl',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.ldb',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.dsdgm',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.ssdgm',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.lsad',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.ssmap',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.cd',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.dsprototype',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.lsaprototype',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.sdm',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.sdmDocument',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.mdf',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.ldf',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.ad',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.dd',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.ldd',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.sd',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.adprototype',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.lddprototype',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.exclude',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.refresh',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.compiled',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.msgx',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.vsdisco',allowed='false'"] /commit:apphost
        .\appcmd.exe set config /section:requestFiltering /+fileExtensions.["fileExtension='.rules',allowed='false'"] /commit:apphost

        #endregion

        #region WebDAV
        #

        #disable WebDAV
        #.\appcmd.exe set config /section:system.webServer/webdav/authoring /enabled:false /commit:apphost
        #Write-Host "WebDav authoring disabled" $logfilename

        #endregion

        #region HTTP VERBS

        #DROP TRACING Handler
        #.\appcmd.exe set config /section:handlers /-["name='TRACEVerbHandler'"] /commit:apphost
        #Write-Host "TRACEVerbHandler dropped" $logfilename

        #endregion

        #set DirectoryBrowse to false
        .\appcmd.exe set config /section:system.webServer/directoryBrowse /enabled:false /commit:apphost
        Write-Log "Directory Browsing Disabled" $logfilename

        .\appcmd.exe set config /section:system.web/machineKey /validation:HMACSHA256 /commit:apphost
        Write-Log "machineKey set to HMACSHA256" $logfilename
    } #endif $AppPoolConfig

    # Content-Security-Policy
    #NOTE: requires all content to be served in files from the current FQDN. This is meant to be overridden on a per-application basis.
    if($CSP) {
        .\appcmd.exe set config /section:httpProtocol /+customHeaders.["name='X-Content-Security-Policy',value='default-src%20''self'''"] /commit:apphost
        .\appcmd.exe set config /section:httpProtocol /+customHeaders.["name='Content-Security-Policy',value='default-src%20''self'''"] /commit:apphost
        Write-Log "Added Content-Security-Policy Headers" $logfilename
    }

    #endregion

    #region machine configuration changes
    #

    #$netpaths = Get-NetVersionPaths 
    #$web = new-object system.collections.arraylist;
    #$machine = new-object system.collections.arraylist;

    if($Retail) {
        #SEE: https://msdn.microsoft.com/library/ms228298(v=vs.100).aspx
        .\appcmd.exe set config /section:system.web/deployment /retail:true /commit:machine
        Write-Log "Set Retail Mode" $logfilename
    }
    if($MediumTrust) {
        #SEE: https://msdn.microsoft.com/library/ff648665.aspx#c09618429_006
        .\appcmd.exe set config /section:system.web/trust /level:Medium /commit:webroot
        .\appcmd.exe set config /section:system.web/trust /allowOverride:false /commit:webroot
        Write-Log "Set Medium Trust" $logfilename
    }
    if($RequireHttpCookies) {
        # Add httpOnly to Cookie header - means this cookie cannot be read by javascript
        .\appcmd.exe set config /section:system.web/httpCookies /httpOnlyCookies:true /commit:webroot
        Write-Log "Set HTTP Only Cookies" $logfilename
    }
    if($SecureCookies) {
        # Add secure to Cookie header - means this cookie is only sent over https
        .\appcmd.exe set config /section:system.web/httpCookies /requireSsl:true /commit:webroot
        Write-Log "Set Secure Cookies" $logfilename
    }

    #endregion


    if($InstallWebPlatformTools) {
        Write-Log "Begin Installation: Web Platform Tools" $logfilename
        $nowpt = (Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match “Microsoft Web Platform Installer”}).Name -eq $null

        if($nowpt) {
            pushd (Split-Path -parent $MyInvocation.MyCommand.Definition) -StackName ConfigureIIS
            #get url_rewrite module
            $client = new-object System.Net.WebClient
            $client.DownloadFile("http://download.microsoft.com/download/C/F/F/CFF3A0B8-99D4-41A2-AE1A-496C08BEB904/WebPlatformInstaller_amd64_en-US.msi", ((Resolve-Path .\tools).ToString()+"\WebPlatformInstaller_amd64_en-US.msi"))
            #install it
            msiexec.exe /i (Resolve-Path .\tools\WebPlatformInstaller_amd64_en-US.msi).Path /qn
            Write-Log "Web Platform Installer 5 Installed" $logfilename
            popd -StackName ConfigureIIS
        }
        Write-Log "Completed Installation: Web Platform Tools" $logfilename
    }

    while( (pwd -Stack -StackName ConfigureIIS).Count > 0) {
        popd -StackName ConfigureIIS
    }
    pushd (Split-Path -parent $MyInvocation.MyCommand.Definition) -StackName ConfigureIIS
    rm .\tools\
    popd -StackName ConfigureIIS
}
#REF: http://geekswithblogs.net/nharrison/archive/2011/05/25/updating-the-machine.config--with-powershell.aspx
