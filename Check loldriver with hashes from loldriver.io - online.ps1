#Set Desktop to save output
$lolDriversPath = "$([Environment]::getfolderpath("Desktop"))\LolDrivers"
try{Get-ChildItem $lolDriversPath -ErrorAction Stop}catch{New-Item $lolDriversPath -ItemType Directory -Force}

#Download and Convert (Use the correct API property names)
$web_client = new-object system.net.webclient
$jsonString = $web_client.DownloadString("https://www.loldrivers.io/api/drivers.json")
$jsonString = $jsonString -replace '"INIT"','"init"'
$loldrivers = $jsonString | ConvertFrom-Json

#Create Array
$VulnerableDrivers = @(
    foreach ($driver in $loldrivers) 
        {
            foreach ($sample in $driver.KnownVulnerableSamples) 
                {
                    $tag = ($driver.Tags | Select-Object -First 1)
                    $date = ($sample.CreationTimestamp -split 'T')[0]
                    [PSCustomObject]@{
                        Tag         = $tag
                        SHA256      = $sample.sha256
                        SHA1        = $sample.sha1
                        Category    = $driver.Category
                        FileName    = $sample.Filename
                        Product     = $sample.Product
                        Description = $sample.Description
                        Created     = $date
                    }
                }
        }
) 

#Save to file for offline use
$out = @('$VulnerableDrivers = @(')
foreach ($vDriver in $VulnerableDrivers) 
    {
        $out += "    @{Tag=`"$($vDriver.Tag)`"; SHA256=`"$($vDriver.SHA256)`"; Category=`"$($vDriver.Category)`"; Created=`"$($vDriver.Created)`"}"
    }
$out += ')'
$out | Out-File "$($lolDriversPath)\lolDrivers.txt" -Encoding utf8

#Now the comparison loop will work!
$driverPath = "C:\Windows\System32\drivers"
$drivers = Get-ChildItem $driverPath -Filter *.sys -File
Write-Host ("Checking {0} drivers in {1} against vulnerability table" -f $drivers.Count, $driverPath) -ForegroundColor Green


foreach ($file in $drivers) 
    {
        #This now works because $VulnerableDrivers is an array of objects
        $matches = $VulnerableDrivers | Where-Object { $_.Tag -eq $file.Name -or $_.FileName -eq $file.Name }

        foreach ($hit in $matches) 
            {
                $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
        
                if ($hash -eq $hit.SHA256) 
                    {
                        Write-Host "[HIT] $($file.Name) matches SHA256! of $($hit.SHA256) - $($hit.category)" -ForegroundColor Red
                    } 
                elseif ([string]::IsNullOrEmpty($hit.SHA256)) 
                    {
                        Write-Host "[HIT] $($file.Name) name match (No Hash in DB) - $($hit.category)" -ForegroundColor Yellow
                    }
            }
    }