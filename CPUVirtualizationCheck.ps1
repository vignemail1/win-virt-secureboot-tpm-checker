<#
.SYNOPSIS
    Detecteur de fonctionnalites de virtualisation et securite CPU
.DESCRIPTION
    Ce script detecte si Intel VT-D / AMD SVM, NX (No-eXecute), IOMMU, TPM et BitLocker sont actives.
    
    Parametres:
    -ClearTPM    : Reinitialise le TPM aux valeurs par defaut (ATTENTION: voir avertissements)
    -ExportKeys  : Exporte les cles de recuperation BitLocker
    -Help        : Affiche l'aide
.NOTES
    Fichier      : CPUVirtualizationCheck.ps1
    Auteur       : Super Z
    Necessite    : Windows 10/11, droits administrateur pour certaines informations
#>

param(
    [switch]$ClearTPM,
    [switch]$ExportKeys,
    [switch]$Help
)

# Afficher l'aide si demandee
if ($Help) {
    Write-Host @"
    
===============================================================================
                    CPUVirtualizationCheck.ps1 - AIDE
===============================================================================

USAGE:
    .\CPUVirtualizationCheck.ps1 [options]

OPTIONS:
    -ClearTPM     Reinitialise le TPM aux valeurs par defaut
                  ATTENTION: Necessite une double validation si BitLocker est actif
                  Les cles BitLocker seront perdues si non sauvegardees!
                  
    -ExportKeys   Exporte les cles de recuperation BitLocker vers le Bureau
                  Recommande avant toute operation sur le TPM
    
    -Help         Affiche cette aide

EXEMPLES:
    .\CPUVirtualizationCheck.ps1              # Detection standard
    .\CPUVirtualizationCheck.ps1 -ExportKeys  # Detection + export cles BitLocker
    .\CPUVirtualizationCheck.ps1 -ClearTPM    # Detection + reinitialisation TPM

AVERTISSEMENT:
    La reinitialisation du TPM effacera toutes les donnees stockees dedans,
    y compris les cles BitLocker. Assurez-vous d'avoir sauvegarde les cles
    de recuperation avant de proceder.

===============================================================================
"@ -ForegroundColor Cyan
    exit 0
}

# Configuration des couleurs pour l'affichage
$Host.UI.RawUI.WindowTitle = "Detection Virtualisation CPU et Securite"

function Write-Header {
    param([string]$Title)
    Write-Host "`n" -NoNewline
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Yellow
    Write-Host "=" * 60 -ForegroundColor Cyan
}

function Write-Result {
    param(
        [string]$Feature,
        [bool]$Enabled,
        [string]$Details = ""
    )
    
    $status = if ($Enabled) { "[ACTIVE]" } else { "[DESACTIVE]" }
    $color = if ($Enabled) { "Green" } else { "Red" }
    
    Write-Host "  $Feature : " -NoNewline -ForegroundColor White
    Write-Host $status -ForegroundColor $color
    if ($Details) {
        Write-Host "    -> $Details" -ForegroundColor Gray
    }
}

function Get-CPUVendor {
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    if ($cpu.Manufacturer -match "Intel") { return "Intel" }
    if ($cpu.Manufacturer -match "AMD") { return "AMD" }
    return "Unknown"
}

function Test-IntelVTx {
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        return $cpu.VirtualizationFirmwareEnabled
    }
    catch {
        try {
            $computerInfo = Get-ComputerInfo -Property "HyperV*" -ErrorAction SilentlyContinue
            return $computerInfo.HyperVRequirementVirtualizationFirmwareEnabled
        }
        catch {
            return $false
        }
    }
}

function Test-IntelVTd {
    try {
        $deviceGuard = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ErrorAction SilentlyContinue
        
        $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        if ($cpu.Manufacturer -match "Intel") {
            if ($deviceGuard.EnableVirtualizationBasedSecurity -eq 1) {
                return $true
            }
        }
        
        $computerInfo = Get-ComputerInfo -Property "Device*" -ErrorAction SilentlyContinue
        if ($computerInfo.DeviceGuardRequiredSecurityProperties -match "IOMMU") {
            return $true
        }
        
        return $false
    }
    catch {
        return $false
    }
}

function Test-AMDSVM {
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        if ($cpu.Manufacturer -match "AMD") {
            return $cpu.VirtualizationFirmwareEnabled
        }
        $computerInfo = Get-ComputerInfo -Property "HyperV*" -ErrorAction SilentlyContinue
        return $computerInfo.HyperVRequirementVirtualizationFirmwareEnabled
    }
    catch {
        return $false
    }
}

function Test-NXFeature {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $depAvailable = $os.DataExecutionPrevention_Available
        $depEnabled = $os.DataExecutionPrevention_32BitApplications
        
        $bcdOutput = bcdedit /enum 2>$null
        $nxEnabled = $bcdOutput | Select-String "nx" | Select-String "OptIn|OptOut|AlwaysOn"
        
        return ($depAvailable -and $depEnabled) -or ($null -ne $nxEnabled)
    }
    catch {
        return $false
    }
}

function Test-IOMMU {
    try {
        $cpuVendor = Get-CPUVendor
        $iommuEnabled = $false
        $details = ""
        
        $deviceGuard = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ErrorAction SilentlyContinue
        
        if ($deviceGuard.EnableVirtualizationBasedSecurity -eq 1) {
            $computerInfo = Get-ComputerInfo -ErrorAction SilentlyContinue
            $requiredProps = $computerInfo.DeviceGuardRequiredSecurityProperties
            
            if ($requiredProps -match "IOMMU" -or $requiredProps -contains "IOMMU") {
                $iommuEnabled = $true
                $details = "IOMMU requis pour VBS"
            }
        }
        
        $dmaControllers = Get-PnpDevice -Class "System" -ErrorAction SilentlyContinue | 
                          Where-Object { $_.FriendlyName -match "IOMMU|DMA|AMD-Vi|VT-d" }
        
        if ($dmaControllers.Count -gt 0) {
            $iommuEnabled = $true
            $details = "Peripheriques IOMMU detectes"
        }
        
        return $iommuEnabled, $details
    }
    catch {
        return $false, ""
    }
}

function Get-TPMStatus {
    try {
        $tpmStatus = [PSCustomObject]@{
            IsPresent    = $false
            Version      = "N/A"
            IsEnabled    = $false
            IsActivated  = $false
            Ready        = $false
            Manufacturer = "N/A"
            Details      = ""
        }
        
        if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
            $tpm = Get-Tpm -ErrorAction SilentlyContinue
            
            if ($tpm -and $tpm.TpmPresent) {
                $tpmStatus.IsPresent = $true
                $tpmStatus.IsEnabled = $tpm.TpmEnabled
                $tpmStatus.IsActivated = $tpm.TpmActivated
                $tpmStatus.Ready = $tpm.TpmReady
                
                if (Get-Command Get-TpmEndorsementKeyInfo -ErrorAction SilentlyContinue) {
                    $tpmInfo = Get-TpmEndorsementKeyInfo -ErrorAction SilentlyContinue
                    if ($tpmInfo) {
                        $tpmStatus.Manufacturer = $tpmInfo.ManufacturerId
                    }
                }
            }
        }
        
        $tpmWmi = Get-CimInstance -Namespace "root\cimv2\security\microsofttpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
        
        if ($tpmWmi) {
            $tpmStatus.IsPresent = $true
            
            $versionStr = $tpmWmi.SpecVersion
            if ($versionStr) {
                if ($versionStr -match "^(\d+\.\d+)") {
                    $tpmStatus.Version = $matches[1]
                } else {
                    $tpmStatus.Version = $versionStr
                }
            }
            
            $tpmStatus.IsEnabled = $tpmWmi.IsEnabled_InitialValue
            $tpmStatus.IsActivated = $tpmWmi.IsActivated_InitialValue
            $tpmStatus.Ready = $tpmWmi.IsReady
            
            if ($tpmWmi.ManufacturerIdTxt) {
                $tpmStatus.Manufacturer = $tpmWmi.ManufacturerIdTxt
            } elseif ($tpmWmi.ManufacturerId) {
                $tpmStatus.Manufacturer = $tpmWmi.ManufacturerId
            }
        }
        
        if (-not $tpmStatus.IsPresent) {
            $tpmReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI" -ErrorAction SilentlyContinue
            if ($tpmReg) {
                $tpmStatus.IsPresent = $true
                if ($tpmReg.NoActionRequired -eq 0) {
                    $tpmStatus.Ready = $true
                }
            }
        }
        
        return $tpmStatus
    }
    catch {
        return [PSCustomObject]@{
            IsPresent    = $false
            Version      = "N/A"
            IsEnabled    = $false
            IsActivated  = $false
            Ready        = $false
            Manufacturer = "N/A"
            Details      = "Erreur lors de la detection"
        }
    }
}

function Test-TPMForWindows11 {
    $tpm = Get-TPMStatus
    
    if (-not $tpm.IsPresent) {
        return $false, "TPM non present"
    }
    
    if ($tpm.Version -match "^2\.") {
        if ($tpm.IsEnabled -and $tpm.IsActivated) {
            return $true, "TPM 2.0 actif et pret"
        } else {
            return $false, "TPM 2.0 present mais non active"
        }
    }
    
    if ($tpm.Version -match "^1\.") {
        return $false, "TPM 1.2 present (TPM 2.0 requis pour Windows 11)"
    }
    
    return $false, "Version TPM non determinee"
}

# ==============================================================================
# FONCTIONS BITLOCKER
# ==============================================================================

function Get-BitLockerStatus {
    <#
    .DESCRIPTION
        Recupere le statut BitLocker de tous les lecteurs du systeme
    #>
    try {
        $bitLockerDrives = @()
        $anyBitLockerEnabled = $false
        
        # Obtenir tous les volumes avec BitLocker
        $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
        
        foreach ($vol in $volumes) {
            $driveInfo = [PSCustomObject]@{
                DriveLetter      = $vol.MountPoint
                VolumeType       = $vol.VolumeType
                ProtectionStatus = $vol.ProtectionStatus
                EncryptionStatus = $vol.EncryptionPercentage
                LockStatus       = $vol.LockStatus
                KeyProtector     = $vol.KeyProtector
                HasRecoveryKey   = ($vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }) -ne $null
            }
            
            $bitLockerDrives += $driveInfo
            
            if ($vol.ProtectionStatus -eq 'On') {
                $anyBitLockerEnabled = $true
            }
        }
        
        return @{
            Drives           = $bitLockerDrives
            AnyEnabled       = $anyBitLockerEnabled
            EnabledDrives    = $bitLockerDrives | Where-Object { $_.ProtectionStatus -eq 'On' }
        }
    }
    catch {
        return @{
            Drives           = @()
            AnyEnabled       = $false
            EnabledDrives    = @()
        }
    }
}

function Export-BitLockerRecoveryKeys {
    <#
    .DESCRIPTION
        Exporte toutes les cles de recuperation BitLocker vers un fichier
    #>
    param([string]$ExportPath)
    
    try {
        $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
        $keysExported = @()
        
        foreach ($vol in $volumes) {
            if ($vol.ProtectionStatus -eq 'On') {
                $recoveryKeys = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
                
                foreach ($key in $recoveryKeys) {
                    $keysExported += [PSCustomObject]@{
                        DriveLetter   = $vol.MountPoint
                        KeyID         = $key.KeyProtectorId
                        RecoveryKey   = $key.RecoveryPassword
                        DateExported  = Get-Date -Format 'dd/MM/yyyy HH:mm:ss'
                    }
                }
            }
        }
        
        if ($keysExported.Count -gt 0) {
            $keysExported | Format-Table -AutoSize | Out-File -FilePath $ExportPath -Encoding UTF8
            return $true, $keysExported.Count
        }
        
        return $false, 0
    }
    catch {
        return $false, 0
    }
}

function Show-BitLockerRecoveryKeyProcedure {
    <#
    .DESCRIPTION
        Affiche la procedure pour sauvegarder les cles de recuperation BitLocker
    #>
    
    Write-Host "`n" -NoNewline
    Write-Host "=" * 60 -ForegroundColor Red
    Write-Host "  PROCEDURE DE SAUVEGARDE DES CLES BITLOCKER" -ForegroundColor Yellow
    Write-Host "=" * 60 -ForegroundColor Red
    
    Write-Host @"

  IMPORTANT: Avant de reinitialiser le TPM, vous DEVEZ sauvegarder 
  vos cles de recuperation BitLocker. Sans ces cles, vous ne pourrez
  plus acceder a vos disques chiffres!

  METHODE 1: Via les parametres Windows
  --------------------------------------
  1. Ouvrir Parametres > Confidentialite et securite > Chiffrement BitLocker
  2. Cliquer sur le lecteur chiffre
  3. Cliquer sur "Sauvegarder la cle de recuperation"
  4. Choisir l'emplacement de sauvegarde:
     - Compte Microsoft (recommande)
     - Fichier USB
     - Fichier sur un autre lecteur
     - Imprimer

  METHODE 2: Via l'invite de commandes (admin)
  --------------------------------------------
  1. Ouvrir CMD en administrateur
  2. Executer: manage-bde -protectors -get C:
  3. Noter la "Mot de passe de recuperation" (48 chiffres)
  4. Repeter pour chaque lecteur chiffre

  METHODE 3: Export automatique via ce script
  -------------------------------------------
  Executer: .\CPUVirtualizationCheck.ps1 -ExportKeys

  CONSEILS IMPORTANTS:
  - Sauvegardez les cles sur PLUSIEURS supports
  - Ne stockez JAMAIS les cles sur le disque chiffre
  - Conservez une copie papier dans un endroit sur
  - Verifiez que vous pouvez acceder aux cles avant de modifier le TPM

"@ -ForegroundColor White

    Write-Host "  Appuyez sur une touche pour continuer..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Invoke-TPMClear {
    <#
    .DESCRIPTION
        Reinitialise le TPM avec validation de securite
    #>
    
    $bitLockerStatus = Get-BitLockerStatus
    
    # Premier ecran d'avertissement
    Clear-Host
    Write-Host "`n" -NoNewline
    Write-Host "=" * 60 -ForegroundColor Red
    Write-Host "  ATTENTION - REINITIALISATION DU TPM" -ForegroundColor Red
    Write-Host "=" * 60 -ForegroundColor Red
    
    Write-Host @"

  Vous etes sur le point de reinitialiser le TPM (Trusted Platform Module).
  
  Cette operation va:
  - Effacer TOUTES les donnees stockees dans le TPM
  - Supprimer les cles BitLocker associees au TPM
  - Reinitialiser le TPM a son etat d'usine

  Si BitLocker est active sur vos disques, vous PERDREZ l'acces a vos
  donnees si vous n'avez pas sauvegarde vos cles de recuperation!

"@ -ForegroundColor Yellow

    # Verifier BitLocker
    if ($bitLockerStatus.AnyEnabled) {
        Write-Host "  " -NoNewline
        Write-Host "DETECTION: BitLocker est ACTIVE sur les lecteurs suivants:" -ForegroundColor Red
        foreach ($drive in $bitLockerStatus.EnabledDrives) {
            Write-Host "    - $($drive.DriveLetter) (Chiffrement: $($drive.EncryptionStatus)%)" -ForegroundColor White
        }
        
        Write-Host "`n  AVERTISSEMENT CRITIQUE:" -ForegroundColor Red
        Write-Host "  Vos cles BitLocker sont stockees dans le TPM actuel." -ForegroundColor Yellow
        Write-Host "  La reinitialisation du TPM rendra ces cles inutilisables!" -ForegroundColor Yellow
        
        Show-BitLockerRecoveryKeyProcedure
        
        # Premiere validation
        Write-Host "`n" -NoNewline
        Write-Host "  Premiere validation requise" -ForegroundColor Cyan
        Write-Host "  ----------------------------" -ForegroundColor Cyan
        $confirm1 = Read-Host "  Tapez 'OUI' pour confirmer que vous avez sauvegarde vos cles BitLocker"
        
        if ($confirm1 -ne "OUI") {
            Write-Host "`n  Operation annulee par l'utilisateur." -ForegroundColor Green
            Write-Host "  Veuillez sauvegarder vos cles BitLocker avant de reessayer." -ForegroundColor Yellow
            return $false
        }
        
        # Deuxieme validation
        Write-Host "`n" -NoNewline
        Write-Host "  Deuxieme validation requise" -ForegroundColor Cyan
        Write-Host "  ----------------------------" -ForegroundColor Cyan
        $confirm2 = Read-Host "  Tapez 'REINITIALISER' pour confirmer la reinitialisation du TPM"
        
        if ($confirm2 -ne "REINITIALISER") {
            Write-Host "`n  Operation annulee par l'utilisateur." -ForegroundColor Green
            return $false
        }
    } else {
        # Pas de BitLocker, validation simple
        Write-Host "`n  BitLocker n'est pas active sur ce systeme." -ForegroundColor Green
        $confirm = Read-Host "  Tapez 'OUI' pour confirmer la reinitialisation du TPM"
        
        if ($confirm -ne "OUI") {
            Write-Host "`n  Operation annulee par l'utilisateur." -ForegroundColor Green
            return $false
        }
    }
    
    # Dernier avertissement
    Write-Host "`n" -NoNewline
    Write-Host "  DERNIER AVERTISSEMENT" -ForegroundColor Red
    Write-Host "  --------------------" -ForegroundColor Red
    Write-Host "  Le TPM va etre reinitialise. Le systeme devra peut-etre redemarrer." -ForegroundColor Yellow
    $finalConfirm = Read-Host "  Continuer? (O/N)"
    
    if ($finalConfirm -ne "O" -and $finalConfirm -ne "o") {
        Write-Host "`n  Operation annulee." -ForegroundColor Green
        return $false
    }
    
    # Execution de la reinitialisation
    Write-Host "`n  Reinitialisation du TPM en cours..." -ForegroundColor Cyan
    
    try {
        # Methode 1: Via Get-Tpm
        if (Get-Command Clear-Tpm -ErrorAction SilentlyContinue) {
            $result = Clear-Tpm -ErrorAction Stop
            Write-Host "  TPM reinitialise avec succes!" -ForegroundColor Green
            Write-Host "  Un redemarrage peut etre necessaire pour appliquer les changements." -ForegroundColor Yellow
            return $true
        }
        
        # Methode 2: Via WMI
        $tpm = Get-CimInstance -Namespace "root\cimv2\security\microsofttpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
        if ($tpm) {
            $result = Invoke-CimMethod -InputObject $tpm -MethodName "SetPhysicalPresenceRequest" -Arguments @{Request = 14} -ErrorAction Stop
            Write-Host "  Demande de reinitialisation TPM envoyee." -ForegroundColor Green
            Write-Host "  Vous devrez confirmer la reinitialisation au prochain redemarrage (F12 ou BIOS)." -ForegroundColor Yellow
            return $true
        }
        
        Write-Host "  Erreur: Impossible de reinitialiser le TPM." -ForegroundColor Red
        return $false
    }
    catch {
        Write-Host "  Erreur lors de la reinitialisation: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-SystemInformation {
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    
    Write-Host "`n  Processeur : " -NoNewline -ForegroundColor White
    Write-Host $cpu.Name -ForegroundColor Cyan
    Write-Host "  Fabricant  : " -NoNewline -ForegroundColor White
    Write-Host $cpu.Manufacturer -ForegroundColor Cyan
    Write-Host "  OS         : " -NoNewline -ForegroundColor White
    Write-Host $os.Caption -ForegroundColor Cyan
    Write-Host "  Architecture: " -NoNewline -ForegroundColor White
    Write-Host $os.OSArchitecture -ForegroundColor Cyan
}

# ==============================================================================
# MAIN
# ==============================================================================

Clear-Host

# Traiter l'export des cles si demande
if ($ExportKeys) {
    $exportPath = "$env:USERPROFILE\Desktop\BitLockerRecoveryKeys_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    Write-Host "`n  Export des cles de recuperation BitLocker..." -ForegroundColor Cyan
    
    $success, $count = Export-BitLockerRecoveryKeys -ExportPath $exportPath
    
    if ($success) {
        Write-Host "  Succes: $count cle(s) exportee(s)" -ForegroundColor Green
        Write-Host "  Fichier: $exportPath" -ForegroundColor White
        
        # Ouvrir le fichier
        Start-Process notepad.exe $exportPath
    } else {
        Write-Host "  Aucune cle de recuperation trouvee ou BitLocker non active." -ForegroundColor Yellow
    }
    
    Write-Host "`n  Appuyez sur une touche pour quitter..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 0
}

# Traiter la reinitialisation TPM si demandee
if ($ClearTPM) {
    # Verifier les droits admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "`n  ERREUR: La reinitialisation du TPM necessite des droits administrateur." -ForegroundColor Red
        Write-Host "  Veuillez relancer le script en tant qu'administrateur." -ForegroundColor Yellow
        Write-Host "`n  Appuyez sur une touche pour quitter..." -ForegroundColor DarkGray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
    
    $result = Invoke-TPMClear
    Write-Host "`n  Appuyez sur une touche pour quitter..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 0
}

# Detection standard
Write-Header "DETECTEUR DE VIRTUALISATION CPU ET SECURITE"

# Afficher les informations systeme
Get-SystemInformation

$cpuVendor = Get-CPUVendor

Write-Header "RESULTATS DE LA DETECTION"

# Detection de la virtualisation de base (VT-x ou SVM)
if ($cpuVendor -eq "Intel") {
    $vtxEnabled = Test-IntelVTx
    Write-Result -Feature "Intel VT-x (Virtualisation)" -Enabled $vtxEnabled -Details "Virtualisation de base du processeur"
    
    $vtdResult = Test-IntelVTd
    Write-Result -Feature "Intel VT-d (IOMMU Intel)" -Enabled $vtdResult -Details "Virtualisation des E/S avec DMA remapping"
}
elseif ($cpuVendor -eq "AMD") {
    $svmEnabled = Test-AMDSVM
    Write-Result -Feature "AMD SVM (Secure Virtual Machine)" -Enabled $svmEnabled -Details "Equivalent AMD d'Intel VT-x"
}

# Detection NX / DEP
$nxEnabled = Test-NXFeature
Write-Result -Feature "NX / DEP (No-eXecute)" -Enabled $nxEnabled -Details "Protection contre l'execution de code dans les zones de donnees"

# Detection IOMMU generique
$iommuResult = Test-IOMMU
$iommuEnabled = $iommuResult[0]
$iommuDetails = $iommuResult[1]
Write-Result -Feature "IOMMU (Input-Output MMU)" -Enabled $iommuEnabled -Details $iommuDetails

# Detection TPM
Write-Host "`n" -NoNewline
Write-Host "  --- MODULE TPM (Trusted Platform Module) ---" -ForegroundColor Magenta
$tpmStatus = Get-TPMStatus
Write-Result -Feature "TPM Present" -Enabled $tpmStatus.IsPresent -Details "Module de securite materielle"
if ($tpmStatus.IsPresent) {
    $tpmVersionOk = $tpmStatus.Version -match "^2\."
    Write-Host "  TPM Version               : " -NoNewline -ForegroundColor White
    if ($tpmVersionOk) {
        Write-Host "$($tpmStatus.Version)" -ForegroundColor Green
    } else {
        Write-Host "$($tpmStatus.Version)" -ForegroundColor Yellow
    }
    Write-Result -Feature "TPM Active" -Enabled $tpmStatus.IsEnabled -Details "TPM active dans le BIOS"
    Write-Result -Feature "TPM Pret" -Enabled $tpmStatus.Ready -Details "TPM operationnel"
    if ($tpmStatus.Manufacturer -ne "N/A") {
        Write-Host "  Fabricant TPM             : " -NoNewline -ForegroundColor White
        Write-Host $tpmStatus.Manufacturer -ForegroundColor Cyan
    }
    
    $win11Compatible, $win11Details = Test-TPMForWindows11
    Write-Result -Feature "Compatible Windows 11" -Enabled $win11Compatible -Details $win11Details
}

# ==============================================================================
# DETECTION BITLOCKER
# ==============================================================================

Write-Host "`n" -NoNewline
Write-Host "  --- BITLOCKER DRIVE ENCRYPTION ---" -ForegroundColor Magenta

$bitLockerStatus = Get-BitLockerStatus

if ($bitLockerStatus.Drives.Count -gt 0) {
    foreach ($drive in $bitLockerStatus.Drives) {
        $isProtected = $drive.ProtectionStatus -eq 'On'
        Write-Result -Feature "Lecteur $($drive.DriveLetter)" -Enabled $isProtected
        
        if ($isProtected) {
            Write-Host "    -> Chiffrement: $($drive.EncryptionPercentage)%" -ForegroundColor Gray
            if ($drive.HasRecoveryKey) {
                Write-Host "    -> Cle de recuperation: Presente" -ForegroundColor Green
            } else {
                Write-Host "    -> Cle de recuperation: NON CONFIGUREE!" -ForegroundColor Red
            }
        } else {
            Write-Host "    -> Statut: Non chiffre" -ForegroundColor Gray
        }
    }
    
    if ($bitLockerStatus.AnyEnabled) {
        Write-Host "`n  /!\ ATTENTION: BitLocker actif - Sauvegardez vos cles!" -ForegroundColor Yellow
        Write-Host "  Utilisez -ExportKeys pour exporter les cles de recuperation" -ForegroundColor DarkGray
    }
} else {
    Write-Host "  Aucun lecteur BitLocker detecte" -ForegroundColor Gray
}

# ==============================================================================
# INFORMATIONS COMPLEMENTAIRES
# ==============================================================================

Write-Header "INFORMATIONS COMPLEMENTAIRES"

# Verifier Hyper-V
$hyperV = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
if ($hyperV) {
    $hvStatus = if ($hyperV.State -eq "Enabled") { "Installe" } else { "Non installe" }
    Write-Host "  Hyper-V                    : $hvStatus" -ForegroundColor $(if ($hyperV.State -eq "Enabled") { "Green" } else { "Gray" })
}

# Verifier VBS
$deviceGuard = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ErrorAction SilentlyContinue
if ($deviceGuard) {
    $vbsStatus = if ($deviceGuard.EnableVirtualizationBasedSecurity -eq 1) { "Active" } else { "Desactive" }
    Write-Host "  VBS (Device Guard)         : $vbsStatus" -ForegroundColor $(if ($deviceGuard.EnableVirtualizationBasedSecurity -eq 1) { "Green" } else { "Gray" })
}

# Verifier Core Isolation
$coreIsolation = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ErrorAction SilentlyContinue
if ($coreIsolation) {
    $ciStatus = if ($coreIsolation.Enabled -eq 1) { "Active" } else { "Desactive" }
    Write-Host "  Core Isolation             : $ciStatus" -ForegroundColor $(if ($coreIsolation.Enabled -eq 1) { "Green" } else { "Gray" })
}

# Verifier Secure Boot
try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    $sbStatus = if ($secureBoot) { "Active" } else { "Desactive" }
    Write-Host "  Secure Boot                : $sbStatus" -ForegroundColor $(if ($secureBoot) { "Green" } else { "Gray" })
}
catch {
    Write-Host "  Secure Boot                : Impossible a determiner (mode Legacy BIOS?)" -ForegroundColor Yellow
}

Write-Header "RECOMMANDATIONS"

if ($cpuVendor -eq "Intel") {
    if (-not (Test-IntelVTx)) {
        Write-Host "  ! Activez Intel VT-x dans le BIOS/UEFI pour utiliser des machines virtuelles" -ForegroundColor Yellow
    }
    if (-not (Test-IntelVTd)) {
        Write-Host "  ! Activez Intel VT-d dans le BIOS/UEFI pour le passthrough PCI et une meilleure securite" -ForegroundColor Yellow
    }
}
elseif ($cpuVendor -eq "AMD") {
    if (-not (Test-AMDSVM)) {
        Write-Host "  ! Activez AMD SVM dans le BIOS/UEFI pour utiliser des machines virtuelles" -ForegroundColor Yellow
    }
}

if (-not (Test-NXFeature)) {
    Write-Host "  ! Activez NX/DEP dans le BIOS/UEFI pour une meilleure securite systeme" -ForegroundColor Yellow
}

# Recommandations TPM
if (-not $tpmStatus.IsPresent) {
    Write-Host "  ! Aucun TPM detecte - Requis pour Windows 11 et BitLocker" -ForegroundColor Yellow
} elseif (-not $tpmStatus.IsEnabled) {
    Write-Host "  ! Activez le TPM dans le BIOS/UEFI pour utiliser BitLocker et Windows 11" -ForegroundColor Yellow
} elseif ($tpmStatus.Version -match "^1\.") {
    Write-Host "  ! TPM 1.2 detecte - TPM 2.0 requis pour Windows 11" -ForegroundColor Yellow
}

# Recommandations BitLocker
if ($bitLockerStatus.AnyEnabled) {
    $missingKeys = $bitLockerStatus.Drives | Where-Object { $_.ProtectionStatus -eq 'On' -and -not $_.HasRecoveryKey }
    if ($missingKeys) {
        Write-Host "  ! CRITIQUE: Cles de recuperation BitLocker manquantes!" -ForegroundColor Red
        Write-Host "    Executez: .\CPUVirtualizationCheck.ps1 -ExportKeys" -ForegroundColor Yellow
    }
}

Write-Host "`n  Note: Certaines informations necessitent des droits administrateur." -ForegroundColor DarkGray
Write-Host "  Pour des resultats optimaux, executez ce script en tant qu'administrateur.`n" -ForegroundColor DarkGray

# Afficher les options disponibles
Write-Host "  OPTIONS DISPONIBLES:" -ForegroundColor Cyan
Write-Host "    -ExportKeys : Exporter les cles de recuperation BitLocker" -ForegroundColor White
Write-Host "    -ClearTPM   : Reinitialiser le TPM (ATTENTION: voir documentation)" -ForegroundColor White
Write-Host "    -Help       : Afficher l'aide complete" -ForegroundColor White

# ==============================================================================
# EXPORT OPTIONNEL
# ==============================================================================

$export = Read-Host "`nVoulez-vous exporter les resultats dans un fichier? (O/N)"
if ($export -eq "O" -or $export -eq "o") {
    $exportPath = "$env:USERPROFILE\Desktop\VirtualizationReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    $tpmStatusExport = Get-TPMStatus
    $win11Compatible, $win11Details = Test-TPMForWindows11
    $bitLockerExport = Get-BitLockerStatus
    
    # Construire le rapport BitLocker
    $bitLockerReport = ""
    foreach ($drive in $bitLockerExport.Drives) {
        $status = if ($drive.ProtectionStatus -eq 'On') { "CHIFFRE" } else { "NON CHIFFRE" }
        $bitLockerReport += "  $($drive.DriveLetter): $status ($($drive.EncryptionStatus)%)`n"
    }
    if ($bitLockerExport.Drives.Count -eq 0) {
        $bitLockerReport = "  Aucun lecteur detecte`n"
    }
    
    $report = @"
===============================================================================
          RAPPORT DE DETECTION DE VIRTUALISATION CPU ET SECURITE
===============================================================================
Date: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')

INFORMATIONS SYSTEME
--------------------
Processeur: $((Get-CimInstance Win32_Processor | Select-Object -First 1).Name)
Fabricant: $((Get-CimInstance Win32_Processor | Select-Object -First 1).Manufacturer)
OS: $((Get-CimInstance Win32_OperatingSystem).Caption)

RESULTATS - VIRTUALISATION
--------------------------
Intel VT-x / AMD SVM: $(if ($cpuVendor -eq "Intel") { if (Test-IntelVTx) { "ACTIVE" } else { "DESACTIVE" } } else { if (Test-AMDSVM) { "ACTIVE" } else { "DESACTIVE" } })
Intel VT-d: $(if ($cpuVendor -eq "Intel") { if (Test-IntelVTd) { "ACTIVE" } else { "DESACTIVE" } } else { "N/A (AMD)" })
NX / DEP: $(if (Test-NXFeature) { "ACTIVE" } else { "DESACTIVE" })
IOMMU: $(if ((Test-IOMMU)[0]) { "ACTIVE" } else { "DESACTIVE" })

RESULTATS - TPM (Trusted Platform Module)
-----------------------------------------
TPM Present: $(if ($tpmStatusExport.IsPresent) { "OUI" } else { "NON" })
TPM Version: $($tpmStatusExport.Version)
TPM Active: $(if ($tpmStatusExport.IsEnabled) { "OUI" } else { "NON" })
TPM Pret: $(if ($tpmStatusExport.Ready) { "OUI" } else { "NON" })
Fabricant TPM: $($tpmStatusExport.Manufacturer)
Compatible Windows 11: $(if ($win11Compatible) { "OUI" } else { "NON" }) - $win11Details

RESULTATS - BITLOCKER
---------------------
$bitLockerReport

===============================================================================
"@

    $report | Out-File -FilePath $exportPath -Encoding UTF8
    Write-Host "`n  Rapport exporte vers: $exportPath" -ForegroundColor Green
}

Write-Host "`n  Appuyez sur une touche pour quitter..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
