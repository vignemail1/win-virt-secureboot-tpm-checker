// cpuvirtcheck - Detecteur de fonctionnalites de virtualisation et securite CPU pour Windows
// Detecte: Intel VT-x/VT-d, AMD SVM, NX/DEP, IOMMU, TPM, BitLocker
// Options: -cleartpm (reinitialiser TPM), -exportkeys (exporter cles BitLocker), -help
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32                      = syscall.NewLazyDLL("kernel32.dll")
	procIsProcessorFeaturePresent = kernel32.NewProc("IsProcessorFeaturePresent")
)

// Constantes pour IsProcessorFeaturePresent
const (
	PF_NX_ENABLED                       = 12 // NX/DEP est active
	PF_VIRT_FIRMWARE_ENABLED            = 21 // Virtualisation firmware active (VT-x/SVM)
	PF_SECOND_LEVEL_ADDRESS_TRANSLATION = 22 // SLAT (EPT/NPT) supporte
	PF_VIRT_FIRMWARE_PRESENT            = 23 // Virtualisation firmware presente
)

// Constantes pour le registre
const (
	KEY_READ           = 0x20019
	HKEY_LOCAL_MACHINE = 0x80000002
)

// Couleurs pour la console Windows
const (
	FOREGROUND_BLUE      = 1
	FOREGROUND_GREEN     = 2
	FOREGROUND_RED       = 4
	FOREGROUND_INTENSITY = 8
)

var stdoutHandle uintptr

func init() {
	stdoutHandle = uintptr(os.Stdout.Fd())
}

// setConsoleColor change la couleur du texte dans la console
func setConsoleColor(color uint16) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setConsoleTextAttribute := kernel32.NewProc("SetConsoleTextAttribute")
	setConsoleTextAttribute.Call(stdoutHandle, uintptr(color))
}

func resetColor() {
	setConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
}

func printColor(text string, color uint16) {
	setConsoleColor(color)
	fmt.Print(text)
	resetColor()
}

func printSuccess(text string) {
	printColor(text, FOREGROUND_GREEN|FOREGROUND_INTENSITY)
}

func printError(text string) {
	printColor(text, FOREGROUND_RED|FOREGROUND_INTENSITY)
}

func printWarning(text string) {
	printColor(text, FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_INTENSITY) // Jaune
}

func printCyan(text string) {
	printColor(text, FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_INTENSITY)
}

func printMagenta(text string) {
	printColor(text, FOREGROUND_RED|FOREGROUND_BLUE|FOREGROUND_INTENSITY)
}

func printRed(text string) {
	printColor(text, FOREGROUND_RED|FOREGROUND_INTENSITY)
}

func printHeader(title string) {
	fmt.Println()
	line := "============================================================"
	printCyan(line + "\n")
	printCyan("  " + title + "\n")
	printCyan(line + "\n")
}

func printHeaderRed(title string) {
	fmt.Println()
	line := "============================================================"
	printRed(line + "\n")
	printRed("  " + title + "\n")
	printRed(line + "\n")
}

// isProcessorFeaturePresent verifie si une fonctionnalite CPU est presente
func isProcessorFeaturePresent(feature uint32) bool {
	ret, _, _ := procIsProcessorFeaturePresent.Call(uintptr(feature))
	return ret != 0
}

// getCPUVendor retourne le vendeur du CPU (Intel, AMD, Unknown)
func getCPUVendor() string {
	keyName, _ := syscall.UTF16PtrFromString(`HARDWARE\DESCRIPTION\System\CentralProcessor\0`)
	var hKey syscall.Handle
	err := syscall.RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyName, 0, KEY_READ, &hKey)
	if err != nil {
		return "Inconnu"
	}
	defer syscall.RegCloseKey(hKey)

	var buf [256]uint16
	var bufLen uint32 = 512
	valName, _ := syscall.UTF16PtrFromString("VendorIdentifier")

	err = syscall.RegQueryValueEx(hKey, valName, nil, nil, (*byte)(unsafe.Pointer(&buf[0])), &bufLen)
	if err == nil {
		vendor := syscall.UTF16ToString(buf[:])
		if vendor == "GenuineIntel" {
			return "Intel"
		}
		if vendor == "AuthenticAMD" {
			return "AMD"
		}
	}

	return "Inconnu"
}

// getCPUName retourne le nom du processeur
func getCPUName() string {
	keyName, _ := syscall.UTF16PtrFromString(`HARDWARE\DESCRIPTION\System\CentralProcessor\0`)
	var hKey syscall.Handle
	err := syscall.RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyName, 0, KEY_READ, &hKey)
	if err != nil {
		return "Inconnu"
	}
	defer syscall.RegCloseKey(hKey)

	var buf [256]uint16
	var bufLen uint32 = 512
	valName, _ := syscall.UTF16PtrFromString("ProcessorNameString")

	err = syscall.RegQueryValueEx(hKey, valName, nil, nil, (*byte)(unsafe.Pointer(&buf[0])), &bufLen)
	if err != nil {
		return "Inconnu"
	}

	return syscall.UTF16ToString(buf[:])
}

// checkRegistryValueDWORD verifie une valeur DWORD dans le registre
func checkRegistryValueDWORD(keyPath, valueName string) (uint32, error) {
	keyName, _ := syscall.UTF16PtrFromString(keyPath)
	var hKey syscall.Handle
	err := syscall.RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyName, 0, KEY_READ, &hKey)
	if err != nil {
		return 0, err
	}
	defer syscall.RegCloseKey(hKey)

	valName, _ := syscall.UTF16PtrFromString(valueName)
	var value uint32
	var valueLen uint32 = 4
	var valueType uint32 = syscall.REG_DWORD

	err = syscall.RegQueryValueEx(hKey, valName, nil, &valueType, (*byte)(unsafe.Pointer(&value)), &valueLen)
	if err != nil {
		return 0, err
	}

	return value, nil
}

// checkRegistryStringValue verifie une valeur string dans le registre
func checkRegistryStringValue(keyPath, valueName string) (string, error) {
	keyName, _ := syscall.UTF16PtrFromString(keyPath)
	var hKey syscall.Handle
	err := syscall.RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyName, 0, KEY_READ, &hKey)
	if err != nil {
		return "", err
	}
	defer syscall.RegCloseKey(hKey)

	valName, _ := syscall.UTF16PtrFromString(valueName)
	var buf [256]uint16
	var bufLen uint32 = 512
	var valueType uint32 = syscall.REG_SZ

	err = syscall.RegQueryValueEx(hKey, valName, nil, &valueType, (*byte)(unsafe.Pointer(&buf[0])), &bufLen)
	if err != nil {
		return "", err
	}

	return syscall.UTF16ToString(buf[:]), nil
}

// isAdmin verifie si le programme est execute en administrateur
func isAdmin() bool {
	_, err := os.Open("\\.\\PHYSICALDRIVE0")
	return err == nil
}

// TPMStatus contient les informations sur le TPM
type TPMStatus struct {
	IsPresent    bool
	Version      string
	IsEnabled    bool
	IsActivated  bool
	Ready        bool
	Manufacturer string
}

// getTPMStatus retourne le statut du TPM
func getTPMStatus() TPMStatus {
	status := TPMStatus{
		IsPresent:    false,
		Version:      "N/A",
		IsEnabled:    false,
		IsActivated:  false,
		Ready:        false,
		Manufacturer: "N/A",
	}

	// Verifier via le registre TPM
	active, err := checkRegistryValueDWORD(`SYSTEM\CurrentControlSet\Services\TPM\WMI`, "NoActionRequired")
	if err == nil {
		status.IsPresent = true
		status.Ready = (active == 1)
	}

	// Verifier la version
	specVersion, err := checkRegistryStringValue(`SYSTEM\CurrentControlSet\Control\TPM\Info`, "SpecVersion")
	if err == nil && specVersion != "" {
		status.IsPresent = true
		status.Version = specVersion
	}

	// Verifier le service TPM
	serviceStatus, err := checkRegistryValueDWORD(`SYSTEM\CurrentControlSet\Services\TPM`, "Start")
	if err == nil {
		status.IsEnabled = (serviceStatus == 2 || serviceStatus == 3)
	}

	// Verifier les informations fabricant
	pcpInfo, err := checkRegistryStringValue(`SOFTWARE\Microsoft\Cryptography\TPM\CurrentInfo`, "Manufacturer")
	if err == nil && pcpInfo != "" {
		status.IsPresent = true
		status.Manufacturer = pcpInfo
	}

	// Verifier presence peripherique TPM
	var hKey syscall.Handle
	keyName, _ := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Enum\ACPI\MSDM`)
	err = syscall.RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyName, 0, KEY_READ, &hKey)
	if err == nil {
		status.IsPresent = true
		syscall.RegCloseKey(hKey)
	}

	keyName2, _ := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Enum\ACPI\PNP0C31`)
	err = syscall.RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyName2, 0, KEY_READ, &hKey)
	if err == nil {
		status.IsPresent = true
		syscall.RegCloseKey(hKey)
	}

	if status.IsPresent && !status.IsActivated {
		status.IsActivated = status.Ready
	}

	return status
}

// testTPMForWindows11 verifie si le TPM est compatible Windows 11
func testTPMForWindows11(status TPMStatus) (bool, string) {
	if !status.IsPresent {
		return false, "TPM non present"
	}

	if len(status.Version) >= 2 && status.Version[0:2] == "2." {
		if status.IsEnabled && status.IsActivated {
			return true, "TPM 2.0 actif et pret"
		}
		return false, "TPM 2.0 present mais non active"
	}

	if len(status.Version) >= 3 && status.Version[0:3] == "1.2" {
		return false, "TPM 1.2 present (TPM 2.0 requis pour Windows 11)"
	}

	if status.IsEnabled && status.IsActivated {
		return true, "TPM actif (version non determinee)"
	}

	return false, "Statut TPM incertain"
}

// BitLockerDriveInfo contient les infos d'un lecteur BitLocker
type BitLockerDriveInfo struct {
	DriveLetter      string
	ProtectionStatus string
	EncryptionPct    string
	HasRecoveryKey   bool
}

// BitLockerStatus contient le statut BitLocker du systeme
type BitLockerStatus struct {
	Drives        []BitLockerDriveInfo
	AnyEnabled    bool
	EnabledDrives []BitLockerDriveInfo
}

// getBitLockerStatus recupere le statut BitLocker via manage-bde
func getBitLockerStatus() BitLockerStatus {
	status := BitLockerStatus{
		Drives:        []BitLockerDriveInfo{},
		AnyEnabled:    false,
		EnabledDrives: []BitLockerDriveInfo{},
	}

	// Executer manage-bde -status
	cmd := exec.Command("manage-bde", "-status")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return status
	}

	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")

	var currentDrive string
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Detecter le lecteur
		if strings.HasPrefix(line, "Volume ") && strings.Contains(line, ":") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.Contains(p, ":") {
					currentDrive = p
					break
				}
			}
		}

		// Detecter le statut de protection
		if strings.HasPrefix(line, "Statut de la protection:") || strings.HasPrefix(line, "Protection Status:") {
			isProtected := strings.Contains(line, "Protection activ") || strings.Contains(line, "Protection On")
			if currentDrive != "" {
				info := BitLockerDriveInfo{
					DriveLetter:      currentDrive,
					ProtectionStatus: "Off",
					HasRecoveryKey:   false,
				}
				if isProtected {
					info.ProtectionStatus = "On"
					status.AnyEnabled = true
					status.EnabledDrives = append(status.EnabledDrives, info)
				}
				status.Drives = append(status.Drives, info)
				currentDrive = ""
			}
		}
	}

	return status
}

// exportBitLockerKeys exporte les cles de recuperation BitLocker
func exportBitLockerKeys() (bool, int, string) {
	// Obtenir les cles via manage-bde
	drives := []string{"C:", "D:", "E:", "F:"}
	keysFound := 0
	var output strings.Builder

	output.WriteString("============================================================\n")
	output.WriteString("        CLES DE RECUPERATION BITLOCKER\n")
	output.WriteString("============================================================\n")
	output.WriteString(fmt.Sprintf("Date: %s\n\n", getDateTime()))

	for _, drive := range drives {
		cmd := exec.Command("manage-bde", "-protectors", "-get", drive)
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}

		outStr := string(out)
		if strings.Contains(outStr, "Mot de passe de recuperation") || strings.Contains(outStr, "Recovery Password") {
			output.WriteString(fmt.Sprintf("\nLecteur %s\n", drive))
			output.WriteString(strings.Repeat("-", 40) + "\n")

			lines := strings.Split(outStr, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "Mot de passe") || strings.Contains(line, "Recovery Password") ||
					strings.Contains(line, "ID") || strings.Contains(line, "Identificateur") {
					output.WriteString(line + "\n")
				}
				// Detecter les 48 chiffres
				if len(line) >= 48 {
					cleanLine := strings.ReplaceAll(line, " ", "")
					if _, err := strconv.ParseInt(cleanLine[:48], 10, 64); err == nil {
						output.WriteString(line + "\n")
						keysFound++
					}
				}
			}
		}
	}

	return keysFound > 0, keysFound, output.String()
}

// showBitLockerRecoveryProcedure affiche la procedure de sauvegarde des cles
func showBitLockerRecoveryProcedure() {
	printHeaderRed("PROCEDURE DE SAUVEGARDE DES CLES BITLOCKER")

	fmt.Print(`
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

  METHODE 3: Export automatique via ce programme
  ----------------------------------------------
  Executer: cpuvirtcheck.exe -exportkeys

`)
	fmt.Println("  Appuyez sur Entree pour continuer...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// invokeTPMClear reinitialise le TPM avec validation
func invokeTPMClear() bool {
	bitLockerStatus := getBitLockerStatus()

	// Premier ecran d'avertissement
	printHeaderRed("ATTENTION - REINITIALISATION DU TPM")

	fmt.Print(`
  Vous etes sur le point de reinitialiser le TPM (Trusted Platform Module).
  
  Cette operation va:
  - Effacer TOUTES les donnees stockees dans le TPM
  - Supprimer les cles BitLocker associees au TPM
  - Reinitialiser le TPM a son etat d'usine

  Si BitLocker est active sur vos disques, vous PERDREZ l'acces a vos
  donnees si vous n'avez pas sauvegarde vos cles de recuperation!

`)

	// Verifier BitLocker
	if bitLockerStatus.AnyEnabled {
		printError("  DETECTION: BitLocker est ACTIVE sur les lecteurs suivants:\n")
		for _, drive := range bitLockerStatus.EnabledDrives {
			fmt.Printf("    - %s\n", drive.DriveLetter)
		}

		printWarning("\n  AVERTISSEMENT CRITIQUE:\n")
		printWarning("  Vos cles BitLocker sont stockees dans le TPM actuel.\n")
		printWarning("  La reinitialisation du TPM rendra ces cles inutilisables!\n")

		showBitLockerRecoveryProcedure()

		// Premiere validation
		fmt.Println()
		printCyan("  Premiere validation requise\n")
		printCyan("  ----------------------------\n")
		fmt.Print("  Tapez 'OUI' pour confirmer que vous avez sauvegarde vos cles BitLocker: ")
		reader := bufio.NewReader(os.Stdin)
		confirm1, _ := reader.ReadString('\n')
		confirm1 = strings.TrimSpace(confirm1)

		if confirm1 != "OUI" {
			printSuccess("\n  Operation annulee par l'utilisateur.\n")
			printWarning("  Veuillez sauvegarder vos cles BitLocker avant de reessayer.\n")
			return false
		}

		// Deuxieme validation
		fmt.Println()
		printCyan("  Deuxieme validation requise\n")
		printCyan("  ----------------------------\n")
		fmt.Print("  Tapez 'REINITIALISER' pour confirmer la reinitialisation du TPM: ")
		confirm2, _ := reader.ReadString('\n')
		confirm2 = strings.TrimSpace(confirm2)

		if confirm2 != "REINITIALISER" {
			printSuccess("\n  Operation annulee par l'utilisateur.\n")
			return false
		}
	} else {
		// Pas de BitLocker, validation simple
		fmt.Println()
		printSuccess("  BitLocker n'est pas active sur ce systeme.\n")
		fmt.Print("  Tapez 'OUI' pour confirmer la reinitialisation du TPM: ")
		reader := bufio.NewReader(os.Stdin)
		confirm, _ := reader.ReadString('\n')
		confirm = strings.TrimSpace(confirm)

		if confirm != "OUI" {
			printSuccess("\n  Operation annulee par l'utilisateur.\n")
			return false
		}
	}

	// Dernier avertissement
	fmt.Println()
	printRed("  DERNIER AVERTISSEMENT\n")
	printRed("  --------------------\n")
	printWarning("  Le TPM va etre reinitialise. Le systeme devra peut-etre redemarrer.\n")
	fmt.Print("  Continuer? (O/N): ")
	finalConfirm, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	finalConfirm = strings.TrimSpace(finalConfirm)

	if finalConfirm != "O" && finalConfirm != "o" {
		printSuccess("\n  Operation annulee.\n")
		return false
	}

	// Execution de la reinitialisation via PowerShell
	printCyan("\n  Reinitialisation du TPM en cours...\n")

	cmd := exec.Command("powershell", "-Command", "Clear-Tpm -ErrorAction Stop")
	output, err := cmd.CombinedOutput()
	if err != nil {
		printError(fmt.Sprintf("  Erreur lors de la reinitialisation: %s\n", string(output)))
		return false
	}

	printSuccess("  TPM reinitialise avec succes!\n")
	printWarning("  Un redemarrage peut etre necessaire pour appliquer les changements.\n")
	return true
}

func getDateTime() string {
	return "N/A"
}

// testVTVirtualization teste si Intel VT-x / AMD SVM est active
func testVTVirtualization() bool {
	return isProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED)
}

// testSLAT teste si Second Level Address Translation est supporte (EPT/NPT)
func testSLAT() bool {
	return isProcessorFeaturePresent(PF_SECOND_LEVEL_ADDRESS_TRANSLATION)
}

// testNXEnabled teste si NX/DEP est active
func testNXEnabled() bool {
	return isProcessorFeaturePresent(PF_NX_ENABLED)
}

// testVTdIOMMU teste si Intel VT-d / AMD IOMMU est active
func testVTdIOMMU() (bool, string) {
	val, err := checkRegistryValueDWORD(`SYSTEM\CurrentControlSet\Control\DeviceGuard`, "EnableVirtualizationBasedSecurity")
	if err == nil && val == 1 {
		return true, "VBS active - IOMMU probablement actif"
	}

	val2, err2 := checkRegistryValueDWORD(`SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`, "Enabled")
	if err2 == nil && val2 == 1 {
		return true, "Memory Integrity (Core Isolation) active"
	}

	val3, err3 := checkRegistryValueDWORD(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization`, "GuestStateVersion")
	if err3 == nil && val3 > 0 {
		return true, "Hyper-V actif - IOMMU utilise"
	}

	return false, "Non detecte via registre Windows"
}

// getDEPStatus retourne le statut DEP detaille
func getDEPStatus() string {
	val, err := checkRegistryValueDWORD(`SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`, "NoExecute")
	if err != nil {
		return "OptIn (defaut)"
	}

	switch val {
	case 0:
		return "Desactive"
	case 1:
		return "OptIn (actif pour les systemes essentiels)"
	case 2:
		return "OptOut (actif pour tout sauf exceptions)"
	case 3:
		return "AlwaysOn (toujours actif)"
	default:
		return fmt.Sprintf("Valeur: %d", val)
	}
}

// checkHyperV verifie si Hyper-V est installe
func checkHyperV() bool {
	val, err := checkRegistryValueDWORD(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization`, "GuestStateVersion")
	return err == nil && val > 0
}

// checkSecureBoot verifie si Secure Boot est active
func checkSecureBoot() (bool, error) {
	keyName, _ := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Control\SecureBoot\State`)
	var hKey syscall.Handle
	err := syscall.RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyName, 0, KEY_READ, &hKey)
	if err != nil {
		return false, err
	}
	defer syscall.RegCloseKey(hKey)

	valName, _ := syscall.UTF16PtrFromString("UEFISecureBootEnabled")
	var value uint32
	var valueLen uint32 = 4
	var valueType uint32 = syscall.REG_DWORD

	err = syscall.RegQueryValueEx(hKey, valName, nil, &valueType, (*byte)(unsafe.Pointer(&value)), &valueLen)
	if err != nil {
		return false, err
	}

	return value == 1, nil
}

func printResult(feature string, enabled bool, details string) {
	fmt.Print("  " + feature + " : ")
	if enabled {
		printSuccess("[ACTIVE]\n")
	} else {
		printError("[DESACTIVE]\n")
	}
	if details != "" {
		fmt.Println("    -> " + details)
	}
}

func showHelp() {
	printCyan(`
============================================================
                    CPUVIRTCHECK.EXE - AIDE
============================================================

USAGE:
    cpuvirtcheck.exe [options]

OPTIONS:
    -cleartpm    Reinitialise le TPM aux valeurs par defaut
                 ATTENTION: Necessite une double validation si BitLocker est actif
                 Les cles BitLocker seront perdues si non sauvegardees!
                 
    -exportkeys  Exporte les cles de recuperation BitLocker
                 Recommande avant toute operation sur le TPM
    
    -help        Affiche cette aide

EXEMPLES:
    cpuvirtcheck.exe              # Detection standard
    cpuvirtcheck.exe -exportkeys  # Detection + export cles BitLocker
    cpuvirtcheck.exe -cleartpm    # Detection + reinitialisation TPM

AVERTISSEMENT:
    La reinitialisation du TPM effacera toutes les donnees stockees dedans,
    y compris les cles BitLocker. Assurez-vous d'avoir sauvegarde les cles
    de recuperation avant de proceder.

============================================================
`)
}

func main() {
	// Analyser les arguments
	args := os.Args[1:]

	for _, arg := range args {
		if arg == "-help" || arg == "--help" {
			showHelp()
			return
		}

		if arg == "-exportkeys" {
			exportPath := os.Getenv("USERPROFILE") + "\\Desktop\\BitLockerRecoveryKeys.txt"

			printCyan("\n  Export des cles de recuperation BitLocker...\n")

			success, count, output := exportBitLockerKeys()

			if success {
				printSuccess(fmt.Sprintf("  Succes: %d cle(s) exportee(s)\n", count))
				fmt.Println("  Fichier: " + exportPath)

				// Ecrire le fichier
				err := os.WriteFile(exportPath, []byte(output), 0644)
				if err != nil {
					printError(fmt.Sprintf("  Erreur ecriture fichier: %s\n", err.Error()))
				}

				// Afficher le contenu
				fmt.Println(output)

				// Ouvrir notepad
				exec.Command("notepad.exe", exportPath).Start()
			} else {
				printWarning("  Aucune cle de recuperation trouvee ou BitLocker non active.\n")
			}

			fmt.Println("\n  Appuyez sur Entree pour quitter...")
			bufio.NewReader(os.Stdin).ReadString('\n')
			return
		}

		if arg == "-cleartpm" {
			// Verifier les droits admin
			if !isAdmin() {
				printError("\n  ERREUR: La reinitialisation du TPM necessite des droits administrateur.\n")
				printWarning("  Veuillez relancer le programme en tant qu'administrateur.\n")
				fmt.Println("\n  Appuyez sur Entree pour quitter...")
				bufio.NewReader(os.Stdin).ReadString('\n')
				return
			}

			invokeTPMClear()
			fmt.Println("\n  Appuyez sur Entree pour quitter...")
			bufio.NewReader(os.Stdin).ReadString('\n')
			return
		}
	}

	// Detection standard
	printHeader("DETECTEUR DE VIRTUALISATION CPU ET SECURITE")

	// Informations systeme
	vendor := getCPUVendor()
	cpuName := getCPUName()

	fmt.Println()
	fmt.Print("  Processeur : ")
	printCyan(cpuName + "\n")
	fmt.Print("  Fabricant  : ")
	printCyan(vendor + "\n")

	// Detection
	printHeader("RESULTATS DE LA DETECTION")

	// Virtualisation de base
	virtEnabled := testVTVirtualization()
	slatEnabled := testSLAT()

	if vendor == "Intel" {
		printResult("Intel VT-x (Virtualisation)", virtEnabled, "Virtualisation de base du processeur")
		printResult("Intel EPT (SLAT)", slatEnabled, "Extended Page Tables pour performances VM")
	} else if vendor == "AMD" {
		printResult("AMD SVM (Secure Virtual Machine)", virtEnabled, "Equivalent AMD d'Intel VT-x")
		printResult("AMD NPT (SLAT)", slatEnabled, "Nested Page Tables pour performances VM")
	} else {
		printResult("Virtualisation CPU", virtEnabled, "Support de virtualisation detecte")
	}

	// NX/DEP
	nxEnabled := testNXEnabled()
	depStatus := getDEPStatus()
	printResult("NX / DEP (No-eXecute)", nxEnabled, depStatus)

	// VT-d / IOMMU
	iommuEnabled, iommuDetails := testVTdIOMMU()
	if vendor == "Intel" {
		printResult("Intel VT-d (IOMMU)", iommuEnabled, iommuDetails)
	} else if vendor == "AMD" {
		printResult("AMD-Vi (AMD IOMMU)", iommuEnabled, iommuDetails)
	} else {
		printResult("IOMMU", iommuEnabled, iommuDetails)
	}

	// Detection TPM
	fmt.Println()
	printMagenta("  --- MODULE TPM (Trusted Platform Module) ---\n")
	tpmStatus := getTPMStatus()
	printResult("TPM Present", tpmStatus.IsPresent, "Module de securite materielle")

	if tpmStatus.IsPresent {
		fmt.Print("  TPM Version               : ")
		if tpmStatus.Version != "N/A" && len(tpmStatus.Version) >= 2 && tpmStatus.Version[0:2] == "2." {
			printSuccess(tpmStatus.Version + "\n")
		} else {
			printWarning(tpmStatus.Version + "\n")
		}

		printResult("TPM Active", tpmStatus.IsEnabled, "TPM active dans le BIOS")
		printResult("TPM Pret", tpmStatus.Ready, "TPM operationnel")

		if tpmStatus.Manufacturer != "N/A" {
			fmt.Print("  Fabricant TPM             : ")
			printCyan(tpmStatus.Manufacturer + "\n")
		}

		win11Compatible, win11Details := testTPMForWindows11(tpmStatus)
		printResult("Compatible Windows 11", win11Compatible, win11Details)
	}

	// Detection BitLocker
	fmt.Println()
	printMagenta("  --- BITLOCKER DRIVE ENCRYPTION ---\n")
	bitLockerStatus := getBitLockerStatus()

	if len(bitLockerStatus.Drives) > 0 {
		for _, drive := range bitLockerStatus.Drives {
			isProtected := drive.ProtectionStatus == "On"
			printResult("Lecteur "+drive.DriveLetter, isProtected, "")

			if isProtected {
				fmt.Println("    -> Statut: Chiffre")
				if bitLockerStatus.AnyEnabled {
					printWarning("    /!\\ Sauvegardez vos cles de recuperation!\n")
				}
			} else {
				fmt.Println("    -> Statut: Non chiffre")
			}
		}

		if bitLockerStatus.AnyEnabled {
			printWarning("\n  ATTENTION: BitLocker actif - Sauvegardez vos cles!\n")
			fmt.Println("  Utilisez -exportkeys pour exporter les cles de recuperation")
		}
	} else {
		fmt.Println("  Aucun lecteur BitLocker detecte")
	}

	// Informations complementaires
	printHeader("INFORMATIONS COMPLEMENTAIRES")

	// Hyper-V
	hyperV := checkHyperV()
	if hyperV {
		fmt.Println("  Hyper-V                    : Installe")
	} else {
		fmt.Println("  Hyper-V                    : Non installe")
	}

	// VBS
	vbsVal, vbsErr := checkRegistryValueDWORD(`SYSTEM\CurrentControlSet\Control\DeviceGuard`, "EnableVirtualizationBasedSecurity")
	if vbsErr == nil {
		if vbsVal == 1 {
			fmt.Println("  VBS (Device Guard)         : Active")
		} else {
			fmt.Println("  VBS (Device Guard)         : Desactive")
		}
	}

	// Core Isolation
	ciVal, ciErr := checkRegistryValueDWORD(`SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`, "Enabled")
	if ciErr == nil {
		if ciVal == 1 {
			fmt.Println("  Core Isolation             : Active")
		} else {
			fmt.Println("  Core Isolation             : Desactive")
		}
	}

	// Secure Boot
	sbEnabled, sbErr := checkSecureBoot()
	if sbErr == nil {
		if sbEnabled {
			fmt.Println("  Secure Boot                : Active")
		} else {
			fmt.Println("  Secure Boot                : Desactive")
		}
	} else {
		fmt.Println("  Secure Boot                : Non disponible (mode Legacy?)")
	}

	// Recommandations
	printHeader("RECOMMANDATIONS")

	if !virtEnabled {
		if vendor == "Intel" {
			printWarning("  ! Activez Intel VT-x dans le BIOS/UEFI pour utiliser des machines virtuelles\n")
		} else if vendor == "AMD" {
			printWarning("  ! Activez AMD SVM dans le BIOS/UEFI pour utiliser des machines virtuelles\n")
		}
	}

	if !nxEnabled {
		printWarning("  ! Activez NX/DEP dans le BIOS/UEFI pour une meilleure securite systeme\n")
	}

	if !iommuEnabled {
		if vendor == "Intel" {
			printWarning("  ! Activez Intel VT-d dans le BIOS/UEFI pour le passthrough PCI\n")
		} else if vendor == "AMD" {
			printWarning("  ! Activez AMD IOMMU dans le BIOS/UEFI pour le passthrough PCI\n")
		}
	}

	// Recommandations TPM
	if !tpmStatus.IsPresent {
		printWarning("  ! Aucun TPM detecte - Requis pour Windows 11 et BitLocker\n")
	} else if !tpmStatus.IsEnabled {
		printWarning("  ! Activez le TPM dans le BIOS/UEFI pour utiliser BitLocker et Windows 11\n")
	} else if tpmStatus.Version != "N/A" && len(tpmStatus.Version) >= 3 && tpmStatus.Version[0:3] == "1.2" {
		printWarning("  ! TPM 1.2 detecte - TPM 2.0 requis pour Windows 11\n")
	}

	fmt.Println("\n  Note: Ce programme doit etre execute avec des droits administrateur")
	fmt.Println("  pour obtenir toutes les informations systeme.\n")

	// Afficher les options disponibles
	printCyan("  OPTIONS DISPONIBLES:\n")
	fmt.Println("    -exportkeys : Exporter les cles de recuperation BitLocker")
	fmt.Println("    -cleartpm   : Reinitialiser le TPM (ATTENTION: voir documentation)")
	fmt.Println("    -help       : Afficher l'aide complete")

	// Pause
	fmt.Println("\n  Appuyez sur Entree pour quitter...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
