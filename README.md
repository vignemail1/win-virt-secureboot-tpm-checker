# Detecteur de Virtualisation CPU et Securite pour Windows

Ce projet fournit deux solutions pour detecter les fonctionnalites de virtualisation et de securite CPU sur Windows :

- Intel VT-x / VT-d (Intel)
- AMD SVM / AMD-Vi (AMD)
- NX (No-eXecute) / DEP (Data Execution Prevention)
- IOMMU (Input-Output Memory Management Unit)
- TPM (Trusted Platform Module) - Version, etat, compatibilite Windows 11
- BitLocker - Statut de chiffrement des lecteurs

Options de securite:

- Export des cles de recuperation BitLocker
- Reinitialisation du TPM avec double validation

## Solution 1: PowerShell

**Fichier** : `CPUVirtualizationCheck.ps1`

**Utilisation** :

```Powershell
# Detection standard
.\CPUVirtualizationCheck.ps1

# Avec droits administrateur (recommande)Right-click -> "Executer avec PowerShell" en tant qu'administrateur

# Exporter les cles BitLocker
.\CPUVirtualizationCheck.ps1 -ExportKeys

# Reinitialiser le TPM
.\CPUVirtualizationCheck.ps1 -ClearTPM

# Afficher l'aide
.\CPUVirtualizationCheck.ps1 -Help
```

### Fonctionnalites

- Detection automatique du processeur (Intel/AMD)
- Verification des fonctionnalites de virtualisation (VT-x/SVM, VT-d/IOMMU)
- Statut NX/DEP detaille
- Statut TPM complet (presence, version, activation)
- Statut BitLocker sur tous les lecteurs
- Verification de compatibilite Windows 11
- Export des cles de recuperation BitLocker
- Reinitialisation securisee du TPM avec double validation
- Informations complementaires (Hyper-V, VBS, Secure Boot)
- Export des resultats en fichier texte
- Recommandations personnalisees

## Solution 2: Go (Golang)

**Fichier** :

cpuvirtcheck/ - Projet Go complet

### Compilation

```bash
# Depuis le dossier cpuvirtcheck
go build -o cpuvirtcheck.exe

# Pour une taille reduite (strip)
go build -ldflags="-s -w" -o cpuvirtcheck.exe
```

Compilation croisee (depuis Linux/Mac)

```bash
# Windows 64-bit
GOOS=windows GOARCH=amd64 go build -o cpuvirtcheck.exe

# Windows 32-bit
GOOS=windows GOARCH=386 go build -o cpuvirtcheck.exe
```

### Utilisation

```cmd
cpuvirtcheck.exe              # Detection standard
cpuvirtcheck.exe -exportkeys  # Export cles BitLocker
cpuvirtcheck.exe -cleartpm    # Reinitialiser TPM
cpuvirtcheck.exe -help        # Afficher l'aide
```

### Fonctionnalites detectees

**Virtualisation CPU**

| Fonctionnalite         | Intel | AMD    | Description                               |
| ---------------------- | ----- | ------ | ----------------------------------------- |
| Virtualisation de base | VT-x  | SVM    | Permet d'executer des machines virtuelles |
| IOMMU                  | VT-d  | AMD-Vi | Passthrough PCI, isolation DMA            |
| SLAT                   | EPT   | NPT    | Tables de pages imbriquees pour les VM    |

**Securite Systeme**

| Fonctionnalite | Description                                                       |
| -------------- | ----------------------------------------------------------------- |
| NX/DEP         | Protection contre l'execution de code dans les zones de donnees   |
| TPM            | Module de securite materielle pour BitLocker, Windows Hello, etc. |
| Secure Boot    | Verification de l'integrite du bootloader                         |
| BitLocker      | Chiffrement des lecteurs avec statut detaille                     |

**TPM (Trusted Platform Module)**

| Information              | Description                             |
| ------------------------ | --------------------------------------- |
| Presence                 | TPM present sur le systeme              |
| Version                  | 1.2 ou 2.0 (2.0 requis pour Windows 11) |
| Activation               | TPM active dans le BIOS                 |
| Etat                     | TPM operationnel et pret a l'emploi     |
| Fabricant                | Identifiant du fabricant TPM            |
| Compatibilite Windows 11 | Verification des pre-requis TPM         |

**BitLocker Drive Encryption**

| Information             | Description                               |
| ----------------------- | ----------------------------------------- |
| Statut par lecteur      | Active / Desactive                        |
| Pourcentage chiffrement | Progression du chiffrement                |
| Cle de recuperation     | Presente ou manquante                     |
| Lecteurs chiffres       | Liste des lecteurs avec protection active |

### Options de ligne de commande

**PowerShell**

| Option        | Description                                               |
| ------------- | --------------------------------------------------------- |
| `-ExportKeys` | Exporte les cles de recuperation BitLocker vers le Bureau |
| `-ClearTPM`   | Reinitialise le TPM aux valeurs d'usine (avec validation) |
| `-Help`       | Affiche l'aide complete                                   |

**Go**

| Option        | Description                                |
| ------------- | ------------------------------------------ |
| `-exportkeys` | Exporte les cles de recuperation BitLocker |
| `-cleartpm`   | Reinitialise le TPM (avec validation)      |
| `-help`       | Affiche l'aide                             |

**Reinitialisation du TPM**

**ATTENTION - CRITIQUE**

La reinitialisation du TPM est une operation destructrice qui efface toutes les donnees stockees dans le module de securite.

**Ce qui se passe lors de la reinitialisation**

1. Toutes les cles stockees dans le TPM sont effacees
1. Les cles BitLocker liees au TPM deviennent inutilisables
1. Le TPM revient a son etat d'usine

**Procedure securisee integree**
Le script integre une procedure de securite avec **double validation**:

1. Detection automatique de l'etat BitLocker
1. Avertissement critique si BitLocker est actif
1. Affichage de la procedure de sauvegarde des cles
1. Premiere validation: Confirmer la sauvegarde des cles (taper "OUI")
1. Deuxieme validation: Confirmer la reinitialisation (taper "REINITIALISER")
1. Dernier avertissement avant execution

**Exemple de flux**

```text

============================================================
  ATTENTION - REINITIALISATION DU TPM
============================================================

  DETECTION: BitLocker est ACTIVE sur les lecteurs suivants:
    - C:
    - D:

  AVERTISSEMENT CRITIQUE:
  Vos cles BitLocker sont stockees dans le TPM actuel.
  La reinitialisation du TPM rendra ces cles inutilisables!

  Premiere validation requise
  ----------------------------
  Tapez 'OUI' pour confirmer que vous avez sauvegarde vos cles BitLocker: OUI

  Deuxieme validation requise
  ----------------------------
  Tapez 'REINITIALISER' pour confirmer la reinitialisation du TPM: REINITIALISER

  DERNIER AVERTISSEMENT
  --------------------
  Le TPM va etre reinitialise. Continuer? (O/N): O

  Reinitialisation du TPM en cours...
  TPM reinitialise avec succes!
```

### Export des cles BitLocker

**Methode 1**: Via le script (recommande)

```powershell
.\CPUVirtualizationCheck.ps1 -ExportKeys
```

Les cles sont exportees vers un fichier sur le Bureau:
`BitLockerRecoveryKeys_YYYYMMDD_HHMMSS.txt`

**Methode 2**: Via les parametres Windows

1. Ouvrir Parametres > Confidentialite et securite > Chiffrement BitLocker
1. Cliquer sur le lecteur chiffre
1. Cliquer sur "Sauvegarder la cle de recuperation"
1. Choisir l'emplacement:
1. Compte Microsoft (recommande, synchronise dans le cloud)
1. Fichier USB
1. Fichier sur un autre lecteur
1. Imprimer

**Methode 3**: Via l'invite de commandes

```cmd
manage-bde -protectors -get C:
```

La cle de recuperation apparait sous "Mot de passe de recuperation" (48 chiffres).

**Conseils de sauvegarde**

- Sauvegardez sur PLUSIEURS supports (USB + cloud + papier)
- Ne stockez JAMAIS les cles sur le disque chiffre
- Conservez une copie papier dans un endroit sur
- Verifiez que vous pouvez acceder aux cles avant de modifier le TPM

Pre-requis pour Windows 11

Ce programme permet de verifier automatiquement les pre-requis pour Windows 11 :

| Pre-requis      | Valeur requise | Detecte par le script |
| --------------- | -------------- | --------------------- |
| TPM             | Version 2.0+   | Oui                   |
| Secure Boot     | Active         | Oui                   |
| Generation UEFI | (pas Legacy)   | Oui                   |
| RAM             | 4 Go minimum   | Partiellement         |
| Stockage        | 64 Go minimum  | Partiellement         |

Configuration BIOS/UEFI

Intel
| Option | Noms possibles selon BIOS                        |
| ------ | ------------------------------------------------ |
| VT-x   | Intel VT-x, Intel Virtualization Technology, VMX |
| VT-d   | Intel VT-d, Intel I/O Virtualization, IOMMU      |
| XD     | Execute Disable Bit, XD Technology, No-eXecute   |

**AMD**

| Option | Noms possibles selon BIOS               |
| ------ | --------------------------------------- |
| SVM    | AMD-V, SVM Mode, AMD Virtualization     |
| IOMMU  | AMD IOMMU, AMD-Vi, I/O Virtualization   |
| NX     | NX Mode, No-eXecute, Execute Protection |

**TPM (tous fabricants)**

| Option | Noms possibles selon BIOS                  |
| ------ | ------------------------------------------ |
| TPM    | TPM Device, TPM 2.0, Security Device, fTPM |
| Mode   | Enabled, Discrete TPM, Firmware TPM        |

**Exemple de sortie**

```text

============================================================
  DETECTEUR DE VIRTUALISATION CPU ET SECURITE
============================================================

  Processeur : AMD Ryzen 9 5900X 12-Core Processor
  Fabricant  : AMD

============================================================
  RESULTATS DE LA DETECTION
============================================================
  AMD SVM (Secure Virtual Machine) : [ACTIVE]
    -> Equivalent AMD d'Intel VT-x
  AMD NPT (SLAT) : [ACTIVE]
    -> Nested Page Tables pour performances VM
  NX / DEP (No-eXecute) : [ACTIVE]
    -> OptIn (actif pour les systemes essentiels)
  AMD-Vi (AMD IOMMU) : [ACTIVE]
    -> VBS active - IOMMU probablement actif

  --- MODULE TPM (Trusted Platform Module) ---
  TPM Present : [ACTIVE]
  TPM Version               : 2.0
  TPM Active : [ACTIVE]
  TPM Pret : [ACTIVE]
  Compatible Windows 11 : [ACTIVE]
    -> TPM 2.0 actif et pret

  --- BITLOCKER DRIVE ENCRYPTION ---
  Lecteur C: : [ACTIVE]
    -> Chiffrement: 100%
    -> Cle de recuperation: Presente
  Lecteur D: : [DESACTIVE]
    -> Statut: Non chiffre

============================================================
  INFORMATIONS COMPLEMENTAIRES
============================================================
  Hyper-V                    : Installe
  VBS (Device Guard)         : Active
  Core Isolation             : Active
  Secure Boot                : Active

============================================================
  OPTIONS DISPONIBLES:
============================================================
    -ExportKeys : Exporter les cles de recuperation BitLocker
    -ClearTPM   : Reinitialiser le TPM (ATTENTION: voir documentation)
    -Help       : Afficher l'aide complete
```

### Prerequis techniques

**PowerShell**

- Windows 10/11
- PowerShell 5.1 ou superieur
- Droits administrateur pour:
  - Reinitialisation TPM (-ClearTPM)
  - Export complet des cles BitLocker

**Go**

- Go 1.21 ou superieur
- Windows 10/11
- Droits administrateur pour:
  - Reinitialisation TPM (-cleartpm)
  - Acces complet aux informations systeme

## Notes importantes

1. Droits administrateur : Necessaires pour la reinitialisation TPM
1. BIOS/UEFI : La virtualisation et le TPM doivent etre actives dans le BIOS
1. Hyper-V : Peut interferer avec d'autres hyperviseurs
1. Secure Boot : Necessaire pour certaines fonctionnalites VBS
1. TPM 2.0 : Requis pour Windows 11, BitLocker, Windows Hello
1. BitLocker : Sauvegardez TOUJOURS vos cles avant de modifier le TPM

## Licence

Ce projet est fourni tel quel, sans garantie. Libre d'utilisation et de modification.
