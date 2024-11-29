import os
import subprocess
import winreg
import sys
from io import StringIO
import datetime
import socket


# Définir les codes ANSI pour les couleurs
RED = "\033[91m" # red
ORANGE = "\033[93m"  # Jaune
GREEN = "\033[92m" # Green
RESET = "\033[0m"  # Réinitialiser les couleurs

print(f"{ORANGE}Lancement du script de vérification de conformité CIS Benchmark 3.0 pour Windows 11{RESET}")
print(f"{ORANGE}Un rapport sera généré à la fin, dans le répertoire d'exécution du script{RESET}")
print(f"{ORANGE}Merci de patienter...{RESET}")

def compliance_check(func):
    """
    Décorateur pour capturer les résultats des fonctions et les convertir en
    un format structuré (id, policy, status, details).
    """
    def wrapper(*args, **kwargs):
        # Capture du flux stdout
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        result = {"id": func.__name__, "policy": func.__doc__.strip() if func.__doc__ else func.__name__}

        try:
            # Exécuter la fonction et capturer ses impressions
            func(*args, **kwargs)
            output = sys.stdout.getvalue().strip()

            # Déterminer le statut en fonction des couleurs ANSI dans l'output
            if "\033[92m" in output:  # GREEN
                result["status"] = "Conforme"
            elif "\033[91m" in output:  # RED
                result["status"] = "Non conforme"
            else:
                result["status"] = "Inconnu"

            result["details"] = output.replace("\033[91m", "").replace("\033[92m", "").replace("\033[0m", "")
        except Exception as e:
            result["status"] = "Erreur"
            result["details"] = str(e)
        finally:
            # Restaurer le flux stdout
            sys.stdout = old_stdout

        return result
    return wrapper

@compliance_check
# Contrôle 1.1.1 : Vérifier l'historique des mots de passe
def check_password_history():
    """
    Vérifie si l'historique des mots de passe Windows est configuré à 24 mots de passe ou plus.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'PasswordHistorySize'
        password_history_line = next((line for line in lines if "PasswordHistorySize" in line), None)

        # Vérifier et afficher la configuration
        if password_history_line:
            value = int(password_history_line.split('=')[1].strip())
            if value >= 24:
                print(f"{GREEN}1.1.1 Enforce password history: Conforme (Valeur Relevée: {value} mots de passe){RESET}")
            else:
                print(f"{RED}1.1.1 Enforce password history: Non conforme (Valeur Relevée: {value} mots de passe){RESET}")
        else:
            print(f"{RED}1.1.1 Enforce password history: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 1.1.1 : {e}{RESET}")

@compliance_check
# Contrôle 1.1.2 : Vérifier la politique "Maximum password age"
def check_maximum_password_age():
    """
    Vérifie si la politique 'Maximum password age' est configurée à 365 jours ou moins, mais pas 0.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'MaximumPasswordAge'
        max_password_age_line = next((line for line in lines if "MaximumPasswordAge" in line), None)

        # Vérifier et afficher la configuration
        if max_password_age_line:
            value = int(max_password_age_line.split('=')[1].strip())
            if value == 0:
                print(f"{RED}1.1.2 Maximum password age: Non conforme (Valeur Relevée: {value} jours - 0 jours n'est pas valide){RESET}")
            elif value <= 365:
                print(f"{GREEN}1.1.2 Maximum password age: Conforme (Valeur Relevée: {value} jours - ≤ 365 jours){RESET}")
            else:
                print(f"{RED}1.1.2 Maximum password age: Non conforme (Valeur Relevée: {value} jours - doit être ≤ 365 jours){RESET}")
        else:
            print(f"{RED}1.1.2 Maximum password age: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 1.1.2 : {e}{RESET}")


@compliance_check
# Contrôle 1.1.3 : Vérifier la politique "Minimum password age"
def check_minimum_password_age():
    """
    Vérifie si la politique 'Minimum password age' est configurée à 1 jour ou plus.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'MinimumPasswordAge'
        min_password_age_line = next((line for line in lines if "MinimumPasswordAge" in line), None)

        # Vérifier et afficher la configuration
        if min_password_age_line:
            value = int(min_password_age_line.split('=')[1].strip())
            if value >= 1:
                print(f"{GREEN}1.1.3 Minimum password age: Conforme (Valeur Relevée: {value} jour(s) - ≥ 1 jour){RESET}")
            else:
                print(f"{RED}1.1.3 Minimum password age: Non conforme (Valeur Relevée: {value} jour(s) - doit être 1 jour ou plus){RESET}")
        else:
            print(f"{RED}1.1.3 Minimum password age: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 1.1.3 : {e}{RESET}")


@compliance_check
# Contrôle 1.1.4 : Vérifier la politique "Minimum password length"
def check_minimum_password_length():
    """
    Vérifie si la politique 'Minimum password length' est configurée à 14 caractères ou plus.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'MinimumPasswordLength'
        min_password_length_line = next((line for line in lines if "MinimumPasswordLength" in line), None)

        # Vérifier et afficher la configuration
        if min_password_length_line:
            value = int(min_password_length_line.split('=')[1].strip())
            if value >= 14:
                print(f"{GREEN}1.1.4 Minimum password length: Conforme (Valeur Relevée: {value} caractères - 14 ou plus requis){RESET}")
            else:
                print(f"{RED}1.1.4 Minimum password length: Non conforme (Valeur Relevée: {value} caractères - doit être 14 ou plus){RESET}")
        else:
            print(f"{RED}1.1.4 Minimum password length: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 1.1.4 : {e}{RESET}")


@compliance_check
# Contrôle 1.1.5 : Vérifier si la politique "Password must meet complexity requirements" est activée
def check_password_complexity():
    """
    Vérifie si la politique 'Password must meet complexity requirements' est activée.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'PasswordComplexity'
        password_complexity_line = next((line for line in lines if "PasswordComplexity" in line), None)

        # Vérifier et afficher la configuration
        if password_complexity_line:
            value = int(password_complexity_line.split('=')[1].strip())
            if value == 1:  # Si la valeur est 1, la politique est activée
                print(f"{GREEN}1.1.5 Password must meet complexity requirements: Conforme (Valeur Relevée: Activé){RESET}")
            else:
                print(f"{RED}1.1.5 Password must meet complexity requirements: Non conforme (Valeur Relevée: Désactivé){RESET}")
        else:
            print(f"{RED}1.1.5 Password must meet complexity requirements: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 1.1.5 : {e}{RESET}")

@compliance_check
# Contrôle 1.1.6 : Vérifier si la politique "Relax minimum password length limits" est activée
def check_relax_minimum_password_length_limits():
    """
    Vérifie si la politique 'Relax minimum password length limits' est activée.
    """
    try:
        # Rechercher dans le registre la clé correspondante à "RelaxMinimumPasswordLengthLimits"
        registry_path = r"HKLM\System\CurrentControlSet\Control\SAM"
        key_name = "RelaxMinimumPasswordLengthLimits"
        
        # Lire la valeur du registre
        import winreg
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérifier et afficher la configuration
            if value == 1:
                print(f"{GREEN}1.1.6 Relax minimum password length limits: Conforme (Valeur Relevée: Activé){RESET}")
            else:
                print(f"{RED}1.1.6 Relax minimum password length limits: Non conforme (Valeur Relevée: Désactivé){RESET}")

        except FileNotFoundError:
            print(f"{RED}1.1.6 Relax minimum password length limits: Non conforme (Valeur Relevée: Introuvable){RESET}")
            return
    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 1.1.6 : {e}{RESET}")

@compliance_check
# Contrôle 1.1.7 : Vérifier la politique "Store passwords using reversible encryption"
def check_reversible_encryption():
    """
    Vérifie si la politique 'Store passwords using reversible encryption' est désactivée.
    """
    try:
        # Rechercher dans le registre la clé correspondante à "StorePasswordsUsingReversibleEncryption"
        registry_path = r"HKLM\System\CurrentControlSet\Control\Lsa"
        key_name = "LimitBlankPasswordUse"
        
        # Lire la valeur du registre
        import winreg
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérifier et afficher la configuration
            if value == 0:
                print(f"{GREEN}1.1.7 Store passwords using reversible encryption: Conforme (Valeur Relevée: Désactivé){RESET}")
            else:
                print(f"{RED}1.1.7 Store passwords using reversible encryption: Non conforme (Valeur Relevée: Activé){RESET}")

        except FileNotFoundError:
            print(f"{RED}1.1.7 Store passwords using reversible encryption: Non conforme (Valeur Relevée: Introuvable){RESET}")
            return
    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 1.1.7 : {e}{RESET}")

@compliance_check
# Contrôle 1.2.1 : Vérifier la politique "Account lockout duration"
def check_account_lockout_duration():
    """
    Vérifie si la politique 'Account lockout duration' est configurée à 15 minutes ou plus.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'LockoutDuration'
        lockout_duration_line = next((line for line in lines if "LockoutDuration" in line), None)

        # Vérifier et afficher la configuration
        if lockout_duration_line:
            value = int(lockout_duration_line.split('=')[1].strip())
            if value >= 15:
                print(f"{GREEN}1.2.1 Account lockout duration: Conforme (Valeur Relevée: {value} minutes){RESET}")
            else:
                print(f"{RED}1.2.1 Account lockout duration: Non conforme (Valeur Relevée: {value} minutes - doit être 15 ou plus){RESET}")
        else:
            print(f"{RED}1.2.1 Account lockout duration: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 1.2.1 : {e}{RESET}")

@compliance_check
# Contrôle 1.2.2 : Vérifier la politique "Account lockout threshold"
def check_account_lockout_threshold():
    """
    Vérifie si la politique 'Account lockout threshold' est configurée à 5 tentatives ou moins,
    mais pas à 0.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'LockoutBadCount'
        lockout_threshold_line = next((line for line in lines if "LockoutBadCount" in line), None)

        # Vérifier et afficher la configuration
        if lockout_threshold_line:
            value = int(lockout_threshold_line.split('=')[1].strip())
            if value == 0:
                print(f"{RED}1.2.2 Account lockout threshold: Non conforme (Valeur Relevée: {value} - ne doit pas être 0){RESET}")
            elif value <= 5:
                print(f"{GREEN}1.2.2 Account lockout threshold: Conforme (Valeur Relevée: {value} tentatives){RESET}")
            else:
                print(f"{RED}1.2.2 Account lockout threshold: Non conforme (Valeur Relevée: {value} tentatives - doit être 5 ou moins){RESET}")
        else:
            print(f"{RED}1.2.2 Account lockout threshold: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 1.2.2 : {e}{RESET}")

@compliance_check
# Contrôle 1.2.3 : Vérifier la politique "Allow Administrator account lockout"
def check_administrator_account_lockout():
    """
    Vérifie si la politique 'Allow Administrator account lockout' est activée.
    """
    try:
        # Rechercher dans le registre la clé correspondante à "Accounts: Administrator account lockout"
        registry_path = r"HKLM\System\CurrentControlSet\Control\Lsa"
        key_name = "Accounts: Administrator account lockout"

        # Lire la valeur du registre
        import winreg
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérifier et afficher la configuration
            if value == 1:
                print(f"{GREEN}1.2.3 Allow Administrator account lockout: Conforme (Valeur Relevée: Activé){RESET}")
            else:
                print(f"{RED}1.2.3 Allow Administrator account lockout: Non conforme (Valeur Relevée: Désactivé){RESET}")

        except FileNotFoundError:
            print(f"{RED}1.2.3 Allow Administrator account lockout: Non conforme (Valeur Relevée: Introuvable){RESET}")
            return
    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 1.2.3 : {e}{RESET}")

@compliance_check
# Contrôle 1.2.4 : Vérifier la politique "Reset account lockout counter after"
def check_reset_account_lockout_counter():
    """
    Vérifie si la politique 'Reset account lockout counter after' est configurée à 15 minutes ou plus.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'LockoutDuration' (relatif à la durée de verrouillage)
        lockout_counter_line = next((line for line in lines if "ResetLockoutCount" in line), None)

        # Vérifier et afficher la configuration
        if lockout_counter_line:
            value = int(lockout_counter_line.split('=')[1].strip())
            if value >= 15:
                print(f"{GREEN}1.2.4 Reset account lockout counter after: Conforme (Valeur Relevée: {value} minutes){RESET}")
            else:
                print(f"{RED}1.2.4 Reset account lockout counter after: Non conforme (Valeur Relevée: {value} minutes - doit être 15 ou plus){RESET}")
        else:
            print(f"{RED}1.2.4 Reset account lockout counter after: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 1.2.4 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.1 : Vérifier la politique "Access Credential Manager as a trusted caller"
def check_access_credential_manager():
    """
    Vérifie si la politique 'Access Credential Manager as a trusted caller' est définie sur 'No One'.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeDenyInteractiveLogonRight' (la politique pertinente)
        credential_manager_line = next((line for line in lines if "SeDenyInteractiveLogonRight" in line), None)

        # Vérifier et afficher la configuration
        if credential_manager_line:
            value = credential_manager_line.split('=')[1].strip()
            if value == "No One":
                print(f"{GREEN}2.2.1 Access Credential Manager as a trusted caller: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.1 Access Credential Manager as a trusted caller: Non conforme (Valeur Relevée: {value} - doit être 'No One'){RESET}")
        else:
            print(f"{RED}2.2.1 Access Credential Manager as a trusted caller: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.1 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.2 : Vérifier la politique "Access this computer from the network"
def check_access_computer_from_network():
    """
    Vérifie si la politique 'Access this computer from the network' est configurée à 'Administrators, Remote Desktop Users' 
    ou 'Administrateurs, Utilisateurs du Bureau à distance' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeRemoteInteractiveLogonRight' (c'est la politique correspondante)
        network_access_line = next((line for line in lines if "SeRemoteInteractiveLogonRight" in line), None)

        # Vérifier et afficher la configuration
        if network_access_line:
            value = network_access_line.split('=')[1].strip()
            # Vérification des groupes autorisés (en anglais et en français)
            if value == "Administrators, Remote Desktop Users" or value == "Administrateurs, Utilisateurs du Bureau à distance":
                print(f"{GREEN}2.2.2 Access this computer from the network: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.2 Access this computer from the network: Non conforme (Valeur Relevée: {value} - doit être 'Administrators, Remote Desktop Users' ou 'Administrateurs, Utilisateurs du Bureau à distance'){RESET}")
        else:
            print(f"{RED}2.2.2 Access this computer from the network: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.2 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.3 : Vérifier la politique "Act as part of the operating system"
def check_act_as_part_of_os():
    """
    Vérifie si la politique 'Act as part of the operating system' est configurée à 'No One'.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeTakeOwnershipPrivilege' (la politique correspondante)
        act_as_part_of_os_line = next((line for line in lines if "SeTakeOwnershipPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if act_as_part_of_os_line:
            value = act_as_part_of_os_line.split('=')[1].strip()
            if value == "No One":
                print(f"{GREEN}2.2.3 Act as part of the operating system: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.3 Act as part of the operating system: Non conforme (Valeur Relevée: {value} - doit être 'No One'){RESET}")
        else:
            print(f"{RED}2.2.3 Act as part of the operating system: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.3 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.4 : Vérifier la politique "Adjust memory quotas for a process"
def check_adjust_memory_quotas():
    """
    Vérifie si la politique 'Adjust memory quotas for a process' est configurée à 
    'Administrators, LOCAL SERVICE, NETWORK SERVICE' ou 'Administrateurs, SERVICE LOCAL, SERVICE RÉSEAU' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeIncreaseQuotaPrivilege' (la politique correspondante)
        memory_quotas_line = next((line for line in lines if "SeIncreaseQuotaPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if memory_quotas_line:
            value = memory_quotas_line.split('=')[1].strip()
            # Vérification des groupes autorisés (en anglais et en français)
            if value == "Administrators, LOCAL SERVICE, NETWORK SERVICE" or value == "Administrateurs, SERVICE LOCAL, SERVICE RÉSEAU":
                print(f"{GREEN}2.2.4 Adjust memory quotas for a process: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.4 Adjust memory quotas for a process: Non conforme (Valeur Relevée: {value} - doit être 'Administrators, LOCAL SERVICE, NETWORK SERVICE' ou 'Administrateurs, SERVICE LOCAL, SERVICE RÉSEAU'){RESET}")
        else:
            print(f"{RED}2.2.4 Adjust memory quotas for a process: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.4 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.5 : Vérifier la politique "Allow log on locally"
def check_allow_log_on_locally():
    """
    Vérifie si la politique 'Allow log on locally' est configurée à 
    'Administrators, Users' ou 'Administrateurs, Utilisateurs' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeDenyInteractiveLogonRight' (c'est la politique correspondante)
        logon_locally_line = next((line for line in lines if "SeDenyInteractiveLogonRight" in line), None)

        # Vérifier et afficher la configuration
        if logon_locally_line:
            value = logon_locally_line.split('=')[1].strip()
            # Vérification des groupes autorisés (en anglais et en français)
            if value == "Administrators, Users" or value == "Administrateurs, Utilisateurs":
                print(f"{GREEN}2.2.5 Allow log on locally: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.5 Allow log on locally: Non conforme (Valeur Relevée: {value} - doit être 'Administrators, Users' ou 'Administrateurs, Utilisateurs'){RESET}")
        else:
            print(f"{RED}2.2.5 Allow log on locally: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.5 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.6 : Vérifier la politique "Allow log on through Remote Desktop Services"
def check_allow_log_on_remote_desktop():
    """
    Vérifie si la politique 'Allow log on through Remote Desktop Services' est configurée à 
    'Administrators, Remote Desktop Users' ou 'Administrateurs, Utilisateurs Bureau à distance' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeRemoteInteractiveLogonRight' (la politique correspondante)
        remote_desktop_line = next((line for line in lines if "SeRemoteInteractiveLogonRight" in line), None)

        # Vérifier et afficher la configuration
        if remote_desktop_line:
            value = remote_desktop_line.split('=')[1].strip()
            # Vérification des groupes autorisés (en anglais et en français)
            if value == "Administrators, Remote Desktop Users" or value == "Administrateurs, Utilisateurs Bureau à distance":
                print(f"{GREEN}2.2.6 Allow log on through Remote Desktop Services: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.6 Allow log on through Remote Desktop Services: Non conforme (Valeur Relevée: {value} - doit être 'Administrators, Remote Desktop Users' ou 'Administrateurs, Utilisateurs Bureau à distance'){RESET}")
        else:
            print(f"{RED}2.2.6 Allow log on through Remote Desktop Services: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.6 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.7 : Vérifier la politique "Back up files and directories"
def check_back_up_files_and_directories():
    """
    Vérifie si la politique 'Back up files and directories' est configurée à 
    'Administrators' ou 'Administrateurs' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeBackupPrivilege' (c'est la politique correspondante)
        backup_files_line = next((line for line in lines if "SeBackupPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if backup_files_line:
            value = backup_files_line.split('=')[1].strip()
            # Vérification en anglais et en français
            if value == "Administrators" or value == "Administrateurs":
                print(f"{GREEN}2.2.7 Back up files and directories: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.7 Back up files and directories: Non conforme (Valeur Relevée: {value} - doit être 'Administrators' ou 'Administrateurs'){RESET}")
        else:
            print(f"{RED}2.2.7 Back up files and directories: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.7 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.8 : Vérifier la politique "Change the system time"
def check_change_system_time():
    """
    Vérifie si la politique 'Change the system time' est configurée à 
    'Administrators, LOCAL SERVICE' ou 'Administrateurs, SERVICE LOCAL' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeSystemTimePrivilege' (la politique correspondante)
        system_time_line = next((line for line in lines if "SeSystemTimePrivilege" in line), None)

        # Vérifier et afficher la configuration
        if system_time_line:
            value = system_time_line.split('=')[1].strip()
            # Vérification en anglais et en français
            if value == "Administrators, LOCAL SERVICE" or value == "Administrateurs, SERVICE LOCAL":
                print(f"{GREEN}2.2.8 Change the system time: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.8 Change the system time: Non conforme (Valeur Relevée: {value} - doit être 'Administrators, LOCAL SERVICE' ou 'Administrateurs, SERVICE LOCAL'){RESET}")
        else:
            print(f"{RED}2.2.8 Change the system time: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.8 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.9 : Vérifier la politique "Change the time zone"
def check_change_time_zone():
    """
    Vérifie si la politique 'Change the time zone' est configurée à 
    'Administrators, LOCAL SERVICE, Users' ou 'Administrateurs, SERVICE LOCAL, Utilisateurs' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeTimeZonePrivilege' (c'est la politique correspondante)
        time_zone_line = next((line for line in lines if "SeTimeZonePrivilege" in line), None)

        # Vérifier et afficher la configuration
        if time_zone_line:
            value = time_zone_line.split('=')[1].strip()
            # Vérification en anglais et en français
            if value == "Administrators, LOCAL SERVICE, Users" or value == "Administrateurs, SERVICE LOCAL, Utilisateurs":
                print(f"{GREEN}2.2.9 Change the time zone: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.9 Change the time zone: Non conforme (Valeur Relevée: {value} - doit être 'Administrators, LOCAL SERVICE, Users' ou 'Administrateurs, SERVICE LOCAL, Utilisateurs'){RESET}")
        else:
            print(f"{RED}2.2.9 Change the time zone: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.9 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.10 : Vérifier la politique "Create a pagefile"
def check_create_pagefile():
    """
    Vérifie si la politique 'Create a pagefile' est configurée à 
    'Administrators' ou 'Administrateurs' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeCreatePagefilePrivilege' (la politique correspondante)
        create_pagefile_line = next((line for line in lines if "SeCreatePagefilePrivilege" in line), None)

        # Vérifier et afficher la configuration
        if create_pagefile_line:
            value = create_pagefile_line.split('=')[1].strip()
            # Vérification en anglais et en français
            if value == "Administrators" or value == "Administrateurs":
                print(f"{GREEN}2.2.10 Create a pagefile: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.10 Create a pagefile: Non conforme (Valeur Relevée: {value} - doit être 'Administrators' ou 'Administrateurs'){RESET}")
        else:
            print(f"{RED}2.2.10 Create a pagefile: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.10 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.11 : Vérifier la politique "Create a token object"
def check_create_token_object():
    """
    Vérifie si la politique 'Create a token object' est configurée à 'No One'.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeCreateTokenPrivilege' (c'est la politique correspondante)
        create_token_line = next((line for line in lines if "SeCreateTokenPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if create_token_line:
            value = create_token_line.split('=')[1].strip()
            if value == "No One":
                print(f"{GREEN}2.2.11 Create a token object: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.11 Create a token object: Non conforme (Valeur Relevée: {value} - doit être 'No One'){RESET}")
        else:
            print(f"{RED}2.2.11 Create a token object: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.11 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.12 : Vérifier la politique "Create global objects"
def check_create_global_objects():
    """
    Vérifie si la politique 'Create global objects' est configurée à 
    'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' ou 'Administrateurs, SERVICE LOCAL, SERVICE RÉSEAU, SERVICE' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeCreateGlobalPrivilege' (c'est la politique correspondante)
        create_global_objects_line = next((line for line in lines if "SeCreateGlobalPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if create_global_objects_line:
            value = create_global_objects_line.split('=')[1].strip()
            # Vérification en anglais et en français
            if value == "Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE" or value == "Administrateurs, SERVICE LOCAL, SERVICE RÉSEAU, SERVICE":
                print(f"{GREEN}2.2.12 Create global objects: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.12 Create global objects: Non conforme (Valeur Relevée: {value} - doit être 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' ou 'Administrateurs, SERVICE LOCAL, SERVICE RÉSEAU, SERVICE'){RESET}")
        else:
            print(f"{RED}2.2.12 Create global objects: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.12 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.13 : Vérifier la politique "Create permanent shared objects"
def check_create_permanent_shared_objects():
    """
    Vérifie si la politique 'Create permanent shared objects' est configurée à 'No One'.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeCreatePermanentSharedObjectsPrivilege' (c'est la politique correspondante)
        create_permanent_shared_objects_line = next((line for line in lines if "SeCreatePermanentSharedObjectsPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if create_permanent_shared_objects_line:
            value = create_permanent_shared_objects_line.split('=')[1].strip()
            if value == "No One":
                print(f"{GREEN}2.2.13 Create permanent shared objects: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.13 Create permanent shared objects: Non conforme (Valeur Relevée: {value} - doit être 'No One'){RESET}")
        else:
            print(f"{RED}2.2.13 Create permanent shared objects: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.13 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.14 : Vérifier la politique "Create symbolic links"
def check_create_symbolic_links():
    """
    Vérifie si la politique 'Create symbolic links' est configurée à 
    'Administrators' et (si Hyper-V est installé) 'NT VIRTUAL MACHINE\\Virtual Machines' (en anglais et en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeCreateSymbolicLinkPrivilege' (c'est la politique correspondante)
        create_symbolic_link_line = next((line for line in lines if "SeCreateSymbolicLinkPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if create_symbolic_link_line:
            value = create_symbolic_link_line.split('=')[1].strip()
            expected_value = "Administrators"
            
            # Si Hyper-V est installé, on ajoute la condition NT VIRTUAL MACHINE\\Virtual Machines
            if "NT VIRTUAL MACHINE\\Virtual Machines" in value:
                expected_value = "Administrators, NT VIRTUAL MACHINE\\Virtual Machines"

            # Vérification en anglais et en français
            if value == expected_value or value == "Administrateurs" or value == "Administrateurs, MACHINE VIRTUELLE NT\\Machines Virtuelles":
                print(f"{GREEN}2.2.14 Create symbolic links: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.14 Create symbolic links: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}' ou 'Administrateurs, MACHINE VIRTUELLE NT\\Machines Virtuelles'){RESET}")
        else:
            print(f"{RED}2.2.14 Create symbolic links: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.14 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.15 : Vérifier la politique "Debug programs"
def check_debug_programs():
    """
    Vérifie si la politique 'Debug programs' est configurée à 
    'Administrators' ou 'Administrateurs' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeDebugPrivilege' (c'est la politique correspondante)
        debug_programs_line = next((line for line in lines if "SeDebugPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if debug_programs_line:
            value = debug_programs_line.split('=')[1].strip()

            # Vérification en anglais et en français
            if value == "Administrators" or value == "Administrateurs":
                print(f"{GREEN}2.2.15 Debug programs: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.15 Debug programs: Non conforme (Valeur Relevée: {value} - doit être 'Administrators' ou 'Administrateurs'){RESET}")
        else:
            print(f"{RED}2.2.15 Debug programs: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.15 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.16 : Vérifier la politique "Deny access to this computer from the network"
def check_deny_access_to_network():
    """
    Vérifie si la politique 'Deny access to this computer from the network' inclut 'Guests' (en anglais) ou 'Invité' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeDenyNetworkLogon' (c'est la politique correspondante)
        deny_network_line = next((line for line in lines if "SeDenyNetworkLogon" in line), None)

        # Vérifier et afficher la configuration
        if deny_network_line:
            value = deny_network_line.split('=')[1].strip()

            # Vérification pour les termes "Guests" et "Invité"
            if "Guests" in value or "Invité" in value:
                print(f"{GREEN}2.2.16 Deny access to this computer from the network: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.16 Deny access to this computer from the network: Non conforme (Valeur Relevée: {value} - doit inclure 'Guests' ou 'Invité'){RESET}")
        else:
            print(f"{RED}2.2.16 Deny access to this computer from the network: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.16 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.17 : Vérifier la politique "Deny log on as a batch job"
def check_deny_log_on_as_batch_job():
    """
    Vérifie si la politique 'Deny log on as a batch job' inclut 'Guests' (en anglais) ou 'Invité' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeDenyBatchLogonRight' (c'est la politique correspondante)
        deny_batch_job_line = next((line for line in lines if "SeDenyBatchLogonRight" in line), None)

        # Vérifier et afficher la configuration
        if deny_batch_job_line:
            value = deny_batch_job_line.split('=')[1].strip()

            # Vérification pour les termes "Guests" et "Invité"
            if "Guests" in value or "Invité" in value:
                print(f"{GREEN}2.2.17 Deny log on as a batch job: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.17 Deny log on as a batch job: Non conforme (Valeur Relevée: {value} - doit inclure 'Guests' ou 'Invité'){RESET}")
        else:
            print(f"{RED}2.2.17 Deny log on as a batch job: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.17 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.18 : Vérifier la politique "Deny log on as a service"
def check_deny_log_on_as_service():
    """
    Vérifie si la politique 'Deny log on as a service' inclut 'Guests' (en anglais) ou 'Invité' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeDenyServiceLogonRight' (c'est la politique correspondante)
        deny_service_line = next((line for line in lines if "SeDenyServiceLogonRight" in line), None)

        # Vérifier et afficher la configuration
        if deny_service_line:
            value = deny_service_line.split('=')[1].strip()

            # Vérification pour "Guests" et "Invité"
            if "Guests" in value or "Invité" in value:
                print(f"{GREEN}2.2.18 Deny log on as a service: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.18 Deny log on as a service: Non conforme (Valeur Relevée: {value} - doit inclure 'Guests' ou 'Invité'){RESET}")
        else:
            print(f"{RED}2.2.18 Deny log on as a service: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.18 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.19 : Vérifier la politique "Deny log on locally"
def check_deny_log_on_locally():
    """
    Vérifie si la politique 'Deny log on locally' inclut 'Guests' (en anglais) ou 'Invité' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeDenyInteractiveLogon' (c'est la politique correspondante)
        deny_logon_locally_line = next((line for line in lines if "SeDenyInteractiveLogon" in line), None)

        # Vérifier et afficher la configuration
        if deny_logon_locally_line:
            value = deny_logon_locally_line.split('=')[1].strip()

            # Vérification pour "Guests" (en anglais) ou "Invité" (en français)
            if "Guests" in value or "Invité" in value:
                print(f"{GREEN}2.2.19 Deny log on locally: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.19 Deny log on locally: Non conforme (Valeur Relevée: {value} - doit inclure 'Guests' ou 'Invité'){RESET}")
        else:
            print(f"{RED}2.2.19 Deny log on locally: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.19 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.20 : Vérifier la politique "Deny log on through Remote Desktop Services"
def check_deny_log_on_remote_desktop():
    """
    Vérifie si la politique 'Deny log on through Remote Desktop Services' inclut 'Guests' (en anglais) ou 'Invité' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeDenyRemoteInteractiveLogon' (c'est la politique correspondante)
        deny_logon_remote_desktop_line = next((line for line in lines if "SeDenyRemoteInteractiveLogon" in line), None)

        # Vérifier et afficher la configuration
        if deny_logon_remote_desktop_line:
            value = deny_logon_remote_desktop_line.split('=')[1].strip()

            # Vérification pour "Guests" (en anglais) ou "Invité" (en français)
            if "Guests" in value or "Invité" in value:
                print(f"{GREEN}2.2.20 Deny log on through Remote Desktop Services: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.20 Deny log on through Remote Desktop Services: Non conforme (Valeur Relevée: {value} - doit inclure 'Guests' ou 'Invité'){RESET}")
        else:
            print(f"{RED}2.2.20 Deny log on through Remote Desktop Services: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.20 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.21 : Vérifier la politique "Enable computer and user accounts to be trusted for delegation"
def check_trusted_for_delegation():
    """
    Vérifie si la politique 'Enable computer and user accounts to be trusted for delegation' 
    est configurée à 'No One'.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeTrustedForDelegation' (c'est la politique correspondante)
        trusted_for_delegation_line = next((line for line in lines if "SeTrustedForDelegation" in line), None)

        # Vérifier et afficher la configuration
        if trusted_for_delegation_line:
            value = trusted_for_delegation_line.split('=')[1].strip()

            if value == "No One":
                print(f"{GREEN}2.2.21 Enable computer and user accounts to be trusted for delegation: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.21 Enable computer and user accounts to be trusted for delegation: Non conforme (Valeur Relevée: {value} - doit être 'No One'){RESET}")
        else:
            print(f"{RED}2.2.21 Enable computer and user accounts to be trusted for delegation: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.21 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.22 : Vérifier la politique "Force shutdown from a remote system"
def check_force_shutdown_remote():
    """
    Vérifie si la politique 'Force shutdown from a remote system' est configurée à 
    'Administrators' ou 'Administrateurs' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeRemoteShutdownPrivilege' (c'est la politique correspondante)
        force_shutdown_remote_line = next((line for line in lines if "SeRemoteShutdownPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if force_shutdown_remote_line:
            value = force_shutdown_remote_line.split('=')[1].strip()

            # Vérification en anglais et en français
            if value == "Administrators" or value == "Administrateurs":
                print(f"{GREEN}2.2.22 Force shutdown from a remote system: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.22 Force shutdown from a remote system: Non conforme (Valeur Relevée: {value} - doit être 'Administrators' ou 'Administrateurs'){RESET}")
        else:
            print(f"{RED}2.2.22 Force shutdown from a remote system: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.22 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.23 : Vérifier la politique "Generate security audits"
def check_generate_security_audits():
    """
    Vérifie si la politique 'Generate security audits' est configurée à 'LOCAL SERVICE, NETWORK SERVICE'.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeAuditPrivilege' (c'est la politique correspondante)
        generate_security_audits_line = next((line for line in lines if "SeAuditPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if generate_security_audits_line:
            value = generate_security_audits_line.split('=')[1].strip()

            if value == "LOCAL SERVICE, NETWORK SERVICE":
                print(f"{GREEN}2.2.23 Generate security audits: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.23 Generate security audits: Non conforme (Valeur Relevée: {value} - doit être 'LOCAL SERVICE, NETWORK SERVICE'){RESET}")
        else:
            print(f"{RED}2.2.23 Generate security audits: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.23 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.24 : Vérifier la politique "Impersonate a client after authentication"
def check_impersonate_client_after_authentication():
    """
    Vérifie si la politique 'Impersonate a client after authentication' est configurée à 
    'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' ou 'Administrateurs, SERVICE LOCAL, SERVICE RÉSEAU, SERVICE' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeImpersonatePrivilege' (c'est la politique correspondante)
        impersonate_client_line = next((line for line in lines if "SeImpersonatePrivilege" in line), None)

        # Vérifier et afficher la configuration
        if impersonate_client_line:
            value = impersonate_client_line.split('=')[1].strip()
            expected_value = "Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE"

            # Vérification en anglais et en français
            if value == expected_value or value == "Administrateurs, SERVICE LOCAL, SERVICE RÉSEAU, SERVICE":
                print(f"{GREEN}2.2.24 Impersonate a client after authentication: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.24 Impersonate a client after authentication: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}' ou 'Administrateurs, SERVICE LOCAL, SERVICE RÉSEAU, SERVICE'){RESET}")
        else:
            print(f"{RED}2.2.24 Impersonate a client after authentication: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.24 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.25 : Vérifier la politique "Increase scheduling priority"
def check_increase_scheduling_priority():
    r"""
    Vérifie si la politique 'Increase scheduling priority' est configurée à 
    'Administrators, Window Manager\Window Manager Group' ou 'Administrateurs, Gestionnaire de fenêtres\Groupe du gestionnaire de fenêtres' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeIncreaseSchedulingPriorityPrivilege' (c'est la politique correspondante)
        increase_scheduling_priority_line = next((line for line in lines if "SeIncreaseSchedulingPriorityPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if increase_scheduling_priority_line:
            value = increase_scheduling_priority_line.split('=')[1].strip()
            expected_value = "Administrators, Window Manager\\Window Manager Group"

            # Vérification en anglais et en français
            if value == expected_value or value == "Administrateurs, Gestionnaire de fenêtres\\Groupe du gestionnaire de fenêtres":
                print(f"{GREEN}2.2.25 Increase scheduling priority: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.25 Increase scheduling priority: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}' ou 'Administrateurs, Gestionnaire de fenêtres\\Groupe du gestionnaire de fenêtres'){RESET}")
        else:
            print(f"{RED}2.2.25 Increase scheduling priority: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.25 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.26 : Vérifier la politique "Load and unload device drivers"
def check_load_and_unload_device_drivers():
    """
    Vérifie si la politique 'Load and unload device drivers' est configurée à 
    'Administrators' ou 'Administrateurs' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeLoadDriverPrivilege' (c'est la politique correspondante)
        load_and_unload_device_drivers_line = next((line for line in lines if "SeLoadDriverPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if load_and_unload_device_drivers_line:
            value = load_and_unload_device_drivers_line.split('=')[1].strip()
            expected_value = "Administrators"

            # Vérification en anglais et en français
            if value == expected_value or value == "Administrateurs":
                print(f"{GREEN}2.2.26 Load and unload device drivers: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.26 Load and unload device drivers: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}' ou 'Administrateurs'){RESET}")
        else:
            print(f"{RED}2.2.26 Load and unload device drivers: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.26 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.27 : Vérifier la politique "Lock pages in memory"
def check_lock_pages_in_memory():
    r"""
    Vérifie si la politique 'Lock pages in memory' est configurée à 
    'No One'.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeLockMemoryPrivilege' (c'est la politique correspondante)
        lock_pages_in_memory_line = next((line for line in lines if "SeLockMemoryPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if lock_pages_in_memory_line:
            value = lock_pages_in_memory_line.split('=')[1].strip()
            expected_value = "No One"

            if value == expected_value:
                print(f"{GREEN}2.2.27 Lock pages in memory: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.27 Lock pages in memory: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}'){RESET}")
        else:
            print(f"{RED}2.2.27 Lock pages in memory: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.27 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.28 : Vérifier la politique "Log on as a batch job"
def check_log_on_as_batch_job():
    r"""
    Vérifie si la politique 'Log on as a batch job' est configurée à 
    'Administrators' ou 'Administrateurs' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeBatchLogonRight' (c'est la politique correspondante)
        log_on_as_batch_job_line = next((line for line in lines if "SeBatchLogonRight" in line), None)

        # Vérifier et afficher la configuration
        if log_on_as_batch_job_line:
            value = log_on_as_batch_job_line.split('=')[1].strip()
            expected_value = "Administrators"

            # Vérification en anglais et en français
            if value == expected_value or value == "Administrateurs":
                print(f"{GREEN}2.2.28 Log on as a batch job: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.28 Log on as a batch job: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}' ou 'Administrateurs'){RESET}")
        else:
            print(f"{RED}2.2.28 Log on as a batch job: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.28 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.29 : Vérifier la politique "Log on as a service"
def check_log_on_as_a_service():
    r"""
    Vérifie si la politique 'Log on as a service' est configurée à 
    'No One', ou (si Hyper-V est installé) 'NT VIRTUAL MACHINE\Virtual Machines' 
    ou (si Windows Defender Application Guard est utilisé) 'WDAGUtilityAccount'.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeServiceLogonRight' (c'est la politique correspondante)
        log_on_as_service_line = next((line for line in lines if "SeServiceLogonRight" in line), None)

        # Vérifier et afficher la configuration
        if log_on_as_service_line:
            value = log_on_as_service_line.split('=')[1].strip()
            expected_value = "No One"

            # Si Hyper-V est installé, on ajoute la condition NT VIRTUAL MACHINE\Virtual Machines
            if "NT VIRTUAL MACHINE\\Virtual Machines" in value or "WDAGUtilityAccount" in value:
                expected_value = "NT VIRTUAL MACHINE\\Virtual Machines"  # ou WDAGUtilityAccount selon la configuration

            if value == expected_value:
                print(f"{GREEN}2.2.29 Log on as a service: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.29 Log on as a service: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}'){RESET}")
        else:
            print(f"{RED}2.2.29 Log on as a service: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.29 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.30 : Vérifier la politique "Manage auditing and security log"
def check_manage_auditing_and_security_log():
    r"""
    Vérifie si la politique 'Manage auditing and security log' est configurée à 
    'Administrators' ou 'Administrateurs' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeSecurityPrivilege' (c'est la politique correspondante)
        manage_auditing_and_security_log_line = next((line for line in lines if "SeSecurityPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if manage_auditing_and_security_log_line:
            value = manage_auditing_and_security_log_line.split('=')[1].strip()
            expected_value = "Administrators"

            # Vérification en anglais et en français
            if value == expected_value or value == "Administrateurs":
                print(f"{GREEN}2.2.30 Manage auditing and security log: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.30 Manage auditing and security log: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}' ou 'Administrateurs'){RESET}")
        else:
            print(f"{RED}2.2.30 Manage auditing and security log: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.30 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.31 : Vérifier la politique "Modify an object label"
def check_modify_object_label():
    r"""
    Vérifie si la politique 'Modify an object label' est configurée à 
    'No One'.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeSystemtimePrivilege' (c'est la politique correspondante)
        modify_object_label_line = next((line for line in lines if "SeSystemtimePrivilege" in line), None)

        # Vérifier et afficher la configuration
        if modify_object_label_line:
            value = modify_object_label_line.split('=')[1].strip()
            expected_value = "No One"

            if value == expected_value:
                print(f"{GREEN}2.2.31 Modify an object label: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.31 Modify an object label: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}'){RESET}")
        else:
            print(f"{RED}2.2.31 Modify an object label: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.31 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.32 : Vérifier la politique "Modify firmware environment values"
def check_modify_firmware_environment_values():
    r"""
    Vérifie si la politique 'Modify firmware environment values' est configurée à 
    'Administrators' ou 'Administrateurs' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeSystemtimePrivilege' (c'est la politique correspondante)
        modify_firmware_environment_values_line = next((line for line in lines if "SeSystemtimePrivilege" in line), None)

        # Vérifier et afficher la configuration
        if modify_firmware_environment_values_line:
            value = modify_firmware_environment_values_line.split('=')[1].strip()
            expected_value = "Administrators"

            # Vérification en anglais et en français
            if value == expected_value or value == "Administrateurs":
                print(f"{GREEN}2.2.32 Modify firmware environment values: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.32 Modify firmware environment values: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}' ou 'Administrateurs'){RESET}")
        else:
            print(f"{RED}2.2.32 Modify firmware environment values: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.32 : {e}{RESET}")

@compliance_check
def check_perform_volume_maintenance_tasks():
    r"""
    Vérifie si la politique 'Perform volume maintenance tasks' est configurée à 
    'Administrators' ou 'Administrateurs' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeManageVolumePrivilege' (c'est la politique correspondante)
        perform_volume_maintenance_tasks_line = next((line for line in lines if "SeManageVolumePrivilege" in line), None)

        # Vérifier et afficher la configuration
        if perform_volume_maintenance_tasks_line:
            value = perform_volume_maintenance_tasks_line.split('=')[1].strip()
            expected_value = "Administrators"

            # Vérification en anglais et en français
            if value == expected_value or value == "Administrateurs":
                print(f"{GREEN}2.2.33 Perform volume maintenance tasks: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.33 Perform volume maintenance tasks: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}' ou 'Administrateurs'){RESET}")
        else:
            print(f"{RED}2.2.33 Perform volume maintenance tasks: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.33 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.34 : Vérifier la politique "Profile single process"
def check_profile_single_process():
    r"""
    Vérifie si la politique 'Profile single process' est configurée à 
    'Administrators' ou 'Administrateurs' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeProfileSingleProcessPrivilege' (c'est la politique correspondante)
        profile_single_process_line = next((line for line in lines if "SeProfileSingleProcessPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if profile_single_process_line:
            value = profile_single_process_line.split('=')[1].strip()
            expected_value = "Administrators"

            # Vérification en anglais et en français
            if value == expected_value or value == "Administrateurs":
                print(f"{GREEN}2.2.34 Profile single process: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.34 Profile single process: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}' ou 'Administrateurs'){RESET}")
        else:
            print(f"{RED}2.2.34 Profile single process: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.34 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.35 : Vérifier la politique "Profile system performance"
def check_profile_system_performance():
    r"""
    Vérifie si la politique 'Profile system performance' est configurée à 
    'Administrators, NT SERVICE\WdiServiceHost' ou 'Administrateurs, NT SERVICE\WdiServiceHost' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeProfileSystemPerformancePrivilege' (c'est la politique correspondante)
        profile_system_performance_line = next((line for line in lines if "SeProfileSystemPerformancePrivilege" in line), None)

        # Vérifier et afficher la configuration
        if profile_system_performance_line:
            value = profile_system_performance_line.split('=')[1].strip()
            expected_value = "Administrators, NT SERVICE\\WdiServiceHost"

            # Vérification en anglais et en français
            if value == expected_value or value == "Administrateurs, NT SERVICE\\WdiServiceHost":
                print(f"{GREEN}2.2.35 Profile system performance: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.35 Profile system performance: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}' ou 'Administrateurs, NT SERVICE\\WdiServiceHost'){RESET}")
        else:
            print(f"{RED}2.2.35 Profile system performance: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.35 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.36 : Vérifier la politique "Replace a process level token"
def check_replace_process_level_token():
    r"""
    Vérifie si la politique 'Replace a process level token' est configurée à 
    'LOCAL SERVICE, NETWORK SERVICE'.
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeReplaceProcessLevelTokenPrivilege' (c'est la politique correspondante)
        replace_process_level_token_line = next((line for line in lines if "SeReplaceProcessLevelTokenPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if replace_process_level_token_line:
            value = replace_process_level_token_line.split('=')[1].strip()
            expected_value = "LOCAL SERVICE, NETWORK SERVICE"

            if value == expected_value:
                print(f"{GREEN}2.2.36 Replace a process level token: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.36 Replace a process level token: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}'){RESET}")
        else:
            print(f"{RED}2.2.36 Replace a process level token: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.36 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.37 : Vérifier la politique "Restore files and directories"
def check_restore_files_and_directories():
    r"""
    Vérifie si la politique 'Restore files and directories' est configurée à 
    'Administrators' ou 'Administrateurs' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeRestorePrivilege' (c'est la politique correspondante)
        restore_files_and_directories_line = next((line for line in lines if "SeRestorePrivilege" in line), None)

        # Vérifier et afficher la configuration
        if restore_files_and_directories_line:
            value = restore_files_and_directories_line.split('=')[1].strip()
            expected_value = "Administrators"

            # Vérification en anglais et en français
            if value == expected_value or value == "Administrateurs":
                print(f"{GREEN}2.2.37 Restore files and directories: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.37 Restore files and directories: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}' ou 'Administrateurs'){RESET}")
        else:
            print(f"{RED}2.2.37 Restore files and directories: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.37 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.38 : Vérifier la politique "Shut down the system"
def check_shut_down_the_system():
    r"""
    Vérifie si la politique 'Shut down the system' est configurée à 
    'Administrators, Users' ou 'Administrateurs, Utilisateurs' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeShutdownPrivilege' (c'est la politique correspondante)
        shut_down_the_system_line = next((line for line in lines if "SeShutdownPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if shut_down_the_system_line:
            value = shut_down_the_system_line.split('=')[1].strip()
            expected_value = "Administrators, Users"

            # Vérification en anglais et en français
            if value == expected_value or value == "Administrateurs, Utilisateurs":
                print(f"{GREEN}2.2.38 Shut down the system: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.38 Shut down the system: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}' ou 'Administrateurs, Utilisateurs'){RESET}")
        else:
            print(f"{RED}2.2.38 Shut down the system: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.38 : {e}{RESET}")

@compliance_check
# Contrôle 2.2.39 : Vérifier la politique "Take ownership of files or other objects"
def check_take_ownership_of_files_or_other_objects():
    r"""
    Vérifie si la politique 'Take ownership of files or other objects' est configurée à 
    'Administrators' ou 'Administrateurs' (en français).
    """
    try:
        # Exporter la configuration des politiques de sécurité dans un fichier temporaire
        temp_path = os.getenv('TEMP')
        export_file = os.path.join(temp_path, "SecurityPolicy.inf")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_file],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True
        )

        # Lire le fichier exporté avec encodage UTF-16
        if not os.path.exists(export_file):
            print(f"{RED}Erreur : Impossible d'exporter les paramètres de sécurité.{RESET}")
            return

        with open(export_file, "r", encoding="utf-16") as f:
            lines = f.readlines()

        # Rechercher la ligne contenant 'SeTakeOwnershipPrivilege' (c'est la politique correspondante)
        take_ownership_line = next((line for line in lines if "SeTakeOwnershipPrivilege" in line), None)

        # Vérifier et afficher la configuration
        if take_ownership_line:
            value = take_ownership_line.split('=')[1].strip()
            expected_value = "Administrators"

            # Vérification en anglais et en français
            if value == expected_value or value == "Administrateurs":
                print(f"{GREEN}2.2.39 Take ownership of files or other objects: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}2.2.39 Take ownership of files or other objects: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}' ou 'Administrateurs'){RESET}")
        else:
            print(f"{RED}2.2.39 Take ownership of files or other objects: Non conforme (Valeur Relevée: Introuvable){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.2.39 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.1.1 : Vérifier la politique "Accounts: Block Microsoft accounts"
def check_block_microsoft_accounts():
    r"""
    Vérifie si la politique 'Accounts: Block Microsoft accounts' est configurée à 
    'Users can't add or log on with Microsoft accounts'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "NoConnectedUser"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.1.1 : La valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier la valeur
        expected_value = 3  # "Users can't add or log on with Microsoft accounts"
        if value == expected_value:
            print(f"{GREEN}2.3.1.1 Accounts: Block Microsoft accounts: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.1.1 Accounts: Block Microsoft accounts: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.1.1 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.1.2 : Vérifier la politique "Accounts: Guest account status"
def check_guest_account_status():
    r"""
    Vérifie si la politique 'Accounts: Guest account status' est configurée à 
    'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "AccountsGuest"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.1.2 : La valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier la valeur
        expected_value = 0  # Disabled
        if value == expected_value:
            print(f"{GREEN}2.3.1.2 Accounts: Guest account status: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.1.2 Accounts: Guest account status: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.1.2 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.1.3 : Vérifier la politique "Limit local account use of blank passwords to console logon only"
def check_limit_blank_password_use():
    r"""
    Vérifie si la politique 'Limit local account use of blank passwords to console logon only' est configurée à 
    'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        registry_value = "LimitBlankPasswordUse"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.1.3 : La valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier la valeur
        expected_value = 1  # "Enabled"
        if value == expected_value:
            print(f"{GREEN}2.3.1.3 Accounts: Limit local account use of blank passwords to console logon only: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.1.3 Accounts: Limit local account use of blank passwords to console logon only: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.1.3 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.1.4 : Vérifier la politique "Rename administrator account"
def check_rename_administrator_account():
    r"""
    Vérifie si la politique 'Rename administrator account' est configurée avec un nom personnalisé autre que 'Administrator' ou 'Administrateur' (en français).
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "LegalNoticeCaption"  # Le nom de l'administrateur modifié est lié à cette clé

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.1.4 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si le nom de l'administrateur est celui par défaut (Administrator ou Administrateur)
        default_values = ["Administrator", "Administrateur"]  # Valeurs par défaut
        if value in default_values:
            print(f"{RED}2.3.1.4 Accounts: Rename administrator account: Non conforme (Valeur Relevée: {value} - doit être personnalisé){RESET}")
        else:
            print(f"{GREEN}2.3.1.4 Accounts: Rename administrator account: Conforme (Valeur Relevée: {value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.1.4 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.1.5 : Vérifier la politique "Rename guest account"
def check_rename_guest_account():
    r"""
    Vérifie si la politique 'Rename guest account' est configurée avec un nom personnalisé autre que 'Guest'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "AccountsGuest"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.1.5 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si le nom de l'invité est celui par défaut (Guest)
        default_value = "Guest"  # Valeur par défaut
        if value == default_value:
            print(f"{RED}2.3.1.5 Accounts: Rename guest account: Non conforme (Valeur Relevée: {value} - doit être personnalisé){RESET}")
        else:
            print(f"{GREEN}2.3.1.5 Accounts: Rename guest account: Conforme (Valeur Relevée: {value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.1.5 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.2.1 : Vérifier la politique "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings"
def check_force_audit_policy_subcategory():
    r"""
    Vérifie si la politique 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings'
    est configurée à 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        registry_value = "SCENoApplyLegacyAuditPolicy"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.2.1 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est définie à 1 (Enabled)
        expected_value = 1  # Enabled
        if value == expected_value:
            print(f"{GREEN}2.3.2.1 Audit: Force audit policy subcategory settings: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.2.1 Audit: Force audit policy subcategory settings: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.2.1 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.2.2 : Vérifier la politique "Audit: Shut down system immediately if unable to log security audits"
def check_shut_down_system_if_unable_to_log_audits():
    r"""
    Vérifie si la politique 'Audit: Shut down system immediately if unable to log security audits'
    est configurée à 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        registry_value = "CrashOnAuditFail"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.2.2 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est définie à 0 (Disabled)
        expected_value = 0  # Disabled
        if value == expected_value:
            print(f"{GREEN}2.3.2.2 Audit: Shut down system immediately if unable to log security audits: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.2.2 Audit: Shut down system immediately if unable to log security audits: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.2.2 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.4.1 : Vérifier la politique "Devices: Prevent users from installing printer drivers"
def check_prevent_users_from_installing_printer_drivers():
    r"""
    Vérifie si la politique 'Devices: Prevent users from installing printer drivers'
    est configurée à 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
        registry_value = "AddPrinterDrivers"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.4.1 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est définie à 1 (Enabled)
        expected_value = 1  # Enabled
        if value == expected_value:
            print(f"{GREEN}2.3.4.1 Devices: Prevent users from installing printer drivers: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.4.1 Devices: Prevent users from installing printer drivers: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.4.1 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.7.1 : Vérifier la politique "Interactive logon: Do not require CTRL+ALT+DEL"
def check_disable_ctrl_alt_del():
    r"""
    Vérifie si la politique 'Interactive logon: Do not require CTRL+ALT+DEL'
    est configurée à 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "DisableCAD"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.7.1 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier la valeur
        expected_value = 0  # Disabled
        if value == expected_value:
            print(f"{GREEN}2.3.7.1 Interactive logon: Do not require CTRL+ALT+DEL: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.7.1 Interactive logon: Do not require CTRL+ALT+DEL: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.7.1 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.7.2 : Vérifier la politique "Interactive logon: Don't display last signed-in"
def check_dont_display_last_user_name():
    r"""
    Vérifie si la politique 'Interactive logon: Don't display last signed-in'
    est configurée à 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "DontDisplayLastUserName"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.7.2 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier la valeur
        expected_value = 1  # Enabled
        if value == expected_value:
            print(f"{GREEN}2.3.7.2 Interactive logon: Don't display last signed-in: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.7.2 Interactive logon: Don't display last signed-in: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.7.2 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.7.3 : Vérifier la politique "Interactive logon: Machine account lockout threshold"
def check_machine_account_lockout_threshold():
    r"""
    Vérifie si la politique 'Interactive logon: Machine account lockout threshold'
    est configurée à '10 ou moins tentatives de connexion invalides, mais pas 0'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "MaxDevicePasswordFailedAttempts"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.7.3 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier la valeur
        if value == 0:
            print(f"{RED}2.3.7.3 Interactive logon: Machine account lockout threshold: Non conforme (Valeur Relevée: {value} - doit être supérieur à 0){RESET}")
        elif value <= 10:
            print(f"{GREEN}2.3.7.3 Interactive logon: Machine account lockout threshold: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.7.3 Interactive logon: Machine account lockout threshold: Non conforme (Valeur Relevée: {value} - doit être inférieur ou égal à 10){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.7.3 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.7.4 : Vérifier la politique "Interactive logon: Machine inactivity limit"
def check_machine_inactivity_limit():
    r"""
    Vérifie si la politique 'Interactive logon: Machine inactivity limit'
    est configurée à '900 ou moins secondes, mais pas 0'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "InactivityTimeoutSecs"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.7.4 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier la valeur
        if value == 0:
            print(f"{RED}2.3.7.4 Interactive logon: Machine inactivity limit: Non conforme (Valeur Relevée: {value} - doit être supérieur à 0){RESET}")
        elif value <= 900:
            print(f"{GREEN}2.3.7.4 Interactive logon: Machine inactivity limit: Conforme (Valeur Relevée: {value} secondes){RESET}")
        else:
            print(f"{RED}2.3.7.4 Interactive logon: Machine inactivity limit: Non conforme (Valeur Relevée: {value} - doit être inférieur ou égal à 900 secondes){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.7.4 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.7.5 : Vérifier la politique "Interactive logon: Message text for users attempting to log on"
def check_message_text_for_users():
    r"""
    Vérifie si la politique 'Interactive logon: Message text for users attempting to log on'
    est configurée à une valeur qui est conforme aux exigences de sécurité et opérationnelles.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "LegalNoticeText"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.7.5 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier la valeur
        if not value:
            print(f"{RED}2.3.7.5 Interactive logon: Message text for users attempting to log on: Non conforme (Valeur Relevée: Aucune message){RESET}")
        else:
            print(f"{GREEN}2.3.7.5 Interactive logon: Message text for users attempting to log on: Conforme (Valeur Relevée: {value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.7.5 : {e}{RESET}")
        
@compliance_check
# Contrôle 2.3.7.6 : Vérifier la politique "Interactive logon: Message title for users attempting to log on"
def check_message_title_for_users():
    r"""
    Vérifie si la politique 'Interactive logon: Message title for users attempting to log on'
    est configurée à une valeur qui est conforme aux exigences de sécurité et opérationnelles.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "LegalNoticeCaption"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.7.6 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier la valeur
        if not value:
            print(f"{RED}2.3.7.6 Interactive logon: Message title for users attempting to log on: Non conforme (Valeur Relevée: Aucune valeur){RESET}")
        else:
            print(f"{GREEN}2.3.7.6 Interactive logon: Message title for users attempting to log on: Conforme (Valeur Relevée: {value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.7.6 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.7.7 : Vérifier la politique "Interactive logon: Prompt user to change password before expiration"
def check_prompt_user_to_change_password():
    r"""
    Vérifie si la politique 'Interactive logon: Prompt user to change password before expiration'
    est configurée à une valeur entre 5 et 14 jours.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        registry_value = "PasswordExpiryWarning"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.7.7 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est dans la plage recommandée
        if 5 <= value <= 14:
            print(f"{GREEN}2.3.7.7 Interactive logon: Prompt user to change password before expiration: Conforme (Valeur Relevée: {value} jours){RESET}")
        else:
            print(f"{RED}2.3.7.7 Interactive logon: Prompt user to change password before expiration: Non conforme (Valeur Relevée: {value} jours - doit être entre 5 et 14 jours){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.7.7 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.7.8 : Vérifier la politique "Interactive logon: Smart card removal behavior"
def check_smart_card_removal_behavior():
    r"""
    Vérifie si la politique 'Interactive logon: Smart card removal behavior' est configurée à 
    'Lock Workstation' ou à une valeur équivalente.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        registry_value = "ScRemoveOption"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.7.8 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est parmi les valeurs attendues
        if value in [1, 2, 3]:  # 1: Lock Workstation, 2: Force Logoff, 3: Disconnect (Remote Desktop)
            print(f"{GREEN}2.3.7.8 Interactive logon: Smart card removal behavior: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.7.8 Interactive logon: Smart card removal behavior: Non conforme (Valeur Relevée: {value} - doit être 1, 2 ou 3){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.7.8 : {e}{RESET}")
        
@compliance_check
# Contrôle 2.3.8.1 : Vérifier la politique "Microsoft network client: Digitally sign communications (always)"
def check_microsoft_network_client_signing():
    r"""
    Vérifie si la politique 'Microsoft network client: Digitally sign communications (always)' 
    est configurée à 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        registry_value = "RequireSecuritySignature"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.8.1 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est définie à 1 (Enabled)
        if value == 1:
            print(f"{GREEN}2.3.8.1 Microsoft network client: Digitally sign communications (always): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.8.1 Microsoft network client: Digitally sign communications (always): Non conforme (Valeur Relevée: {value} - doit être 1){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.8.1 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.8.2 : Vérifier la politique "Microsoft network client: Digitally sign communications (if server agrees)"
def check_microsoft_network_client_signing_if_server_agrees():
    r"""
    Vérifie si la politique 'Microsoft network client: Digitally sign communications (if server agrees)' 
    est configurée à 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        registry_value = "EnableSecuritySignature"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.8.2 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est définie à 1 (Enabled)
        if value == 1:
            print(f"{GREEN}2.3.8.2 Microsoft network client: Digitally sign communications (if server agrees): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.8.2 Microsoft network client: Digitally sign communications (if server agrees): Non conforme (Valeur Relevée: {value} - doit être 1){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.8.2 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.8.3 : Vérifier la politique "Microsoft network client: Send unencrypted password to third-party SMB servers"
def check_microsoft_network_client_send_unencrypted_password():
    r"""
    Vérifie si la politique 'Microsoft network client: Send unencrypted password to third-party SMB servers' 
    est configurée à 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        registry_value = "EnablePlainTextPassword"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.8.3 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est définie à 0 (Disabled)
        if value == 0:
            print(f"{GREEN}2.3.8.3 Microsoft network client: Send unencrypted password to third-party SMB servers: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.8.3 Microsoft network client: Send unencrypted password to third-party SMB servers: Non conforme (Valeur Relevée: {value} - doit être 0){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.8.3 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.9.1 : Vérifier la politique "Microsoft network server: Amount of idle time required before suspending session"
def check_microsoft_network_server_idle_time():
    r"""
    Vérifie si la politique 'Microsoft network server: Amount of idle time required before suspending session'
    est configurée à '15 ou moins minutes'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        registry_value = "AutoDisconnect"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.9.1 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est inférieure ou égale à 15 (minutes)
        if value <= 15:
            print(f"{GREEN}2.3.9.1 Microsoft network server: Amount of idle time required before suspending session: Conforme (Valeur Relevée: {value} minutes){RESET}")
        else:
            print(f"{RED}2.3.9.1 Microsoft network server: Amount of idle time required before suspending session: Non conforme (Valeur Relevée: {value} minutes - doit être 15 ou moins){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.9.1 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.9.2 : Vérifier la politique "Microsoft network server: Digitally sign communications (always)"
def check_microsoft_network_server_signing():
    r"""
    Vérifie si la politique 'Microsoft network server: Digitally sign communications (always)'
    est configurée à 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        registry_value = "RequireSecuritySignature"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.9.2 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est configurée à 1 (Enabled)
        if value == 1:
            print(f"{GREEN}2.3.9.2 Microsoft network server: Digitally sign communications (always): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.9.2 Microsoft network server: Digitally sign communications (always): Non conforme (Valeur Relevée: {value} - doit être 1){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.9.2 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.9.3 : Vérifier la politique "Microsoft network server: Digitally sign communications (if client agrees)"
def check_microsoft_network_server_signing_if_client_agrees():
    r"""
    Vérifie si la politique 'Microsoft network server: Digitally sign communications (if client agrees)'
    est configurée à 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        registry_value = "EnableSecuritySignature"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.9.3 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est configurée à 1 (Enabled)
        if value == 1:
            print(f"{GREEN}2.3.9.3 Microsoft network server: Digitally sign communications (if client agrees): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.9.3 Microsoft network server: Digitally sign communications (if client agrees): Non conforme (Valeur Relevée: {value} - doit être 1){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.9.3 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.9.4 : Vérifier la politique "Microsoft network server: Disconnect clients when logon hours expire"
def check_microsoft_network_server_disconnect_clients():
    r"""
    Vérifie si la politique 'Microsoft network server: Disconnect clients when logon hours expire'
    est configurée à 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        registry_value = "enableforcedlogoff"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.9.4 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est configurée à 1 (Enabled)
        if value == 1:
            print(f"{GREEN}2.3.9.4 Microsoft network server: Disconnect clients when logon hours expire: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.9.4 Microsoft network server: Disconnect clients when logon hours expire: Non conforme (Valeur Relevée: {value} - doit être 1){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.9.4 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.9.5 : Vérifier la politique "Microsoft network server: Server SPN target name validation level"
def check_smb_server_spn_validation():
    r"""
    Vérifie si la politique 'Microsoft network server: Server SPN target name validation level'
    est configurée à 'Accept if provided by client' ou plus.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        registry_value = "SMBServerNameHardeningLevel"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.9.5 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est configurée à 1 ou plus (Accept if provided by client)
        if value >= 1:
            print(f"{GREEN}2.3.9.5 Microsoft network server: Server SPN target name validation level: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.9.5 Microsoft network server: Server SPN target name validation level: Non conforme (Valeur Relevée: {value} - doit être 1 ou plus){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.9.5 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.10.1 : Vérifier la politique "Network access: Allow anonymous SID/Name translation"
def check_anonymous_sid_name_translation():
    r"""
    Vérifie si la politique 'Network access: Allow anonymous SID/Name translation'
    est configurée à 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        registry_value = "AllowAnonymousSIDNameTranslation"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.10.1 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est configurée à 0 (Disabled)
        if value == 0:
            print(f"{GREEN}2.3.10.1 Network access: Allow anonymous SID/Name translation: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.10.1 Network access: Allow anonymous SID/Name translation: Non conforme (Valeur Relevée: {value} - doit être 0){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.10.1 : {e}{RESET}")
        
@compliance_check
 # Contrôle 2.3.10.2 : Vérifier la politique "Network access: Do not allow anonymous enumeration of SAM accounts"
def check_anonymous_enum_sam_accounts():
    r"""
    Vérifie si la politique 'Network access: Do not allow anonymous enumeration of SAM accounts'
    est configurée à 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        registry_value = "RestrictAnonymousSAM"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.10.2 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est configurée à 1 (Enabled)
        if value == 1:
            print(f"{GREEN}2.3.10.2 Network access: Do not allow anonymous enumeration of SAM accounts: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.10.2 Network access: Do not allow anonymous enumeration of SAM accounts: Non conforme (Valeur Relevée: {value} - doit être 1){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.10.2 : {e}{RESET}")       
        
@compliance_check
# Contrôle 2.3.10.3 : Vérifier la politique "Network access: Do not allow anonymous enumeration of SAM accounts and shares"
def check_anonymous_enum_sam_and_shares():
    r"""
    Vérifie si la politique 'Network access: Do not allow anonymous enumeration of SAM accounts and shares'
    est configurée à 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        registry_value = "RestrictAnonymous"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.10.3 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est configurée à 1 (Enabled)
        if value == 1:
            print(f"{GREEN}2.3.10.3 Network access: Do not allow anonymous enumeration of SAM accounts and shares: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.10.3 Network access: Do not allow anonymous enumeration of SAM accounts and shares: Non conforme (Valeur Relevée: {value} - doit être 1){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.10.3 : {e}{RESET}")     

@compliance_check
  # Contrôle 2.3.10.4 : Vérifier la politique "Network access: Do not allow storage of passwords and credentials for network authentication"
def check_no_storage_of_credentials():
    r"""
    Vérifie si la politique 'Network access: Do not allow storage of passwords and credentials for network authentication'
    est configurée à 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        registry_value = "DisableDomainCreds"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.10.4 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est configurée à 1 (Enabled)
        if value == 1:
            print(f"{GREEN}2.3.10.4 Network access: Do not allow storage of passwords and credentials for network authentication: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.10.4 Network access: Do not allow storage of passwords and credentials for network authentication: Non conforme (Valeur Relevée: {value} - doit être 1){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.10.4 : {e}{RESET}")      

@compliance_check
# Contrôle 2.3.10.5 : Vérifier la politique "Network access: Let Everyone permissions apply to anonymous users"
def check_let_everyone_permissions_apply():
    r"""
    Vérifie si la politique 'Network access: Let Everyone permissions apply to anonymous users'
    est configurée à 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        registry_value = "EveryoneIncludesAnonymous"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.10.5 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est configurée à 0 (Disabled)
        if value == 0:
            print(f"{GREEN}2.3.10.5 Network access: Let Everyone permissions apply to anonymous users: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.10.5 Network access: Let Everyone permissions apply to anonymous users: Non conforme (Valeur Relevée: {value} - doit être 0){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.10.5 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.10.6 : Vérifier la politique "Network access: Named Pipes that can be accessed anonymously"
def check_named_pipes_access():
    r"""
    Vérifie si la politique 'Network access: Named Pipes that can be accessed anonymously'
    est configurée à 'None' (valeur vide).
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        registry_value = "NullSessionPipes"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.10.6 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est vide (None)
        if not value:
            print(f"{GREEN}2.3.10.6 Network access: Named Pipes that can be accessed anonymously: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.10.6 Network access: Named Pipes that can be accessed anonymously: Non conforme (Valeur Relevée: {value} - doit être vide){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.10.6 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.10.7 : Vérifier la politique "Network access: Remotely accessible registry paths"
def check_remotely_accessible_registry_paths():
    r"""
    Vérifie si la politique 'Network access: Remotely accessible registry paths' 
    est configurée avec les chemins de registre appropriés.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg"
        registry_value = "AllowedExactPaths"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.10.7 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier les chemins de registre autorisés
        expected_values = [
            "System\\CurrentControlSet\\Control\\ProductOptions",
            "System\\CurrentControlSet\\Control\\Server Applications",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        ]
        
        # Vérifier si les chemins attendus sont dans les valeurs trouvées
        missing_paths = [path for path in expected_values if path not in value]

        if missing_paths:
            print(f"{RED}2.3.10.7 Network access: Remotely accessible registry paths: Non conforme (Valeur Relevée: {value} - manque les chemins suivants : {', '.join(missing_paths)}){RESET}")
        else:
            print(f"{GREEN}2.3.10.7 Network access: Remotely accessible registry paths: Conforme (Valeur Relevée: {value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.10.7 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.10.8 : Vérifier la politique "Network access: Remotely accessible registry paths and sub-paths"
def check_remotely_accessible_registry_paths_and_sub_paths():
    r"""
    Vérifie si la politique 'Network access: Remotely accessible registry paths and sub-paths' 
    est configurée avec les chemins de registre et sous-chemins appropriés.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg"
        registry_value = "AllowedPaths"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.10.8 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier les chemins de registre et sous-chemins attendus
        expected_values = [
            "System\\CurrentControlSet\\Control\\Print\\Printers",
            "System\\CurrentControlSet\\Services\\Eventlog",
            "Software\\Microsoft\\OLAP Server",
            "Software\\Microsoft\\Windows NT\\CurrentVersion\\Print",
            "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
            "System\\CurrentControlSet\\Control\\ContentIndex",
            "System\\CurrentControlSet\\Control\\Terminal Server",
            "System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig",
            "System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration",
            "Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib",
            "System\\CurrentControlSet\\Services\\SysmonLog"
        ]

        # Vérifier si les chemins attendus sont dans les valeurs trouvées
        missing_paths = [path for path in expected_values if path not in value]

        if missing_paths:
            print(f"{RED}2.3.10.8 Network access: Remotely accessible registry paths and sub-paths: Non conforme (Valeur Relevée: {value} - manque les chemins suivants : {', '.join(missing_paths)}){RESET}")
        else:
            print(f"{GREEN}2.3.10.8 Network access: Remotely accessible registry paths and sub-paths: Conforme (Valeur Relevée: {value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.10.8 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.10.9 : Vérifier la politique "Network access: Restrict anonymous access to Named Pipes and Shares"
def check_restrict_anonymous_access():
    r"""
    Vérifie si la politique 'Network access: Restrict anonymous access to Named Pipes and Shares' 
    est configurée à 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        registry_value = "RestrictNullSessAccess"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.10.9 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier la valeur
        expected_value = 1  # "Enabled" est représenté par la valeur 1
        if value == expected_value:
            print(f"{GREEN}2.3.10.9 Network access: Restrict anonymous access to Named Pipes and Shares: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.10.9 Network access: Restrict anonymous access to Named Pipes and Shares: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.10.9 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.10.10 : Vérifier la politique "Network access: Restrict clients allowed to make remote calls to SAM"
def check_restrict_clients_remote_sam():
    r"""
    Vérifie si la politique 'Network access: Restrict clients allowed to make remote calls to SAM' 
    est configurée à 'Administrators: Remote Access: Allow'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        registry_value = "restrictremotesam"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.10.10 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier la valeur
        expected_value = "O:BAG:BAD:(A;;RC;;;BA)"  # La valeur attendue est définie comme une chaîne spécifique
        if value == expected_value:
            print(f"{GREEN}2.3.10.10 Network access: Restrict clients allowed to make remote calls to SAM: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.10.10 Network access: Restrict clients allowed to make remote calls to SAM: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}'){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.10.10 : {e}{RESET}")  

@compliance_check
# Contrôle 2.3.10.11 : Vérifier la politique "Network access: Shares that can be accessed anonymously"
def check_shares_accessed_anonymously():
    r"""
    Vérifie si la politique 'Network access: Shares that can be accessed anonymously' 
    est configurée à 'None'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        registry_value = "NullSessionShares"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.10.11 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est vide
        if value == []:
            print(f"{GREEN}2.3.10.11 Network access: Shares that can be accessed anonymously: Conforme (Aucune valeur dans la clé){RESET}")
        else:
            print(f"{RED}2.3.10.11 Network access: Shares that can be accessed anonymously: Non conforme (Valeur Relevée: {value} - doit être vide){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.10.11 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.10.12 : Vérifier la politique "Network access: Sharing and security model for local accounts"
def check_sharing_security_model():
    r"""
    Vérifie si la politique 'Network access: Sharing and security model for local accounts' 
    est configurée à 'Classic - local users authenticate as themselves'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        registry_value = "ForceGuest"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.10.12 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est 0 (Classic - local users authenticate as themselves)
        expected_value = 0
        if value == expected_value:
            print(f"{GREEN}2.3.10.12 Network access: Sharing and security model for local accounts: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.10.12 Network access: Sharing and security model for local accounts: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.10.12 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.11.1 : Vérifier la politique "Network security: Allow Local System to use computer identity for NTLM"
def check_local_system_ntlm_identity():
    r"""
    Vérifie si la politique 'Network security: Allow Local System to use computer identity for NTLM' 
    est configurée à 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        registry_value = "UseMachineId"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.11.1 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est 1 (Enabled)
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}2.3.11.1 Network security: Allow Local System to use computer identity for NTLM: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.11.1 Network security: Allow Local System to use computer identity for NTLM: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.11.1 : {e}{RESET}")
        
@compliance_check
  # Contrôle 2.3.11.2 : Vérifier la politique "Network security: Allow LocalSystem NULL session fallback"
def check_local_system_null_session_fallback():
    r"""
    Vérifie si la politique 'Network security: Allow LocalSystem NULL session fallback' 
    est configurée à 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        registry_value = "AllowNullSessionFallback"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.11.2 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est 0 (Disabled)
        expected_value = 0
        if value == expected_value:
            print(f"{GREEN}2.3.11.2 Network security: Allow LocalSystem NULL session fallback: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.11.2 Network security: Allow LocalSystem NULL session fallback: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.11.2 : {e}{RESET}")      

@compliance_check
# Contrôle 2.3.11.3 : Vérifier la politique "Network Security: Allow PKU2U authentication requests to this computer to use online identities"
def check_allow_pku2u_online_identity():
    r"""
    Vérifie si la politique 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' 
    est configurée à 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"
        registry_value = "AllowOnlineID"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.11.3 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est 0 (Disabled)
        expected_value = 0
        if value == expected_value:
            print(f"{GREEN}2.3.11.3 Network Security: Allow PKU2U authentication requests to this computer to use online identities: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.11.3 Network Security: Allow PKU2U authentication requests to this computer to use online identities: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.11.3 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.11.4 : Vérifier la configuration des types de chiffrement autorisés pour Kerberos
def check_kerberos_encryption():
    r"""
    Vérifie si la politique 'Network security: Configure encryption types allowed for Kerberos'
    est configurée sur 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
        registry_value = "SupportedEncryptionTypes"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.11.4 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (2147483640 correspond à AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types)
        expected_value = 2147483640
        if value == expected_value:
            print(f"{GREEN}2.3.11.4 Kerberos Encryption: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.11.4 Kerberos Encryption: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.11.4 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.11.5 : Vérifier la politique "Do not store LAN Manager hash value on next password change"
def check_no_lan_manager_hash():
    r"""
    Vérifie si la politique 'Network security: Do not store LAN Manager hash value on next password change' 
    est configurée sur 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Control\Lsa"
        registry_value = "NoLMHash"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.11.5 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'Enabled')
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}2.3.11.5 Network security: Do not store LAN Manager hash value on next password change: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.11.5 Network security: Do not store LAN Manager hash value on next password change: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.11.5 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.11.6 : Vérifier la politique "Force logoff when logon hours expire"
def check_force_logoff_when_logon_hours_expire():
    r"""
    Vérifie si la politique 'Network security: Force logoff when logon hours expire' 
    est configurée sur 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Control\Lsa"
        registry_value = "ForceLogoffWhenLogonHoursExpire"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.11.6 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'Enabled')
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}2.3.11.6 Network security: Force logoff when logon hours expire: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.11.6 Network security: Force logoff when logon hours expire: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.11.6 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.11.7 : Vérifier la politique "LAN Manager authentication level"
def check_lan_manager_authentication_level():
    r"""
    Vérifie si la politique 'Network security: LAN Manager authentication level' 
    est configurée sur 'Send NTLMv2 response only. Refuse LM & NTLM'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Control\Lsa"
        registry_value = "LmCompatibilityLevel"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.11.7 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (5 signifie 'Send NTLMv2 response only. Refuse LM & NTLM')
        expected_value = 5
        if value == expected_value:
            print(f"{GREEN}2.3.11.7 Network security: LAN Manager authentication level: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.11.7 Network security: LAN Manager authentication level: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.11.7 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.11.8 : Vérifier la politique "LDAP client signing requirements"
def check_ldap_client_signing_requirements():
    r"""
    Vérifie si la politique 'Network security: LDAP client signing requirements' 
    est configurée sur 'Negotiate signing' ou plus élevé.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\LDAP"
        registry_value = "LDAPClientIntegrity"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.11.8 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'Negotiate signing')
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}2.3.11.8 Network security: LDAP client signing requirements: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.11.8 Network security: LDAP client signing requirements: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.11.8 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.11.9 : Vérifier la politique "Minimum session security for NTLM SSP based clients"
def check_ntlm_minimum_session_security():
    r"""
    Vérifie si la politique 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' 
    est configurée sur 'Require NTLMv2 session security, Require 128-bit encryption'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        registry_value = "NTLMMinClientSec"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.11.9 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (537395200 correspond à 'Require NTLMv2 session security, Require 128-bit encryption')
        expected_value = 537395200
        if value == expected_value:
            print(f"{GREEN}2.3.11.9 Network security: Minimum session security for NTLM SSP based (including secure RPC) clients: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.11.9 Network security: Minimum session security for NTLM SSP based (including secure RPC) clients: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.11.9 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.11.10 : Vérifier la politique "Minimum session security for NTLM SSP based servers"
def check_ntlm_minimum_session_security_servers():
    r"""
    Vérifie si la politique 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' 
    est configurée sur 'Require NTLMv2 session security, Require 128-bit encryption'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        registry_value = "NTLMMinServerSec"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.11.10 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (537395200 correspond à 'Require NTLMv2 session security, Require 128-bit encryption')
        expected_value = 537395200
        if value == expected_value:
            print(f"{GREEN}2.3.11.10 Network security: Minimum session security for NTLM SSP based (including secure RPC) servers: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.11.10 Network security: Minimum session security for NTLM SSP based (including secure RPC) servers: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.11.10 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.11.11 : Vérifier la politique "Restrict NTLM: Audit Incoming NTLM Traffic"
def check_restrict_ntlm_audit_incoming_traffic():
    r"""
    Vérifie si la politique 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' 
    est configurée sur 'Enable auditing for all accounts'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        registry_value = "AuditReceivingNTLMTraffic"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.11.11 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (2 signifie 'Enable auditing for all accounts')
        expected_value = 2
        if value == expected_value:
            print(f"{GREEN}2.3.11.11 Network security: Restrict NTLM: Audit Incoming NTLM Traffic: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.11.11 Network security: Restrict NTLM: Audit Incoming NTLM Traffic: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.11.11 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.11.12 : Vérifier la politique "Restrict NTLM: Outgoing NTLM traffic to remote servers"
def check_restrict_ntlm_outgoing_traffic():
    r"""
    Vérifie si la politique 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' 
    est configurée sur 'Audit all' ou plus élevé.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        registry_value = "RestrictSendingNTLMTraffic"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.11.12 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 ou 2 signifie 'Audit all' ou plus élevé)
        if value == 1 or value == 2:
            print(f"{GREEN}2.3.11.12 Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.11.12 Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers: Non conforme (Valeur Relevée: {value} - doit être 1 ou 2){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.11.12 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.14.1 : Vérifier la politique "Force strong key protection for user keys"
def check_force_strong_key_protection():
    r"""
    Vérifie si la politique 'System cryptography: Force strong key protection for user keys stored on the computer' 
    est configurée sur 'User is prompted when the key is first used' ou plus élevé.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\Cryptography"
        registry_value = "ForceKeyProtection"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.14.1 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'User is prompted when the key is first used')
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}2.3.14.1 System cryptography: Force strong key protection for user keys: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.14.1 System cryptography: Force strong key protection for user keys: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.14.1 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.15.1 : Vérifier la politique "Require case insensitivity for non-Windows subsystems"
def check_require_case_insensitivity_for_non_windows_subsystems():
    r"""
    Vérifie si la politique 'System objects: Require case insensitivity for non-Windows subsystems' 
    est configurée sur 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
        registry_value = "ObCaseInsensitive"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.15.1 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'Enabled')
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}2.3.15.1 System objects: Require case insensitivity for non-Windows subsystems: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.15.1 System objects: Require case insensitivity for non-Windows subsystems: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.15.1 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.15.2 : Vérifier la politique "Strengthen default permissions of internal system objects"
def check_strengthen_default_permissions_of_system_objects():
    r"""
    Vérifie si la politique 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' 
    est configurée sur 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Control\Session Manager"
        registry_value = "ProtectionMode"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.15.2 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'Enabled')
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}2.3.15.2 System objects: Strengthen default permissions of internal system objects: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.15.2 System objects: Strengthen default permissions of internal system objects: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.15.2 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.17.1 : Vérifier la politique "Admin Approval Mode for the Built-in Administrator account"
def check_admin_approval_mode_for_builtin_administrator():
    r"""
    Vérifie si la politique 'User Account Control: Admin Approval Mode for the Built-in Administrator account' 
    est configurée sur 'Enabled' (valeur 1 pour "Enabled").
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "FilterAdministratorToken"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.17.1 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'Enabled')
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}2.3.17.1 User Account Control: Admin Approval Mode for the Built-in Administrator account: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.17.1 User Account Control: Admin Approval Mode for the Built-in Administrator account: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.17.1 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.17.2 : Vérifier la politique "Behavior of the elevation prompt for administrators in Admin Approval Mode"
def check_elevation_prompt_behavior_for_admins():
    r"""
    Vérifie si la politique 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode'
    est configurée sur 'Prompt for consent on the secure desktop' ou plus élevé.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "ConsentPromptBehaviorAdmin"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.17.2 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 ou 2 signifie 'Prompt for consent on the secure desktop' ou plus élevé)
        if value == 1 or value == 2:
            print(f"{GREEN}2.3.17.2 User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.17.2 User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode: Non conforme (Valeur Relevée: {value} - doit être 1 ou 2){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.17.2 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.17.3 : Vérifier la politique "Behavior of the elevation prompt for standard users"
def check_elevation_prompt_behavior_for_standard_users():
    r"""
    Vérifie si la politique 'User Account Control: Behavior of the elevation prompt for standard users'
    est configurée sur 'Automatically deny elevation requests'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "ConsentPromptBehaviorUser"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.17.3 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (0 signifie 'Automatically deny elevation requests')
        expected_value = 0
        if value == expected_value:
            print(f"{GREEN}2.3.17.3 User Account Control: Behavior of the elevation prompt for standard users: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.17.3 User Account Control: Behavior of the elevation prompt for standard users: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.17.3 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.17.4 : Vérifier la politique "Detect application installations and prompt for elevation"
def check_detect_application_installations_and_prompt_for_elevation():
    r"""
    Vérifie si la politique 'User Account Control: Detect application installations and prompt for elevation' 
    est configurée sur 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "EnableInstallerDetection"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.17.4 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'Enabled')
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}2.3.17.4 User Account Control: Detect application installations and prompt for elevation: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.17.4 User Account Control: Detect application installations and prompt for elevation: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.17.4 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.17.5 : Vérifier la politique "Only elevate UIAccess applications that are installed in secure locations"
def check_only_elevate_uiaccess_in_secure_locations():
    r"""
    Vérifie si la politique 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' 
    est configurée sur 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "EnableSecureUIAccessPaths"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.17.5 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'Enabled')
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}2.3.17.5 User Account Control: Only elevate UIAccess applications that are installed in secure locations: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.17.5 User Account Control: Only elevate UIAccess applications that are installed in secure locations: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.17.5 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.17.6 : Vérifier la politique "Run all administrators in Admin Approval Mode"
def check_run_all_administrators_in_admin_approval_mode():
    r"""
    Vérifie si la politique 'User Account Control: Run all administrators in Admin Approval Mode'
    est configurée sur 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "EnableLUA"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.17.6 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'Enabled')
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}2.3.17.6 User Account Control: Run all administrators in Admin Approval Mode: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.17.6 User Account Control: Run all administrators in Admin Approval Mode: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.17.6 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.17.7 : Vérifier la politique "Switch to the secure desktop when prompting for elevation"
def check_switch_to_secure_desktop_when_prompting_for_elevation():
    r"""
    Vérifie si la politique 'User Account Control: Switch to the secure desktop when prompting for elevation'
    est configurée sur 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "PromptOnSecureDesktop"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.17.7 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'Enabled')
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}2.3.17.7 User Account Control: Switch to the secure desktop when prompting for elevation: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.17.7 User Account Control: Switch to the secure desktop when prompting for elevation: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.17.7 : {e}{RESET}")

@compliance_check
# Contrôle 2.3.17.8 : Vérifier la politique "Virtualize file and registry write failures to per-user locations"
def check_virtualize_file_and_registry_write_failures():
    r"""
    Vérifie si la politique 'User Account Control: Virtualize file and registry write failures to per-user locations' 
    est configurée sur 'Enabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        registry_value = "EnableVirtualization"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}2.3.17.8 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'Enabled')
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}2.3.17.8 User Account Control: Virtualize file and registry write failures to per-user locations: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}2.3.17.8 User Account Control: Virtualize file and registry write failures to per-user locations: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 2.3.17.8 : {e}{RESET}")

@compliance_check
# Contrôle 5.1 : Vérifier la politique "Bluetooth Audio Gateway Service (BTAGService)"
def check_bluetooth_audio_gateway_service():
    r"""
    Vérifie si le service 'Bluetooth Audio Gateway Service (BTAGService)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\BTAGService"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}5.1 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.1 Bluetooth Audio Gateway Service (BTAGService): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.1 Bluetooth Audio Gateway Service (BTAGService): Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.1 : {e}{RESET}")

@compliance_check
# Contrôle 5.2 : Vérifier la politique "Bluetooth Support Service (bthserv)"
def check_bluetooth_support_service():
    r"""
    Vérifie si le service 'Bluetooth Support Service (bthserv)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\bthserv"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}5.2 : La clé de registre '{registry_key}' ou la valeur '{registry_value}' n'existe pas.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.2 Bluetooth Support Service (bthserv): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.2 Bluetooth Support Service (bthserv): Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.2 : {e}{RESET}")

@compliance_check
# Contrôle 5.3 : Vérifier la politique "Computer Browser (Browser)"
def check_computer_browser_service():
    r"""
    Vérifie si le service 'Computer Browser (Browser)' est configuré sur 'Disabled' ou 'Not Installed'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\Browser"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.3 : Le service 'Computer Browser' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.3 Computer Browser (Browser): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.3 Computer Browser (Browser): Non conforme (Valeur Relevée: {value} - doit être 4 ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.3 : {e}{RESET}")

@compliance_check
# Contrôle 5.4 : Vérifier la politique "Downloaded Maps Manager (MapsBroker)"
def check_downloaded_maps_manager_service():
    r"""
    Vérifie si le service 'Downloaded Maps Manager (MapsBroker)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\MapsBroker"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.4 : Le service 'Downloaded Maps Manager (MapsBroker)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.4 Downloaded Maps Manager (MapsBroker): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.4 Downloaded Maps Manager (MapsBroker): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.4 : {e}{RESET}")

@compliance_check
# Contrôle 5.5 : Vérifier la politique "Geolocation Service (lfsvc)"
def check_geolocation_service():
    r"""
    Vérifie si le service 'Geolocation Service (lfsvc)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\lfsvc"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.5 : Le service 'Geolocation Service (lfsvc)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.5 Geolocation Service (lfsvc): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.5 Geolocation Service (lfsvc): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.5 : {e}{RESET}")

@compliance_check
# Contrôle 5.6 : Vérifier la politique "IIS Admin Service (IISADMIN)"
def check_iis_admin_service():
    r"""
    Vérifie si le service 'IIS Admin Service (IISADMIN)' est configuré sur 'Disabled' ou 'Not Installed'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\IISADMIN"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.6 : Le service 'IIS Admin Service (IISADMIN)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.6 IIS Admin Service (IISADMIN): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.6 IIS Admin Service (IISADMIN): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.6 : {e}{RESET}")

@compliance_check
# Contrôle 5.7 : Vérifier la politique "Infrared monitor service (irmon)"
def check_infrared_monitor_service():
    r"""
    Vérifie si le service 'Infrared monitor service (irmon)' est configuré sur 'Disabled' ou 'Not Installed'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\irmon"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.7 : Le service 'Infrared monitor service (irmon)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.7 Infrared monitor service (irmon): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.7 Infrared monitor service (irmon): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.7 : {e}{RESET}")

@compliance_check
# Contrôle 5.8 : Vérifier la politique "Link-Layer Topology Discovery Mapper (lltdsvc)"
def check_link_layer_topology_discovery_mapper_service():
    r"""
    Vérifie si le service 'Link-Layer Topology Discovery Mapper (lltdsvc)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\lltdsvc"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.8 : Le service 'Link-Layer Topology Discovery Mapper (lltdsvc)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.8 Link-Layer Topology Discovery Mapper (lltdsvc): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.8 Link-Layer Topology Discovery Mapper (lltdsvc): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.8 : {e}{RESET}")

@compliance_check
# Contrôle 5.9 : Vérifier la politique "LxssManager (LxssManager)"
def check_lxss_manager_service():
    r"""
    Vérifie si le service 'LxssManager (LxssManager)' est configuré sur 'Disabled' ou 'Not Installed'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\LxssManager"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.9 : Le service 'LxssManager (LxssManager)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.9 LxssManager (LxssManager): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.9 LxssManager (LxssManager): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.9 : {e}{RESET}")

@compliance_check
# Contrôle 5.10 : Vérifier la politique "Microsoft FTP Service (FTPSVC)"
def check_microsoft_ftp_service():
    r"""
    Vérifie si le service 'Microsoft FTP Service (FTPSVC)' est configuré sur 'Disabled' ou 'Not Installed'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\FTPSVC"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.10 : Le service 'Microsoft FTP Service (FTPSVC)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.10 Microsoft FTP Service (FTPSVC): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.10 Microsoft FTP Service (FTPSVC): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.10 : {e}{RESET}")

@compliance_check
# Contrôle 5.11 : Vérifier la politique "Microsoft iSCSI Initiator Service (MSiSCSI)"
def check_microsoft_iscsi_initiator_service():
    r"""
    Vérifie si le service 'Microsoft iSCSI Initiator Service (MSiSCSI)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\MSiSCSI"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.11 : Le service 'Microsoft iSCSI Initiator Service (MSiSCSI)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.11 Microsoft iSCSI Initiator Service (MSiSCSI): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.11 Microsoft iSCSI Initiator Service (MSiSCSI): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.11 : {e}{RESET}")

@compliance_check
# Contrôle 5.12 : Vérifier la politique "OpenSSH SSH Server (sshd)"
def check_openssh_ssh_server_service():
    r"""
    Vérifie si le service 'OpenSSH SSH Server (sshd)' est configuré sur 'Disabled' ou 'Not Installed'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\sshd"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.12 : Le service 'OpenSSH SSH Server (sshd)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.12 OpenSSH SSH Server (sshd): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.12 OpenSSH SSH Server (sshd): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.12 : {e}{RESET}")

@compliance_check
# Contrôle 5.13 : Vérifier la politique "Peer Name Resolution Protocol (PNRPsvc)"
def check_peer_name_resolution_protocol_service():
    r"""
    Vérifie si le service 'Peer Name Resolution Protocol (PNRPsvc)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\PNRPsvc"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.13 : Le service 'Peer Name Resolution Protocol (PNRPsvc)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.13 Peer Name Resolution Protocol (PNRPsvc): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.13 Peer Name Resolution Protocol (PNRPsvc): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.13 : {e}{RESET}")

@compliance_check
# Contrôle 5.14 : Vérifier la politique "Peer Networking Grouping (p2psvc)"
def check_peer_networking_grouping_service():
    r"""
    Vérifie si le service 'Peer Networking Grouping (p2psvc)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\p2psvc"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.14 : Le service 'Peer Networking Grouping (p2psvc)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.14 Peer Networking Grouping (p2psvc): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.14 Peer Networking Grouping (p2psvc): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.14 : {e}{RESET}")
        
@compliance_check        
# Contrôle 5.15 : Vérifier la politique "Peer Networking Identity Manager (p2pimsvc)"
def check_peer_networking_identity_manager_service():
    r"""
    Vérifie si le service 'Peer Networking Identity Manager (p2pimsvc)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\p2pimsvc"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.15 : Le service 'Peer Networking Identity Manager (p2pimsvc)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.15 Peer Networking Identity Manager (p2pimsvc): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.15 Peer Networking Identity Manager (p2pimsvc): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.15 : {e}{RESET}")

@compliance_check
# Contrôle 5.16 : Vérifier la politique "PNRP Machine Name Publication Service (PNRPAutoReg)"
def check_pnrp_machine_name_publication_service():
    r"""
    Vérifie si le service 'PNRP Machine Name Publication Service (PNRPAutoReg)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\PNRPAutoReg"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.16 : Le service 'PNRP Machine Name Publication Service (PNRPAutoReg)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.16 PNRP Machine Name Publication Service (PNRPAutoReg): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.16 PNRP Machine Name Publication Service (PNRPAutoReg): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.16 : {e}{RESET}")

@compliance_check
# Contrôle 5.17 : Vérifier la politique "Print Spooler (Spooler)"
def check_print_spooler_service():
    r"""
    Vérifie si le service 'Print Spooler (Spooler)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\Spooler"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.17 : Le service 'Print Spooler (Spooler)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.17 Print Spooler (Spooler): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.17 Print Spooler (Spooler): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.17 : {e}{RESET}")

@compliance_check
# Contrôle 5.18 : Vérifier la politique "Problem Reports and Solutions Control Panel Support (wercplsupport)"
def check_problem_reports_and_solutions_control_panel_support_service():
    r"""
    Vérifie si le service 'Problem Reports and Solutions Control Panel Support (wercplsupport)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\wercplsupport"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.18 : Le service 'Problem Reports and Solutions Control Panel Support (wercplsupport)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.18 Problem Reports and Solutions Control Panel Support (wercplsupport): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.18 Problem Reports and Solutions Control Panel Support (wercplsupport): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.18 : {e}{RESET}")

@compliance_check
# Contrôle 5.19 : Vérifier la politique "Remote Access Auto Connection Manager (RasAuto)"
def check_remote_access_auto_connection_manager_service():
    r"""
    Vérifie si le service 'Remote Access Auto Connection Manager (RasAuto)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\RasAuto"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.19 : Le service 'Remote Access Auto Connection Manager (RasAuto)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.19 Remote Access Auto Connection Manager (RasAuto): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.19 Remote Access Auto Connection Manager (RasAuto): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.19 : {e}{RESET}")

@compliance_check
# Contrôle 5.20 : Vérifier la politique "Remote Desktop Configuration (SessionEnv)"
def check_remote_desktop_configuration_service():
    r"""
    Vérifie si le service 'Remote Desktop Configuration (SessionEnv)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\SessionEnv"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.20 : Le service 'Remote Desktop Configuration (SessionEnv)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.20 Remote Desktop Configuration (SessionEnv): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.20 Remote Desktop Configuration (SessionEnv): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.20 : {e}{RESET}")

@compliance_check
# Contrôle 5.21 : Vérifier la politique "Remote Desktop Services (TermService)"
def check_remote_desktop_services_service():
    r"""
    Vérifie si le service 'Remote Desktop Services (TermService)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\TermService"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.21 : Le service 'Remote Desktop Services (TermService)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.21 Remote Desktop Services (TermService): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.21 Remote Desktop Services (TermService): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.21 : {e}{RESET}")

@compliance_check
# Contrôle 5.22 : Vérifier la politique "Remote Desktop Services UserMode Port Redirector (UmRdpService)"
def check_remote_desktop_services_usermode_port_redirector_service():
    r"""
    Vérifie si le service 'Remote Desktop Services UserMode Port Redirector (UmRdpService)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\UmRdpService"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.22 : Le service 'Remote Desktop Services UserMode Port Redirector (UmRdpService)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.22 Remote Desktop Services UserMode Port Redirector (UmRdpService): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.22 Remote Desktop Services UserMode Port Redirector (UmRdpService): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.22 : {e}{RESET}")

@compliance_check
# Contrôle 5.23 : Vérifier la politique "Remote Procedure Call (RPC) Locator (RpcLocator)"
def check_rpc_locator_service():
    r"""
    Vérifie si le service 'Remote Procedure Call (RPC) Locator (RpcLocator)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\RpcLocator"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.23 : Le service 'Remote Procedure Call (RPC) Locator (RpcLocator)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.23 Remote Procedure Call (RPC) Locator (RpcLocator): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.23 Remote Procedure Call (RPC) Locator (RpcLocator): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.23 : {e}{RESET}")

@compliance_check
# Contrôle 5.24 : Vérifier la politique "Remote Registry (RemoteRegistry)"
def check_remote_registry_service():
    r"""
    Vérifie si le service 'Remote Registry (RemoteRegistry)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\RemoteRegistry"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.24 : Le service 'Remote Registry (RemoteRegistry)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.24 Remote Registry (RemoteRegistry): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.24 Remote Registry (RemoteRegistry): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.24 : {e}{RESET}")

@compliance_check
# Contrôle 5.25 : Vérifier la politique "Routing and Remote Access (RemoteAccess)"
def check_routing_and_remote_access_service():
    r"""
    Vérifie si le service 'Routing and Remote Access (RemoteAccess)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\RemoteAccess"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.25 : Le service 'Routing and Remote Access (RemoteAccess)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.25 Routing and Remote Access (RemoteAccess): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.25 Routing and Remote Access (RemoteAccess): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.25 : {e}{RESET}")

@compliance_check
# Contrôle 5.26 : Vérifier la politique "Server (LanmanServer)"
def check_server_lanmanserver_service():
    r"""
    Vérifie si le service 'Server (LanmanServer)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\LanmanServer"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.26 : Le service 'Server (LanmanServer)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.26 Server (LanmanServer): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.26 Server (LanmanServer): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.26 : {e}{RESET}")

@compliance_check
# Contrôle 5.27 : Vérifier la politique "Simple TCP/IP Services (simptcp)"
def check_simple_tcp_ip_services_service():
    r"""
    Vérifie si le service 'Simple TCP/IP Services (simptcp)' est configuré sur 'Disabled' ou 'Not Installed'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\simptcp"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.27 : Le service 'Simple TCP/IP Services (simptcp)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.27 Simple TCP/IP Services (simptcp): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.27 Simple TCP/IP Services (simptcp): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.27 : {e}{RESET}")

@compliance_check
# Contrôle 5.28 : Vérifier la politique "SNMP Service (SNMP)"
def check_snmp_service():
    r"""
    Vérifie si le service 'SNMP Service (SNMP)' est configuré sur 'Disabled' ou 'Not Installed'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\SNMP"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.28 : Le service 'SNMP Service (SNMP)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.28 SNMP Service (SNMP): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.28 SNMP Service (SNMP): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.28 : {e}{RESET}")

@compliance_check
# Contrôle 5.29 : Vérifier la politique "Special Administration Console Helper (sacsvr)"
def check_special_administration_console_helper_service():
    r"""
    Vérifie si le service 'Special Administration Console Helper (sacsvr)' est configuré sur 'Disabled' ou 'Not Installed'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\sacsvr"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.29 : Le service 'Special Administration Console Helper (sacsvr)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.29 Special Administration Console Helper (sacsvr): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.29 Special Administration Console Helper (sacsvr): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.29 : {e}{RESET}")

@compliance_check
# Contrôle 5.30 : Vérifier la politique "SSDP Discovery (SSDPSRV)"
def check_ssdp_discovery_service():
    r"""
    Vérifie si le service 'SSDP Discovery (SSDPSRV)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\SSDPSRV"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.30 : Le service 'SSDP Discovery (SSDPSRV)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.30 SSDP Discovery (SSDPSRV): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.30 SSDP Discovery (SSDPSRV): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.30 : {e}{RESET}")

@compliance_check
# Contrôle 5.31 : Vérifier la politique "UPnP Device Host (upnphost)"
def check_upnp_device_host_service():
    r"""
    Vérifie si le service 'UPnP Device Host (upnphost)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\upnphost"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.31 : Le service 'UPnP Device Host (upnphost)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.31 UPnP Device Host (upnphost): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.31 UPnP Device Host (upnphost): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.31 : {e}{RESET}")

@compliance_check
# Contrôle 5.32 : Vérifier la politique "Web Management Service (WMSvc)"
def check_web_management_service():
    r"""
    Vérifie si le service 'Web Management Service (WMSvc)' est configuré sur 'Disabled' ou 'Not Installed'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\WMSvc"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.32 : Le service 'Web Management Service (WMSvc)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.32 Web Management Service (WMSvc): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.32 Web Management Service (WMSvc): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.32 : {e}{RESET}")

@compliance_check
# Contrôle 5.33 : Vérifier la politique "Windows Error Reporting Service (WerSvc)"
def check_windows_error_reporting_service():
    r"""
    Vérifie si le service 'Windows Error Reporting Service (WerSvc)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\WerSvc"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.33 : Le service 'Windows Error Reporting Service (WerSvc)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.33 Windows Error Reporting Service (WerSvc): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.33 Windows Error Reporting Service (WerSvc): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.33 : {e}{RESET}")

@compliance_check
# Contrôle 5.34 : Vérifier la politique "Windows Event Collector (Wecsvc)"
def check_windows_event_collector_service():
    r"""
    Vérifie si le service 'Windows Event Collector (Wecsvc)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\Wecsvc"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.34 : Le service 'Windows Event Collector (Wecsvc)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.34 Windows Event Collector (Wecsvc): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.34 Windows Event Collector (Wecsvc): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.34 : {e}{RESET}")

@compliance_check
# Contrôle 5.35 : Vérifier la politique "Windows Media Player Network Sharing Service (WMPNetworkSvc)"
def check_wmp_network_sharing_service():
    r"""
    Vérifie si le service 'Windows Media Player Network Sharing Service (WMPNetworkSvc)' est configuré sur 'Disabled' ou 'Not Installed'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\WMPNetworkSvc"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.35 : Le service 'Windows Media Player Network Sharing Service (WMPNetworkSvc)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.35 Windows Media Player Network Sharing Service (WMPNetworkSvc): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.35 Windows Media Player Network Sharing Service (WMPNetworkSvc): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.35 : {e}{RESET}")

@compliance_check
# Contrôle 5.36 : Vérifier la politique "Windows Mobile Hotspot Service (icssvc)"
def check_windows_mobile_hotspot_service():
    r"""
    Vérifie si le service 'Windows Mobile Hotspot Service (icssvc)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\icssvc"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.36 : Le service 'Windows Mobile Hotspot Service (icssvc)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.36 Windows Mobile Hotspot Service (icssvc): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.36 Windows Mobile Hotspot Service (icssvc): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.36 : {e}{RESET}")

@compliance_check
# Contrôle 5.37 : Vérifier la politique "Windows Push Notifications System Service (WpnService)"
def check_wpn_service():
    r"""
    Vérifie si le service 'Windows Push Notifications System Service (WpnService)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\WpnService"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.37 : Le service 'Windows Push Notifications System Service (WpnService)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.37 Windows Push Notifications System Service (WpnService): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.37 Windows Push Notifications System Service (WpnService): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.37 : {e}{RESET}")

@compliance_check
# Contrôle 5.38 : Vérifier la politique "Windows PushToInstall Service (PushToInstall)"
def check_push_to_install_service():
    r"""
    Vérifie si le service 'Windows PushToInstall Service (PushToInstall)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\PushToInstall"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.38 : Le service 'Windows PushToInstall Service (PushToInstall)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.38 Windows PushToInstall Service (PushToInstall): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.38 Windows PushToInstall Service (PushToInstall): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.38 : {e}{RESET}")
        
@compliance_check
# Contrôle 5.39 : Vérifier la politique "Windows Remote Management (WinRM)"
def check_winrm_service():
    r"""
    Vérifie si le service 'Windows Remote Management (WinRM)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\WinRM"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.39 : Le service 'Windows Remote Management (WinRM)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.39 Windows Remote Management (WinRM): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.39 Windows Remote Management (WinRM): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.39 : {e}{RESET}")

@compliance_check
# Contrôle 5.40 : Vérifier la politique "World Wide Web Publishing Service (W3SVC)"
def check_www_publishing_service():
    r"""
    Vérifie si le service 'World Wide Web Publishing Service (W3SVC)' est configuré sur 'Disabled' ou 'Not Installed'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\W3SVC"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.40 : Le service 'World Wide Web Publishing Service (W3SVC)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.40 World Wide Web Publishing Service (W3SVC): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.40 World Wide Web Publishing Service (W3SVC): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.40 : {e}{RESET}")

@compliance_check
# Contrôle 5.41 : Vérifier la politique "Xbox Accessory Management Service (XboxGipSvc)"
def check_xbox_accessory_management_service():
    r"""
    Vérifie si le service 'Xbox Accessory Management Service (XboxGipSvc)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\XboxGipSvc"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.41 : Le service 'Xbox Accessory Management Service (XboxGipSvc)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.41 Xbox Accessory Management Service (XboxGipSvc): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.41 Xbox Accessory Management Service (XboxGipSvc): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.41 : {e}{RESET}")

@compliance_check
# Contrôle 5.42 : Vérifier la politique "Xbox Live Auth Manager (XblAuthManager)"
def check_xbox_live_auth_manager():
    r"""
    Vérifie si le service 'Xbox Live Auth Manager (XblAuthManager)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\XblAuthManager"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.42 : Le service 'Xbox Live Auth Manager (XblAuthManager)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.42 Xbox Live Auth Manager (XblAuthManager): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.42 Xbox Live Auth Manager (XblAuthManager): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.42 : {e}{RESET}")

@compliance_check
# Contrôle 5.43 : Vérifier la politique "Xbox Live Game Save (XblGameSave)"
def check_xbox_live_game_save():
    r"""
    Vérifie si le service 'Xbox Live Game Save (XblGameSave)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\XblGameSave"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.43 : Le service 'Xbox Live Game Save (XblGameSave)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.43 Xbox Live Game Save (XblGameSave): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.43 Xbox Live Game Save (XblGameSave): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.43 : {e}{RESET}")

@compliance_check
# Contrôle 5.44 : Vérifier la politique "Xbox Live Networking Service (XboxNetApiSvc)"
def check_xbox_live_networking_service():
    r"""
    Vérifie si le service 'Xbox Live Networking Service (XboxNetApiSvc)' est configuré sur 'Disabled'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SYSTEM\CurrentControlSet\Services\XboxNetApiSvc"
        registry_value = "Start"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}5.44 : Le service 'Xbox Live Networking Service (XboxNetApiSvc)' n'est pas installé (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (4 signifie 'Disabled')
        expected_value = 4
        if value == expected_value:
            print(f"{GREEN}5.44 Xbox Live Networking Service (XboxNetApiSvc): Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}5.44 Xbox Live Networking Service (XboxNetApiSvc): Non conforme (Valeur Relevée: {value} - doit être {expected_value} ou clé non existante){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 5.44 : {e}{RESET}")

@compliance_check
# Contrôle 9.2.1 : Vérifier la politique "Windows Firewall: Private: Firewall state"
def check_private_firewall_state():
    r"""
    Vérifie si l'état du pare-feu privé de Windows est configuré sur 'On (recommended)'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
        registry_value = "EnableFirewall"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}9.2.1 : Le service 'Windows Firewall: Private: Firewall state' n'est pas configuré (clé de registre '{registry_key}' introuvable). Conformité vérifiée.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'On')
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}9.2.1 Windows Firewall: Private: Firewall state: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}9.2.1 Windows Firewall: Private: Firewall state: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 9.2.1 : {e}{RESET}")

@compliance_check
# Contrôle 9.2.2 : Vérifier la politique "Windows Firewall: Private: Inbound connections"
def check_private_inbound_connections():
    r"""
    Vérifie si la politique "Windows Firewall: Private: Inbound connections" est configurée sur 'Block (default)'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
        registry_value = "DefaultInboundAction"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}9.2.2 : La clé de registre '{registry_key}' est introuvable, ce qui signifie que la configuration est correcte (Blocage des connexions entrantes par défaut).{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'Block')
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}9.2.2 Windows Firewall: Private: Inbound connections: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}9.2.2 Windows Firewall: Private: Inbound connections: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 9.2.2 : {e}{RESET}")

@compliance_check
# Contrôle 9.2.3 : Vérifier la politique "Windows Firewall: Private: Settings: Display a notification"
def check_private_firewall_notification():
    r"""
    Vérifie si la politique 'Windows Firewall: Private: Settings: Display a notification' est configurée sur 'No'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
        registry_value = "DisableNotifications"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{GREEN}9.2.3 : La clé de registre '{registry_key}' est introuvable, ce qui signifie que la configuration est correcte (Notification désactivée).{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'No', notifications désactivées)
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}9.2.3 Windows Firewall: Private: Settings: Display a notification: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}9.2.3 Windows Firewall: Private: Settings: Display a notification: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 9.2.3 : {e}{RESET}")

@compliance_check
# Contrôle 9.2.4 : Vérifier la politique "Windows Firewall: Private: Logging: Name"
def check_private_firewall_log_file():
    r"""
    Vérifie si le chemin du fichier de journalisation du pare-feu privé est configuré sur '%SystemRoot%\System32\logfiles\firewall\privatefw.log'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
        registry_value = "LogFilePath"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}9.2.4 : La clé de registre '{registry_key}' est introuvable. Vérifiez la configuration du fichier de journalisation.{RESET}")
            return

        # Vérifier si la valeur est correcte
        expected_value = r"%SystemRoot%\System32\logfiles\firewall\privatefw.log"
        if value == expected_value:
            print(f"{GREEN}9.2.4 Windows Firewall: Private: Logging: Name: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}9.2.4 Windows Firewall: Private: Logging: Name: Non conforme (Valeur Relevée: {value} - doit être '{expected_value}'){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 9.2.4 : {e}{RESET}")

@compliance_check
# Contrôle 9.2.5 : Vérifier la politique "Windows Firewall: Private: Logging: Size limit (KB)"
def check_private_firewall_log_size_limit():
    r"""
    Vérifie si la taille limite du fichier de journalisation du pare-feu privé est configurée sur '16,384 KB ou plus'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
        registry_value = "LogFileSize"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}9.2.5 : La clé de registre '{registry_key}' est introuvable. Vérifiez la configuration de la taille limite du fichier de journalisation.{RESET}")
            return

        # Vérifier si la valeur est correcte (16384 KB ou plus)
        minimum_value = 16384
        if value >= minimum_value:
            print(f"{GREEN}9.2.5 Windows Firewall: Private: Logging: Size limit (KB): Conforme (Valeur Relevée: {value} KB){RESET}")
        else:
            print(f"{RED}9.2.5 Windows Firewall: Private: Logging: Size limit (KB): Non conforme (Valeur Relevée: {value} KB - doit être {minimum_value} KB ou plus){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 9.2.5 : {e}{RESET}")

@compliance_check
# Contrôle 9.2.6 : Vérifier la politique "Windows Firewall: Private: Logging: Log dropped packets"
def check_private_firewall_log_dropped_packets():
    r"""
    Vérifie si la politique 'Windows Firewall: Private: Logging: Log dropped packets' est configurée sur 'Yes'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
        registry_value = "LogDroppedPackets"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}9.2.6 : La clé de registre '{registry_key}' est introuvable. Vérifiez la configuration de la journalisation des paquets abandonnés.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'Yes', journalisation des paquets abandonnés activée)
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}9.2.6 Windows Firewall: Private: Logging: Log dropped packets: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}9.2.6 Windows Firewall: Private: Logging: Log dropped packets: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 9.2.6 : {e}{RESET}")

@compliance_check
# Contrôle 9.2.7 : Vérifier la politique "Windows Firewall: Private: Logging: Log successful connections"
def check_private_firewall_log_successful_connections():
    r"""
    Vérifie si la politique 'Windows Firewall: Private: Logging: Log successful connections' est configurée sur 'Yes'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
        registry_value = "LogSuccessfulConnections"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}9.2.7 : La clé de registre '{registry_key}' est introuvable. Vérifiez la configuration de la journalisation des connexions réussies.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'Yes', journalisation des connexions réussies activée)
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}9.2.7 Windows Firewall: Private: Logging: Log successful connections: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}9.2.7 Windows Firewall: Private: Logging: Log successful connections: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 9.2.7 : {e}{RESET}")

@compliance_check
# Contrôle 9.3.1 : Vérifier la politique "Windows Firewall: Public: Firewall state"
def check_public_firewall_state():
    r"""
    Vérifie si la politique 'Windows Firewall: Public: Firewall state' est configurée sur 'On (recommended)'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        registry_value = "EnableFirewall"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}9.3.1 : La clé de registre '{registry_key}' est introuvable. Vérifiez la configuration de l'état du pare-feu public.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'On (recommended)', pare-feu activé)
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}9.3.1 Windows Firewall: Public: Firewall state: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}9.3.1 Windows Firewall: Public: Firewall state: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 9.3.1 : {e}{RESET}")

@compliance_check
# Contrôle 9.3.2 : Vérifier la politique "Windows Firewall: Public: Inbound connections"
def check_public_firewall_inbound_connections():
    r"""
    Vérifie si la politique 'Windows Firewall: Public: Inbound connections' est configurée sur 'Block (default)'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        registry_value = "DefaultInboundAction"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}9.3.2 : La clé de registre '{registry_key}' est introuvable. Vérifiez la configuration des connexions entrantes du pare-feu public.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'Block (default)', connexions entrantes bloquées par défaut)
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}9.3.2 Windows Firewall: Public: Inbound connections: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}9.3.2 Windows Firewall: Public: Inbound connections: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 9.3.2 : {e}{RESET}")

@compliance_check
# Contrôle 9.3.3 : Vérifier la politique "Windows Firewall: Public: Settings: Display a notification"
def check_public_firewall_display_notification():
    r"""
    Vérifie si la politique 'Windows Firewall: Public: Settings: Display a notification' est configurée sur 'No'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        registry_value = "DisableNotifications"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}9.3.3 : La clé de registre '{registry_key}' est introuvable. Vérifiez la configuration des notifications du pare-feu public.{RESET}")
            return

        # Vérifier si la valeur est correcte (1 signifie 'No', notifications désactivées)
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}9.3.3 Windows Firewall: Public: Settings: Display a notification: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}9.3.3 Windows Firewall: Public: Settings: Display a notification: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 9.3.3 : {e}{RESET}")

@compliance_check
# Contrôle 9.3.4 : Vérifier la politique "Windows Firewall: Public: Settings: Apply local firewall rules"
def check_public_firewall_apply_local_rules():
    r"""
    Vérifie si la politique 'Windows Firewall: Public: Settings: Apply local firewall rules' est configurée sur 'No'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        registry_value = "AllowLocalPolicyMerge"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}9.3.4 : La clé de registre '{registry_key}' est introuvable. Vérifiez la configuration de l'application des règles locales du pare-feu public.{RESET}")
            return

        # Vérifier si la valeur est correcte (0 signifie 'No', application des règles locales désactivée)
        expected_value = 0
        if value == expected_value:
            print(f"{GREEN}9.3.4 Windows Firewall: Public: Settings: Apply local firewall rules: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}9.3.4 Windows Firewall: Public: Settings: Apply local firewall rules: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 9.3.4 : {e}{RESET}")

@compliance_check
# Contrôle 9.3.5 : Vérifier la politique "Windows Firewall: Public: Settings: Apply local connection security rules"
def check_public_firewall_apply_local_ipsec_rules():
    r"""
    Vérifie si la politique 'Windows Firewall: Public: Settings: Apply local connection security rules' est configurée sur 'No'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        registry_value = "AllowLocalIPsecPolicyMerge"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}9.3.5 : La clé de registre '{registry_key}' est introuvable. Vérifiez la configuration de l'application des règles locales de sécurité des connexions du pare-feu public.{RESET}")
            return

        # Vérifier si la valeur est correcte (0 signifie 'No', application des règles de sécurité des connexions locales désactivée)
        expected_value = 0
        if value == expected_value:
            print(f"{GREEN}9.3.5 Windows Firewall: Public: Settings: Apply local connection security rules: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}9.3.5 Windows Firewall: Public: Settings: Apply local connection security rules: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 9.3.5 : {e}{RESET}")

@compliance_check
# Contrôle 9.3.6 : Vérifier la politique "Windows Firewall: Public: Logging: Name"
def check_public_firewall_log_file_path():
    r"""
    Vérifie si la politique 'Windows Firewall: Public: Logging: Name' est configurée sur '%SystemRoot%\System32\logfiles\firewall\publicfw.log'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
        registry_value = "LogFilePath"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}9.3.6 : La clé de registre '{registry_key}' est introuvable. Vérifiez la configuration du fichier de log du pare-feu public.{RESET}")
            return

        # Vérifier si la valeur est correcte (le chemin attendu est '%SystemRoot%\System32\logfiles\firewall\publicfw.log')
        expected_value = r"%SystemRoot%\System32\logfiles\firewall\publicfw.log"
        if value == expected_value:
            print(f"{GREEN}9.3.6 Windows Firewall: Public: Logging: Name: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}9.3.6 Windows Firewall: Public: Logging: Name: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 9.3.6 : {e}{RESET}")

@compliance_check
# Contrôle 9.3.7 : Vérifier la politique "Windows Firewall: Public: Logging: Size limit (KB)"
def check_public_firewall_log_file_size():
    r"""
    Vérifie si la politique 'Windows Firewall: Public: Logging: Size limit (KB)' est configurée sur '16,384 KB ou plus'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
        registry_value = "LogFileSize"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}9.3.7 : La clé de registre '{registry_key}' est introuvable. Vérifiez la configuration de la taille limite du fichier de log du pare-feu public.{RESET}")
            return

        # Vérifier si la valeur est correcte (la taille doit être égale ou supérieure à 16,384 KB)
        expected_value = 16384
        if value >= expected_value:
            print(f"{GREEN}9.3.7 Windows Firewall: Public: Logging: Size limit (KB): Conforme (Valeur Relevée: {value} KB){RESET}")
        else:
            print(f"{RED}9.3.7 Windows Firewall: Public: Logging: Size limit (KB): Non conforme (Valeur Relevée: {value} KB - doit être {expected_value} KB ou plus){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 9.3.7 : {e}{RESET}")

@compliance_check
# Contrôle 9.3.8 : Vérifier la politique "Windows Firewall: Public: Logging: Log dropped packets"
def check_public_firewall_log_dropped_packets():
    r"""
    Vérifie si la politique 'Windows Firewall: Public: Logging: Log dropped packets' est configurée sur 'Yes'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
        registry_value = "LogDroppedPackets"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}9.3.8 : La clé de registre '{registry_key}' est introuvable. Vérifiez la configuration de l'enregistrement des paquets rejetés dans le journal du pare-feu public.{RESET}")
            return

        # Vérifier si la valeur est correcte (la valeur attendue est 1 pour 'Yes')
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}9.3.8 Windows Firewall: Public: Logging: Log dropped packets: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}9.3.8 Windows Firewall: Public: Logging: Log dropped packets: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 9.3.8 : {e}{RESET}")

@compliance_check
# Contrôle 9.3.9 : Vérifier la politique "Windows Firewall: Public: Logging: Log successful connections"
def check_public_firewall_log_successful_connections():
    r"""
    Vérifie si la politique 'Windows Firewall: Public: Logging: Log successful connections' est configurée sur 'Yes'.
    """
    try:
        # Vérification de la clé de registre correspondante
        registry_key = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
        registry_value = "LogSuccessfulConnections"

        # Essayer d'ouvrir la clé de registre
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key) as key:
                value, regtype = winreg.QueryValueEx(key, registry_value)
        except FileNotFoundError:
            print(f"{RED}9.3.9 : La clé de registre '{registry_key}' est introuvable. Vérifiez la configuration de l'enregistrement des connexions réussies dans le journal du pare-feu public.{RESET}")
            return

        # Vérifier si la valeur est correcte (la valeur attendue est 1 pour 'Yes')
        expected_value = 1
        if value == expected_value:
            print(f"{GREEN}9.3.9 Windows Firewall: Public: Logging: Log successful connections: Conforme (Valeur Relevée: {value}){RESET}")
        else:
            print(f"{RED}9.3.9 Windows Firewall: Public: Logging: Log successful connections: Non conforme (Valeur Relevée: {value} - doit être {expected_value}){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 9.3.9 : {e}{RESET}")

@compliance_check
# Contrôle 17.1.1 : Vérifier la politique "Audit Credential Validation" via PowerShell
def check_audit_credential_validation():
    """
    Vérifie si la politique 'Audit Credential Validation' est configurée à 'Success and Failure' en utilisant PowerShell.
    """
    try:
        # Exécuter PowerShell pour vérifier la configuration de "Credential Validation"
        ps_command = '''
        Get-WinEvent -ListLog Security | Where-Object { $_.LogName -eq 'Security' } | 
        Select-String -Pattern 'Credential Validation'
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Credential Validation" in output:
            print(f"{GREEN}17.1.1 Audit Credential Validation: Conforme (Valeur Relevée: Success and Failure){RESET}")
        else:
            print(f"{RED}17.1.1 Audit Credential Validation: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.1.1 : {e}{RESET}")

@compliance_check
# Contrôle 17.2.1 : Vérifier la politique "Audit Application Group Management" via PowerShell
def check_audit_application_group_management():
    """
    Vérifie si la politique 'Audit Application Group Management' est configurée à 'Success and Failure' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Application Group Management"
        ps_command = '''
        Get-AuditPolicy -Category "Account Management" | Where-Object {$_.Subcategory -eq "Application Group Management"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success and Failure" in output:
            print(f"{GREEN}17.2.1 Audit Application Group Management: Conforme (Valeur Relevée: Success and Failure){RESET}")
        else:
            print(f"{RED}17.2.1 Audit Application Group Management: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.2.1 : {e}{RESET}")

@compliance_check
# Contrôle 17.2.2 : Vérifier la politique "Audit Security Group Management" via PowerShell
def check_audit_security_group_management():
    """
    Vérifie si la politique 'Audit Security Group Management' est configurée pour inclure 'Success' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Security Group Management"
        ps_command = '''
        Get-AuditPolicy -Category "Account Management" | Where-Object {$_.Subcategory -eq "Security Group Management"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success" in output:
            print(f"{GREEN}17.2.2 Audit Security Group Management: Conforme (Valeur Relevée: Success){RESET}")
        else:
            print(f"{RED}17.2.2 Audit Security Group Management: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.2.2 : {e}{RESET}")

@compliance_check
# Contrôle 17.2.3 : Vérifier la politique "Audit User Account Management" via PowerShell
def check_audit_user_account_management():
    """
    Vérifie si la politique 'Audit User Account Management' est configurée à 'Success and Failure' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "User Account Management"
        ps_command = '''
        Get-AuditPolicy -Category "Account Management" | Where-Object {$_.Subcategory -eq "User Account Management"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success and Failure" in output:
            print(f"{GREEN}17.2.3 Audit User Account Management: Conforme (Valeur Relevée: Success and Failure){RESET}")
        else:
            print(f"{RED}17.2.3 Audit User Account Management: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.2.3 : {e}{RESET}")

@compliance_check
# Contrôle 17.3.1 : Vérifier la politique "Audit PNP Activity" via PowerShell
def check_audit_pnp_activity():
    """
    Vérifie si la politique 'Audit PNP Activity' est configurée pour inclure 'Success' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "PNP Activity"
        ps_command = '''
        Get-AuditPolicy -Category "Detailed Tracking" | Where-Object {$_.Subcategory -eq "PNP Activity"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success" in output:
            print(f"{GREEN}17.3.1 Audit PNP Activity: Conforme (Valeur Relevée: Success){RESET}")
        else:
            print(f"{RED}17.3.1 Audit PNP Activity: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.3.1 : {e}{RESET}")

@compliance_check
# Contrôle 17.3.2 : Vérifier la politique "Audit Process Creation" via PowerShell
def check_audit_process_creation():
    """
    Vérifie si la politique 'Audit Process Creation' est configurée pour inclure 'Success' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Process Creation"
        ps_command = '''
        Get-AuditPolicy -Category "Detailed Tracking" | Where-Object {$_.Subcategory -eq "Process Creation"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success" in output:
            print(f"{GREEN}17.3.2 Audit Process Creation: Conforme (Valeur Relevée: Success){RESET}")
        else:
            print(f"{RED}17.3.2 Audit Process Creation: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.3.2 : {e}{RESET}")

@compliance_check
# Contrôle 17.5.1 : Vérifier la politique "Audit Account Lockout" via PowerShell
def check_audit_account_lockout():
    """
    Vérifie si la politique 'Audit Account Lockout' est configurée pour inclure 'Failure' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Account Lockout"
        ps_command = '''
        Get-AuditPolicy -Category "Logon/Logoff" | Where-Object {$_.Subcategory -eq "Account Lockout"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Failure" in output:
            print(f"{GREEN}17.5.1 Audit Account Lockout: Conforme (Valeur Relevée: Failure){RESET}")
        else:
            print(f"{RED}17.5.1 Audit Account Lockout: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.5.1 : {e}{RESET}")

@compliance_check
# Contrôle 17.5.2 : Vérifier la politique "Audit Group Membership" via PowerShell
def check_audit_group_membership():
    """
    Vérifie si la politique 'Audit Group Membership' est configurée pour inclure 'Success' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Group Membership"
        ps_command = '''
        Get-AuditPolicy -Category "Logon/Logoff" | Where-Object {$_.Subcategory -eq "Group Membership"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success" in output:
            print(f"{GREEN}17.5.2 Audit Group Membership: Conforme (Valeur Relevée: Success){RESET}")
        else:
            print(f"{RED}17.5.2 Audit Group Membership: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.5.2 : {e}{RESET}")

@compliance_check
# Contrôle 17.5.3 : Vérifier la politique "Audit Logoff" via PowerShell
def check_audit_logoff():
    """
    Vérifie si la politique 'Audit Logoff' est configurée pour inclure 'Success' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Logoff"
        ps_command = '''
        Get-AuditPolicy -Category "Logon/Logoff" | Where-Object {$_.Subcategory -eq "Logoff"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success" in output:
            print(f"{GREEN}17.5.3 Audit Logoff: Conforme (Valeur Relevée: Success){RESET}")
        else:
            print(f"{RED}17.5.3 Audit Logoff: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.5.3 : {e}{RESET}")

@compliance_check
# Contrôle 17.5.4 : Vérifier la politique "Audit Logon" via PowerShell
def check_audit_logon():
    """
    Vérifie si la politique 'Audit Logon' est configurée pour inclure 'Success and Failure' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Logon"
        ps_command = '''
        Get-AuditPolicy -Category "Logon/Logoff" | Where-Object {$_.Subcategory -eq "Logon"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success and Failure" in output:
            print(f"{GREEN}17.5.4 Audit Logon: Conforme (Valeur Relevée: Success and Failure){RESET}")
        else:
            print(f"{RED}17.5.4 Audit Logon: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.5.4 : {e}{RESET}")

@compliance_check
# Contrôle 17.5.5 : Vérifier la politique "Audit Other Logon/Logoff Events" via PowerShell
def check_audit_other_logon_logoff_events():
    """
    Vérifie si la politique 'Audit Other Logon/Logoff Events' est configurée pour inclure 'Success and Failure' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Other Logon/Logoff Events"
        ps_command = '''
        Get-AuditPolicy -Category "Logon/Logoff" | Where-Object {$_.Subcategory -eq "Other Logon/Logoff Events"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success and Failure" in output:
            print(f"{GREEN}17.5.5 Audit Other Logon/Logoff Events: Conforme (Valeur Relevée: Success and Failure){RESET}")
        else:
            print(f"{RED}17.5.5 Audit Other Logon/Logoff Events: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.5.5 : {e}{RESET}")

@compliance_check
# Contrôle 17.5.6 : Vérifier la politique "Audit Special Logon" via PowerShell
def check_audit_special_logon():
    """
    Vérifie si la politique 'Audit Special Logon' est configurée pour inclure 'Success' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Special Logon"
        ps_command = '''
        Get-AuditPolicy -Category "Logon/Logoff" | Where-Object {$_.Subcategory -eq "Special Logon"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success" in output:
            print(f"{GREEN}17.5.6 Audit Special Logon: Conforme (Valeur Relevée: Success){RESET}")
        else:
            print(f"{RED}17.5.6 Audit Special Logon: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.5.6 : {e}{RESET}")

@compliance_check
# Contrôle 17.6.1 : Vérifier la politique "Audit Detailed File Share" via PowerShell
def check_audit_detailed_file_share():
    """
    Vérifie si la politique 'Audit Detailed File Share' est configurée pour inclure 'Failure' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Detailed File Share"
        ps_command = '''
        Get-AuditPolicy -Category "Object Access" | Where-Object {$_.Subcategory -eq "Detailed File Share"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Failure" in output:
            print(f"{GREEN}17.6.1 Audit Detailed File Share: Conforme (Valeur Relevée: Failure){RESET}")
        else:
            print(f"{RED}17.6.1 Audit Detailed File Share: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.6.1 : {e}{RESET}")

@compliance_check
# Contrôle 17.6.2 : Vérifier la politique "Audit File Share" via PowerShell
def check_audit_file_share():
    """
    Vérifie si la politique 'Audit File Share' est configurée pour inclure 'Success and Failure' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "File Share"
        ps_command = '''
        Get-AuditPolicy -Category "Object Access" | Where-Object {$_.Subcategory -eq "File Share"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success and Failure" in output:
            print(f"{GREEN}17.6.2 Audit File Share: Conforme (Valeur Relevée: Success and Failure){RESET}")
        else:
            print(f"{RED}17.6.2 Audit File Share: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.6.2 : {e}{RESET}")

@compliance_check
# Contrôle 17.6.3 : Vérifier la politique "Audit Other Object Access Events" via PowerShell
def check_audit_other_object_access_events():
    """
    Vérifie si la politique 'Audit Other Object Access Events' est configurée pour inclure 'Success and Failure' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Other Object Access Events"
        ps_command = '''
        Get-AuditPolicy -Category "Object Access" | Where-Object {$_.Subcategory -eq "Audit Other Object Access Events"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success and Failure" in output:
            print(f"{GREEN}17.6.3 Audit Other Object Access Events: Conforme (Valeur Relevée: Success and Failure){RESET}")
        else:
            print(f"{RED}17.6.3 Audit Other Object Access Events: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.6.3 : {e}{RESET}")

@compliance_check
# Contrôle 17.6.4 : Vérifier la politique "Audit Removable Storage" via PowerShell
def check_audit_removable_storage():
    """
    Vérifie si la politique 'Audit Removable Storage' est configurée pour inclure 'Success and Failure' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Removable Storage"
        ps_command = '''
        Get-AuditPolicy -Category "Object Access" | Where-Object {$_.Subcategory -eq "Removable Storage"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success and Failure" in output:
            print(f"{GREEN}17.6.4 Audit Removable Storage: Conforme (Valeur Relevée: Success and Failure){RESET}")
        else:
            print(f"{RED}17.6.4 Audit Removable Storage: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.6.4 : {e}{RESET}")

@compliance_check
# Contrôle 17.7.1 : Vérifier la politique "Audit Audit Policy Change" via PowerShell
def check_audit_audit_policy_change():
    """
    Vérifie si la politique 'Audit Audit Policy Change' est configurée pour inclure 'Success' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Audit Policy Change"
        ps_command = '''
        Get-AuditPolicy -Category "Policy Change" | Where-Object {$_.Subcategory -eq "Audit Policy Change"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success" in output:
            print(f"{GREEN}17.7.1 Audit Audit Policy Change: Conforme (Valeur Relevée: Success){RESET}")
        else:
            print(f"{RED}17.7.1 Audit Audit Policy Change: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.7.1 : {e}{RESET}")

@compliance_check
# Contrôle 17.7.2 : Vérifier la politique "Audit Authentication Policy Change" via PowerShell
def check_audit_authentication_policy_change():
    """
    Vérifie si la politique 'Audit Authentication Policy Change' est configurée pour inclure 'Success' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Authentication Policy Change"
        ps_command = '''
        Get-AuditPolicy -Category "Policy Change" | Where-Object {$_.Subcategory -eq "Authentication Policy Change"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success" in output:
            print(f"{GREEN}17.7.2 Audit Authentication Policy Change: Conforme (Valeur Relevée: Success){RESET}")
        else:
            print(f"{RED}17.7.2 Audit Authentication Policy Change: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.7.2 : {e}{RESET}")

@compliance_check
# Contrôle 17.7.3 : Vérifier la politique "Audit Authorization Policy Change" via PowerShell
def check_audit_authorization_policy_change():
    """
    Vérifie si la politique 'Audit Authorization Policy Change' est configurée pour inclure 'Success' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Authorization Policy Change"
        ps_command = '''
        Get-AuditPolicy -Category "Policy Change" | Where-Object {$_.Subcategory -eq "Authorization Policy Change"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success" in output:
            print(f"{GREEN}17.7.3 Audit Authorization Policy Change: Conforme (Valeur Relevée: Success){RESET}")
        else:
            print(f"{RED}17.7.3 Audit Authorization Policy Change: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.7.3 : {e}{RESET}")

@compliance_check
# Contrôle 17.7.4 : Vérifier la politique "Audit MPSSVC Rule-Level Policy Change" via PowerShell
def check_audit_mpssvc_rule_level_policy_change():
    """
    Vérifie si la politique 'Audit MPSSVC Rule-Level Policy Change' est configurée pour inclure 'Success and Failure' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "MPSSVC Rule-Level Policy Change"
        ps_command = '''
        Get-AuditPolicy -Category "Policy Change" | Where-Object {$_.Subcategory -eq "MPSSVC Rule-Level Policy Change"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success and Failure" in output:
            print(f"{GREEN}17.7.4 Audit MPSSVC Rule-Level Policy Change: Conforme (Valeur Relevée: Success and Failure){RESET}")
        else:
            print(f"{RED}17.7.4 Audit MPSSVC Rule-Level Policy Change: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.7.4 : {e}{RESET}")

@compliance_check
# Contrôle 17.7.5 : Vérifier la politique "Audit Other Policy Change Events" via PowerShell
def check_audit_other_policy_change_events():
    """
    Vérifie si la politique 'Audit Other Policy Change Events' est configurée pour inclure 'Failure' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Other Policy Change Events"
        ps_command = '''
        Get-AuditPolicy -Category "Policy Change" | Where-Object {$_.Subcategory -eq "Other Policy Change Events"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Failure" in output:
            print(f"{GREEN}17.7.5 Audit Other Policy Change Events: Conforme (Valeur Relevée: Failure){RESET}")
        else:
            print(f"{RED}17.7.5 Audit Other Policy Change Events: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.7.5 : {e}{RESET}")

@compliance_check
# Contrôle 17.8.1 : Vérifier la politique "Audit Sensitive Privilege Use" via PowerShell
def check_audit_sensitive_privilege_use():
    """
    Vérifie si la politique 'Audit Sensitive Privilege Use' est configurée pour inclure 'Success and Failure' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Sensitive Privilege Use"
        ps_command = '''
        Get-AuditPolicy -Category "Privilege Use" | Where-Object {$_.Subcategory -eq "Sensitive Privilege Use"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success and Failure" in output:
            print(f"{GREEN}17.8.1 Audit Sensitive Privilege Use: Conforme (Valeur Relevée: Success and Failure){RESET}")
        else:
            print(f"{RED}17.8.1 Audit Sensitive Privilege Use: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.8.1 : {e}{RESET}")

@compliance_check
# Contrôle 17.9.1 : Vérifier la politique "Audit IPsec Driver" via PowerShell
def check_audit_ipsec_driver():
    """
    Vérifie si la politique 'Audit IPsec Driver' est configurée pour inclure 'Success and Failure' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "IPsec Driver"
        ps_command = '''
        Get-AuditPolicy -Category "System" | Where-Object {$_.Subcategory -eq "IPsec Driver"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success and Failure" in output:
            print(f"{GREEN}17.9.1 Audit IPsec Driver: Conforme (Valeur Relevée: Success and Failure){RESET}")
        else:
            print(f"{RED}17.9.1 Audit IPsec Driver: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.9.1 : {e}{RESET}")

@compliance_check
# Contrôle 17.9.2 : Vérifier la politique "Audit Other System Events" via PowerShell
def check_audit_other_system_events():
    """
    Vérifie si la politique 'Audit Other System Events' est configurée pour inclure 'Success and Failure' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Other System Events"
        ps_command = '''
        Get-AuditPolicy -Category "System" | Where-Object {$_.Subcategory -eq "Other System Events"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success and Failure" in output:
            print(f"{GREEN}17.9.2 Audit Other System Events: Conforme (Valeur Relevée: Success and Failure){RESET}")
        else:
            print(f"{RED}17.9.2 Audit Other System Events: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.9.2 : {e}{RESET}")

@compliance_check
# Contrôle 17.9.3 : Vérifier la politique "Audit Security State Change" via PowerShell
def check_audit_security_state_change():
    """
    Vérifie si la politique 'Audit Security State Change' est configurée pour inclure 'Success' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Security State Change"
        ps_command = '''
        Get-AuditPolicy -Category "System" | Where-Object {$_.Subcategory -eq "Security State Change"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success" in output:
            print(f"{GREEN}17.9.3 Audit Security State Change: Conforme (Valeur Relevée: Success){RESET}")
        else:
            print(f"{RED}17.9.3 Audit Security State Change: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.9.3 : {e}{RESET}")

@compliance_check
# Contrôle 17.9.4 : Vérifier la politique "Audit Security System Extension" via PowerShell
def check_audit_security_system_extension():
    """
    Vérifie si la politique 'Audit Security System Extension' est configurée pour inclure 'Success' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "Security System Extension"
        ps_command = '''
        Get-AuditPolicy -Category "System" | Where-Object {$_.Subcategory -eq "Security System Extension"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success" in output:
            print(f"{GREEN}17.9.4 Audit Security System Extension: Conforme (Valeur Relevée: Success){RESET}")
        else:
            print(f"{RED}17.9.4 Audit Security System Extension: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.9.4 : {e}{RESET}")

@compliance_check
# Contrôle 17.9.5 : Vérifier la politique "Audit System Integrity" via PowerShell
def check_audit_system_integrity():
    """
    Vérifie si la politique 'Audit System Integrity' est configurée pour inclure 'Success and Failure' en utilisant PowerShell.
    """
    try:
        # Commande PowerShell pour vérifier la configuration de "System Integrity"
        ps_command = '''
        Get-AuditPolicy -Category "System" | Where-Object {$_.Subcategory -eq "System Integrity"}
        '''
        
        # Exécuter le script PowerShell
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        # Vérifier la sortie
        output = result.stdout.strip()

        if "Success and Failure" in output:
            print(f"{GREEN}17.9.5 Audit System Integrity: Conforme (Valeur Relevée: Success and Failure){RESET}")
        else:
            print(f"{RED}17.9.5 Audit System Integrity: Non conforme ou non trouvé dans les événements{RESET}")

    except subprocess.CalledProcessError as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 17.9.5 : {e}{RESET}")

@compliance_check
# Contrôle 18.1.1.1 : Vérifier la politique "Prevent enabling lock screen camera" via le registre
def check_prevent_lock_screen_camera():
    """
    Vérifie si la politique 'Prevent enabling lock screen camera' est configurée sur 'Enabled' 
    en vérifiant la valeur du registre.
    """
    try:
        # Ouvrir la clé de registre où la politique est définie
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Personalization"
        
        try:
            # Tenter d'ouvrir la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            
            # Lire la valeur de la clé NoLockScreenCamera
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "NoLockScreenCamera")
                winreg.CloseKey(reg_key)

                # Vérifier si la valeur est définie sur 1 (activé)
                if value == 1:
                    print(f"{GREEN}18.1.1.1 Prevent enabling lock screen camera: Conforme (Valeur Relevée: Enabled){RESET}")
                else:
                    print(f"{RED}18.1.1.1 Prevent enabling lock screen camera: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.1.1.1 Prevent enabling lock screen camera: Clé 'NoLockScreenCamera' non trouvée dans le registre. Cette politique peut ne pas être appliquée via GPO ou manuellement.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé de registre '{registry_path}' n'existe pas. La politique 'Prevent enabling lock screen camera' n'a peut-être pas été appliquée via GPO. Veuillez vérifier la configuration de la politique sur la machine.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de la vérification du contrôle 18.1.1.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.1.1.2 : Vérifier la politique "Prevent enabling lock screen slide show" via le registre
def check_prevent_lock_screen_slide_show():
    """
    Vérifie si la politique 'Prevent enabling lock screen slide show' est configurée sur 'Enabled' 
    en vérifiant la valeur du registre.
    """
    try:
        # Ouvrir la clé de registre où la politique est définie
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Personalization"
        
        try:
            # Tenter d'ouvrir la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            
            # Lire la valeur de la clé NoLockScreenSlideshow
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "NoLockScreenSlideshow")
                winreg.CloseKey(reg_key)

                # Vérifier si la valeur est définie sur 1 (activé)
                if value == 1:
                    print(f"{GREEN}18.1.1.2 Prevent enabling lock screen slide show: Conforme (Valeur Relevée: Enabled){RESET}")
                else:
                    print(f"{RED}18.1.1.2 Prevent enabling lock screen slide show: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.1.1.2 Prevent enabling lock screen slide show: Clé 'NoLockScreenSlideshow' non trouvée dans le registre. Cette politique peut ne pas être appliquée via GPO ou manuellement.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé de registre '{registry_path}' n'existe pas. La politique 'Prevent enabling lock screen slide show' n'a peut-être pas été appliquée via GPO. Veuillez vérifier la configuration de la politique sur la machine.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de la vérification du contrôle 18.1.1.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.1.2.2 : Vérifier la politique "Allow users to enable online speech recognition services" via le registre
def check_allow_online_speech_recognition():
    """
    Vérifie si la politique 'Allow users to enable online speech recognition services' est configurée sur 'Disabled' 
    en vérifiant la valeur du registre.
    """
    try:
        # Ouvrir la clé de registre où la politique est définie
        registry_path = r"SOFTWARE\Policies\Microsoft\InputPersonalization"
        
        try:
            # Tenter d'ouvrir la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            
            # Lire la valeur de la clé AllowInputPersonalization
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "AllowInputPersonalization")
                winreg.CloseKey(reg_key)

                # Vérifier si la valeur est définie sur 0 (désactivé)
                if value == 0:
                    print(f"{GREEN}18.1.2.2 Allow users to enable online speech recognition services: Conforme (Valeur Relevée: Disabled){RESET}")
                else:
                    print(f"{RED}18.1.2.2 Allow users to enable online speech recognition services: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.1.2.2 Allow users to enable online speech recognition services: Clé 'AllowInputPersonalization' non trouvée dans le registre. Cette politique peut ne pas être appliquée via GPO ou manuellement.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé de registre '{registry_path}' n'existe pas. La politique 'Allow users to enable online speech recognition services' n'a peut-être pas été appliquée via GPO. Veuillez vérifier la configuration de la politique sur la machine.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de la vérification du contrôle 18.1.2.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.1.3 : Vérifier la politique "Allow Online Tips" via le registre
def check_allow_online_tips():
    """
    Vérifie si la politique 'Allow Online Tips' est configurée sur 'Disabled' 
    en vérifiant la valeur du registre.
    """
    try:
        # Ouvrir la clé de registre où la politique est définie
        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        
        try:
            # Tenter d'ouvrir la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            
            # Lire la valeur de la clé AllowOnlineTips
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "AllowOnlineTips")
                winreg.CloseKey(reg_key)

                # Vérifier si la valeur est définie sur 0 (désactivé)
                if value == 0:
                    print(f"{GREEN}18.1.3 Allow Online Tips: Conforme (Valeur Relevée: Disabled){RESET}")
                else:
                    print(f"{RED}18.1.3 Allow Online Tips: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.1.3 Allow Online Tips: Clé 'AllowOnlineTips' non trouvée dans le registre. Cette politique peut ne pas être appliquée via GPO ou manuellement.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé de registre '{registry_path}' n'existe pas. La politique 'Allow Online Tips' n'a peut-être pas été appliquée via GPO. Veuillez vérifier la configuration de la politique sur la machine.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de la vérification du contrôle 18.1.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.4.1 : Vérifier la politique "Configure RPC packet level privacy setting for incoming connections" via le registre
def check_rpc_packet_level_privacy():
    """
    Vérifie si la politique 'Configure RPC packet level privacy setting for incoming connections' 
    est configurée sur 'Enabled' en vérifiant la valeur du registre.
    """
    try:
        # Ouvrir la clé de registre où la politique est définie
        registry_path = r"SYSTEM\CurrentControlSet\Control\Print"
        
        try:
            # Tenter d'ouvrir la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            
            # Lire la valeur de la clé RpcAuthnLevelPrivacyEnabled
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "RpcAuthnLevelPrivacyEnabled")
                winreg.CloseKey(reg_key)

                # Vérifier si la valeur est définie sur 1 (activé)
                if value == 1:
                    print(f"{GREEN}18.4.1 Configure RPC packet level privacy setting for incoming connections: Conforme (Valeur Relevée: Enabled){RESET}")
                else:
                    print(f"{RED}18.4.1 Configure RPC packet level privacy setting for incoming connections: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.4.1 Configure RPC packet level privacy setting for incoming connections: Clé 'RpcAuthnLevelPrivacyEnabled' non trouvée dans le registre. Cette politique peut ne pas être appliquée via GPO ou manuellement.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé de registre '{registry_path}' n'existe pas. La politique 'Configure RPC packet level privacy setting for incoming connections' n'a peut-être pas été appliquée via GPO. Veuillez vérifier la configuration de la politique sur la machine.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de la vérification du contrôle 18.4.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.4.2 : Vérifier la politique "Configure SMB v1 client driver" via le registre
def check_smb_v1_client_driver():
    """
    Vérifie si la politique 'Configure SMB v1 client driver' est configurée sur 'Enabled: Disable driver (recommended)' 
    en vérifiant la valeur du registre.
    """
    try:
        # Ouvrir la clé de registre où la politique est définie
        registry_path = r"SYSTEM\CurrentControlSet\Services\mrxsmb10"
        
        try:
            # Tenter d'ouvrir la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            
            # Lire la valeur de la clé Start
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "Start")
                winreg.CloseKey(reg_key)

                # Vérifier si la valeur est définie sur 4 (désactiver SMBv1)
                if value == 4:
                    print(f"{GREEN}18.4.2 Configure SMB v1 client driver: Conforme (Valeur Relevée: Disabled driver){RESET}")
                else:
                    print(f"{RED}18.4.2 Configure SMB v1 client driver: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.4.2 Configure SMB v1 client driver: Clé 'Start' non trouvée dans le registre. Cette politique peut ne pas être appliquée via GPO ou manuellement.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé de registre '{registry_path}' n'existe pas. La politique 'Configure SMB v1 client driver' n'a peut-être pas été appliquée via GPO. Veuillez vérifier la configuration de la politique sur la machine.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de la vérification du contrôle 18.4.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.4.3 : Vérifier la politique "Configure SMB v1 server" via le registre
def check_smb_v1_server():
    """
    Vérifie si la politique 'Configure SMB v1 server' est configurée sur 'Disabled' 
    en vérifiant la valeur du registre.
    """
    try:
        # Ouvrir la clé de registre où la politique est définie
        registry_path = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        
        try:
            # Tenter d'ouvrir la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            
            # Lire la valeur de la clé SMB1
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "SMB1")
                winreg.CloseKey(reg_key)

                # Vérifier si la valeur est définie sur 0 (désactivé)
                if value == 0:
                    print(f"{GREEN}18.4.3 Configure SMB v1 server: Conforme (Valeur Relevée: Disabled){RESET}")
                else:
                    print(f"{RED}18.4.3 Configure SMB v1 server: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.4.3 Configure SMB v1 server: Clé 'SMB1' non trouvée dans le registre. Cette politique peut ne pas être appliquée via GPO ou manuellement.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé de registre '{registry_path}' n'existe pas. La politique 'Configure SMB v1 server' n'a peut-être pas été appliquée via GPO. Veuillez vérifier la configuration de la politique sur la machine.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de la vérification du contrôle 18.4.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.4.4 : Vérifier la politique "Enable Certificate Padding" via le registre
def check_enable_certificate_padding():
    """
    Vérifie si la politique 'Enable Certificate Padding' est configurée sur 'Enabled' 
    en vérifiant la valeur du registre.
    """
    try:
        # Ouvrir la clé de registre où la politique est définie
        registry_path = r"SOFTWARE\Microsoft\Cryptography\Wintrust\Config"
        
        try:
            # Tenter d'ouvrir la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            
            # Lire la valeur de la clé EnableCertPaddingCheck
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "EnableCertPaddingCheck")
                winreg.CloseKey(reg_key)

                # Vérifier si la valeur est définie sur 1 (activé)
                if value == 1:
                    print(f"{GREEN}18.4.4 Enable Certificate Padding: Conforme (Valeur Relevée: Enabled){RESET}")
                else:
                    print(f"{RED}18.4.4 Enable Certificate Padding: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.4.4 Enable Certificate Padding: Clé 'EnableCertPaddingCheck' non trouvée dans le registre. Cette politique peut ne pas être appliquée via GPO ou manuellement.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé de registre '{registry_path}' n'existe pas. La politique 'Enable Certificate Padding' n'a peut-être pas été appliquée via GPO. Veuillez vérifier la configuration de la politique sur la machine.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de la vérification du contrôle 18.4.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.4.5 : Vérifier "Enable Structured Exception Handling Overwrite Protection (SEHOP)" via le registre
def check_sehop():
    try:
        registry_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "DisableExceptionChainValidation")
                winreg.CloseKey(reg_key)

                if value == 0:
                    print(f"{GREEN}18.4.5 Enable SEHOP: Conforme (Valeur Relevée: Enabled){RESET}")
                else:
                    print(f"{RED}18.4.5 Enable SEHOP: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.4.5 Enable SEHOP: Clé 'DisableExceptionChainValidation' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.4.6 : Vérifier "NetBT NodeType configuration" via le registre
def check_netbt_node_type():
    try:
        registry_path = r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "NodeType")
                winreg.CloseKey(reg_key)

                if value == 2:
                    print(f"{GREEN}18.4.6 NetBT NodeType configuration: Conforme (Valeur Relevée: P-node){RESET}")
                else:
                    print(f"{RED}18.4.6 NetBT NodeType configuration: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.4.6 NetBT NodeType configuration: Clé 'NodeType' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.4.7 : Vérifier "WDigest Authentication" via le registre
def check_wdigest_authentication():
    try:
        registry_path = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "UseLogonCredential")
                winreg.CloseKey(reg_key)

                if value == 0:
                    print(f"{GREEN}18.4.7 WDigest Authentication: Conforme (Valeur Relevée: Disabled){RESET}")
                else:
                    print(f"{RED}18.4.7 WDigest Authentication: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.4.7 WDigest Authentication: Clé 'UseLogonCredential' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.5.1 : Vérifier "MSS: (AutoAdminLogon) Enable Automatic Logon" via le registre
def check_auto_admin_logon():
    try:
        registry_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "AutoAdminLogon")
                winreg.CloseKey(reg_key)

                if value == "0":
                    print(f"{GREEN}18.5.1 MSS: (AutoAdminLogon) Enable Automatic Logon: Conforme (Valeur Relevée: Disabled){RESET}")
                else:
                    print(f"{RED}18.5.1 MSS: (AutoAdminLogon) Enable Automatic Logon: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.5.1 MSS: (AutoAdminLogon) Enable Automatic Logon: Clé 'AutoAdminLogon' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.5.2 : Vérifier "MSS: (DisableIPSourceRouting IPv6) IP source routing protection level" via le registre
def check_disable_ip_source_routing():
    try:
        registry_path = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "DisableIPSourceRouting")
                winreg.CloseKey(reg_key)

                if value == 2:
                    print(f"{GREEN}18.5.2 MSS: (DisableIPSourceRouting IPv6) IP source routing protection level: Conforme (Valeur Relevée: Highest protection, source routing is completely disabled){RESET}")
                else:
                    print(f"{RED}18.5.2 MSS: (DisableIPSourceRouting IPv6) IP source routing protection level: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.5.2 MSS: (DisableIPSourceRouting IPv6) IP source routing protection level: Clé 'DisableIPSourceRouting' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")
        
@compliance_check
# Contrôle 18.5.3 : Vérifier "MSS: (DisableIPSourceRouting) IP source routing protection level" via le registre
def check_disable_ip_source_routing_tcpip():
    try:
        registry_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "DisableIPSourceRouting")
                winreg.CloseKey(reg_key)

                if value == 2:
                    print(f"{GREEN}18.5.3 MSS: (DisableIPSourceRouting) IP source routing protection level: Conforme (Valeur Relevée: Highest protection, source routing is completely disabled){RESET}")
                else:
                    print(f"{RED}18.5.3 MSS: (DisableIPSourceRouting) IP source routing protection level: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.5.3 MSS: (DisableIPSourceRouting) IP source routing protection level: Clé 'DisableIPSourceRouting' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")
        
@compliance_check
# Contrôle 18.5.4 : Vérifier "MSS: (DisableSavePassword) Prevent the dial-up password from being saved" via le registre
def check_disable_save_password():
    try:
        registry_path = r"SYSTEM\CurrentControlSet\Services\RasMan\Parameters"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "DisableSavePassword")
                winreg.CloseKey(reg_key)

                if value == 1:
                    print(f"{GREEN}18.5.4 MSS: (DisableSavePassword) Prevent the dial-up password from being saved: Conforme (Valeur Relevée: Enabled){RESET}")
                else:
                    print(f"{RED}18.5.4 MSS: (DisableSavePassword) Prevent the dial-up password from being saved: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.5.4 MSS: (DisableSavePassword) Prevent the dial-up password from being saved: Clé 'DisableSavePassword' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.5.5 : Vérifier "MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes" via le registre
def check_enable_icmp_redirect():
    try:
        registry_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "EnableICMPRedirect")
                winreg.CloseKey(reg_key)

                if value == 0:
                    print(f"{GREEN}18.5.5 MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes: Conforme (Valeur Relevée: Disabled){RESET}")
                else:
                    print(f"{RED}18.5.5 MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.5.5 MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes: Clé 'EnableICMPRedirect' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.5.6 : Vérifier "MSS: (KeepAliveTime) How often keep-alive packets are sent" via le registre
def check_keep_alive_time():
    try:
        registry_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "KeepAliveTime")
                winreg.CloseKey(reg_key)

                if value == 300000:
                    print(f"{GREEN}18.5.6 MSS: (KeepAliveTime) How often keep-alive packets are sent: Conforme (Valeur Relevée: 300,000 ms ou 5 minutes){RESET}")
                else:
                    print(f"{RED}18.5.6 MSS: (KeepAliveTime) How often keep-alive packets are sent: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.5.6 MSS: (KeepAliveTime) How often keep-alive packets are sent: Clé 'KeepAliveTime' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.5.7 : Vérifier "MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers" via le registre
def check_no_name_release_on_demand():
    try:
        registry_path = r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "NoNameReleaseOnDemand")
                winreg.CloseKey(reg_key)

                if value == 1:
                    print(f"{GREEN}18.5.7 MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers: Conforme (Valeur Relevée: Enabled){RESET}")
                else:
                    print(f"{RED}18.5.7 MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.5.7 MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers: Clé 'NoNameReleaseOnDemand' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.5.8 : Vérifier "MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses" via le registre
def check_perform_router_discovery():
    try:
        registry_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "PerformRouterDiscovery")
                winreg.CloseKey(reg_key)

                if value == 0:
                    print(f"{GREEN}18.5.8 MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses: Conforme (Valeur Relevée: Disabled){RESET}")
                else:
                    print(f"{RED}18.5.8 MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.5.8 MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses: Clé 'PerformRouterDiscovery' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.5.9 : Vérifier "MSS: (SafeDllSearchMode) Enable Safe DLL search mode" via le registre
def check_safe_dll_search_mode():
    try:
        registry_path = r"SYSTEM\CurrentControlSet\Control\Session Manager"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "SafeDllSearchMode")
                winreg.CloseKey(reg_key)

                if value == 1:
                    print(f"{GREEN}18.5.9 MSS: (SafeDllSearchMode) Enable Safe DLL search mode: Conforme (Valeur Relevée: Enabled){RESET}")
                else:
                    print(f"{RED}18.5.9 MSS: (SafeDllSearchMode) Enable Safe DLL search mode: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.5.9 MSS: (SafeDllSearchMode) Enable Safe DLL search mode: Clé 'SafeDllSearchMode' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.5.10 : Vérifier "MSS: (ScreenSaverGracePeriod) The time before the screen saver grace period expires" via le registre
def check_screensaver_grace_period():
    try:
        registry_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "ScreenSaverGracePeriod")
                winreg.CloseKey(reg_key)

                if value <= 5:
                    print(f"{GREEN}18.5.10 MSS: (ScreenSaverGracePeriod) The time before the screen saver grace period expires: Conforme (Valeur Relevée: {value} secondes){RESET}")
                else:
                    print(f"{RED}18.5.10 MSS: (ScreenSaverGracePeriod) The time before the screen saver grace period expires: Non conforme (Valeur Relevée: {value} secondes){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.5.10 MSS: (ScreenSaverGracePeriod) The time before the screen saver grace period expires: Clé 'ScreenSaverGracePeriod' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.5.11 : Vérifier "MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted" via le registre
def check_tcp_max_data_retransmissions_ipv6():
    try:
        registry_path = r"SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "TcpMaxDataRetransmissions")
                winreg.CloseKey(reg_key)

                if value == 3:
                    print(f"{GREEN}18.5.11 MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted: Conforme (Valeur Relevée: 3){RESET}")
                else:
                    print(f"{RED}18.5.11 MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.5.11 MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted: Clé 'TcpMaxDataRetransmissions' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.5.12 : Vérifier "MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted" via le registre
def check_tcp_max_data_retransmissions():
    try:
        registry_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "TcpMaxDataRetransmissions")
                winreg.CloseKey(reg_key)

                if value == 3:
                    print(f"{GREEN}18.5.12 MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted: Conforme (Valeur Relevée: 3){RESET}")
                else:
                    print(f"{RED}18.5.12 MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.5.12 MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted: Clé 'TcpMaxDataRetransmissions' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.5.13 : Vérifier "MSS: (WarningLevel) Percentage threshold for the security event log" via le registre
def check_warning_level():
    try:
        registry_path = r"SYSTEM\CurrentControlSet\Services\Eventlog\Security"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "WarningLevel")
                winreg.CloseKey(reg_key)

                if value <= 90:
                    print(f"{GREEN}18.5.13 MSS: (WarningLevel) Percentage threshold for the security event log: Conforme (Valeur Relevée: {value}%){RESET}")
                else:
                    print(f"{RED}18.5.13 MSS: (WarningLevel) Percentage threshold for the security event log: Non conforme (Valeur Relevée: {value}%){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.5.13 MSS: (WarningLevel) Percentage threshold for the security event log: Clé 'WarningLevel' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.6.4.1 : Vérifier "Configure DNS over HTTPS (DoH) name resolution" via le registre
def check_doh_policy():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "DoHPolicy")
                winreg.CloseKey(reg_key)

                if value == 2 or value == 3:
                    print(f"{GREEN}18.6.4.1 Configure DNS over HTTPS (DoH) name resolution: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.6.4.1 Configure DNS over HTTPS (DoH) name resolution: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.6.4.1 Configure DNS over HTTPS (DoH) name resolution: Clé 'DoHPolicy' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.6.5.1 : Vérifier "Enable Font Providers" via le registre
def check_enable_font_providers():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\System"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "EnableFontProviders")
                winreg.CloseKey(reg_key)

                if value == 0:
                    print(f"{GREEN}18.6.5.1 Enable Font Providers: Conforme (Valeur Relevée: Disabled){RESET}")
                else:
                    print(f"{RED}18.6.5.1 Enable Font Providers: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.6.5.1 Enable Font Providers: Clé 'EnableFontProviders' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.6.8.1 : Vérifier "Enable insecure guest logons" via le registre
def check_insecure_guest_logons():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "AllowInsecureGuestAuth")
                winreg.CloseKey(reg_key)

                if value == 0:
                    print(f"{GREEN}18.6.8.1 Enable insecure guest logons: Conforme (Valeur Relevée: Disabled){RESET}")
                else:
                    print(f"{RED}18.6.8.1 Enable insecure guest logons: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.6.8.1 Enable insecure guest logons: Clé 'AllowInsecureGuestAuth' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.6.9.1 : Vérifier "Turn on Mapper I/O (LLTDIO) driver" via le registre
def check_mapper_io_driver():
    try:
        registry_paths = [
            r"SOFTWARE\Policies\Microsoft\Windows\LLTD:AllowLLTDIOOnDomain",
            r"SOFTWARE\Policies\Microsoft\Windows\LLTD:AllowLLTDIOOnPublicNet",
            r"SOFTWARE\Policies\Microsoft\Windows\LLTD:EnableLLTDIO",
            r"SOFTWARE\Policies\Microsoft\Windows\LLTD:ProhibitLLTDIOOnPrivateNet"
        ]

        all_compliant = True

        for path in registry_paths:
            try:
                reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                value, regtype = winreg.QueryValueEx(reg_key, path.split(":")[-1])
                winreg.CloseKey(reg_key)

                if value != 0:
                    print(f"{RED}18.6.9.1 Turn on Mapper I/O (LLTDIO) driver: Non conforme (Valeur Relevée: {value} pour {path}){RESET}")
                    all_compliant = False
            except FileNotFoundError:
                print(f"{RED}18.6.9.1 Turn on Mapper I/O (LLTDIO) driver: Clé non trouvée pour {path}{RESET}")
                all_compliant = False

        if all_compliant:
            print(f"{GREEN}18.6.9.1 Turn on Mapper I/O (LLTDIO) driver: Conforme (Toutes les clés sont désactivées){RESET}")

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.6.9.2 : Vérifier "Turn on Responder (RSPNDR) driver" via le registre
def check_responder_driver():
    try:
        registry_paths = [
            r"SOFTWARE\Policies\Microsoft\Windows\LLTD:AllowRspndrOnDomain",
            r"SOFTWARE\Policies\Microsoft\Windows\LLTD:AllowRspndrOnPublicNet",
            r"SOFTWARE\Policies\Microsoft\Windows\LLTD:EnableRspndr",
            r"SOFTWARE\Policies\Microsoft\Windows\LLTD:ProhibitRspndrOnPrivateNet"
        ]

        all_compliant = True

        for path in registry_paths:
            try:
                reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                value, regtype = winreg.QueryValueEx(reg_key, path.split(":")[-1])
                winreg.CloseKey(reg_key)

                if value != 0:
                    print(f"{RED}18.6.9.2 Turn on Responder (RSPNDR) driver: Non conforme (Valeur Relevée: {value} pour {path}){RESET}")
                    all_compliant = False
            except FileNotFoundError:
                print(f"{RED}18.6.9.2 Turn on Responder (RSPNDR) driver: Clé non trouvée pour {path}{RESET}")
                all_compliant = False

        if all_compliant:
            print(f"{GREEN}18.6.9.2 Turn on Responder (RSPNDR) driver: Conforme (Toutes les clés sont désactivées){RESET}")

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.6.10.2 : Vérifier "Turn off Microsoft Peer-to-Peer Networking Services" via le registre
def check_turn_off_peer_to_peer_services():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Peernet"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "Disabled")
                winreg.CloseKey(reg_key)

                if value == 1:
                    print(f"{GREEN}18.6.10.2 Turn off Microsoft Peer-to-Peer Networking Services: Conforme (Valeur Relevée: Enabled){RESET}")
                else:
                    print(f"{RED}18.6.10.2 Turn off Microsoft Peer-to-Peer Networking Services: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.6.10.2 Turn off Microsoft Peer-to-Peer Networking Services: Clé 'Disabled' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}La clé '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.6.11.2 : Vérifier "Prohibit installation and configuration of Network Bridge" via le registre
def check_prohibit_network_bridge():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\NetworkConnections"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "NC_AllowNetBridge_NLA")
                winreg.CloseKey(reg_key)

                if value == 0:
                    print(f"{GREEN}18.6.11.2 Prohibit installation and configuration of Network Bridge: Conforme (Valeur Relevée: Enabled){RESET}")
                else:
                    print(f"{RED}18.6.11.2 Prohibit installation and configuration of Network Bridge: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.6.11.2 Prohibit installation and configuration of Network Bridge: Clé 'NC_AllowNetBridge_NLA' non trouvée dans {registry_path}.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.6.11.2 Prohibit installation and configuration of Network Bridge: Clé de registre '{registry_path}' non trouvée.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")

@compliance_check
# Contrôle 18.6.11.3 : Vérifier "Prohibit use of Internet Connection Sharing" via le registre
def check_prohibit_internet_connection_sharing():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\NetworkConnections"
        
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, regtype = winreg.QueryValueEx(reg_key, "NC_ShowSharedAccessUI")
                winreg.CloseKey(reg_key)

                if value == 0:
                    print(f"{GREEN}18.6.11.3 Prohibit use of Internet Connection Sharing: Conforme (Valeur Relevée: Enabled){RESET}")
                else:
                    print(f"{RED}18.6.11.3 Prohibit use of Internet Connection Sharing: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.6.11.3 Prohibit use of Internet Connection Sharing: Clé 'NC_ShowSharedAccessUI' non trouvée dans {registry_path}.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.6.11.3 Prohibit use of Internet Connection Sharing: Clé de registre '{registry_path}' non trouvée.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur : {e}{RESET}")
        
@compliance_check
# Contrôle 18.6.14.1 : Vérifier "Hardened UNC Paths" via le registre
def check_hardened_unc_paths():
    try:
        registry_paths = [
            r"SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\*\NETLOGON",
            r"SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\*\SYSVOL"
        ]

        all_compliant = True

        for path in registry_paths:
            try:
                reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                try:
                    mutual_auth, _ = winreg.QueryValueEx(reg_key, "RequireMutualAuthentication")
                    integrity, _ = winreg.QueryValueEx(reg_key, "RequireIntegrity")
                    privacy, _ = winreg.QueryValueEx(reg_key, "RequirePrivacy")
                    winreg.CloseKey(reg_key)

                    # Vérification des conditions
                    if mutual_auth == 1 and integrity == 1 and privacy == 1:
                        print(f"{GREEN}18.6.14.1 Hardened UNC Paths: Conforme pour {path} (RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1){RESET}")
                    else:
                        print(f"{RED}18.6.14.1 Hardened UNC Paths: Non conforme pour {path} (Valeurs : RequireMutualAuthentication={mutual_auth}, RequireIntegrity={integrity}, RequirePrivacy={privacy}){RESET}")
                        all_compliant = False

                except FileNotFoundError:
                    print(f"{RED}18.6.14.1 Hardened UNC Paths: Clé de registre '{path}' non trouvée.{RESET}")
                    all_compliant = False

            except FileNotFoundError:
                print(f"{RED}18.6.14.1 Hardened UNC Paths: La clé de registre '{path}' n'existe pas dans le registre.{RESET}")
                all_compliant = False

        if all_compliant:
            print(f"{GREEN}18.6.14.1 Hardened UNC Paths: Conforme (Toutes les clés sont correctement configurées){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.6.14.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.6.20.1 : Vérifier "Configuration of wireless settings using Windows Connect Now" via le registre
def check_wireless_settings_windows_connect_now():
    try:
        registry_paths = [
            r"SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars:EnableRegistrars",
            r"SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars:DisableUPnPRegistrar",
            r"SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars:DisableInBand802DOT11Registrar",
            r"SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars:DisableFlashConfigRegistrar",
            r"SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars:DisableWPDRegistrar"
        ]

        all_compliant = True

        for path in registry_paths:
            try:
                reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                try:
                    value, _ = winreg.QueryValueEx(reg_key, path.split(":")[-1])
                    winreg.CloseKey(reg_key)

                    if value == 0:
                        print(f"{GREEN}18.6.20.1 Configuration of wireless settings using Windows Connect Now: Conforme pour {path} (Valeur Relevée: Disabled){RESET}")
                    else:
                        print(f"{RED}18.6.20.1 Configuration of wireless settings using Windows Connect Now: Non conforme pour {path} (Valeur Relevée: {value}){RESET}")
                        all_compliant = False

                except FileNotFoundError:
                    print(f"{RED}18.6.20.1 Configuration of wireless settings using Windows Connect Now: Clé de registre '{path}' non trouvée.{RESET}")
                    all_compliant = False

            except FileNotFoundError:
                print(f"{RED}18.6.20.1 Configuration of wireless settings using Windows Connect Now: La clé de registre '{path}' n'existe pas.{RESET}")
                all_compliant = False

        if all_compliant:
            print(f"{GREEN}18.6.20.1 Configuration of wireless settings using Windows Connect Now: Conforme (Toutes les clés sont correctement configurées){RESET}")

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.6.20.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.6.20.2 : Vérifier "Prohibit access of the Windows Connect Now wizards" via le registre
def check_prohibit_wcn_wizards():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WCN\UI"
        key_name = "DisableWcnUi"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                if value == 1:
                    print(f"{GREEN}18.6.20.2 Prohibit access of the Windows Connect Now wizards: Conforme (Valeur Relevée: Enabled){RESET}")
                else:
                    print(f"{RED}18.6.20.2 Prohibit access of the Windows Connect Now wizards: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.6.20.2 Prohibit access of the Windows Connect Now wizards: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.6.20.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.6.20.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.6.21.1 : Vérifier "Minimize the number of simultaneous connections to the Internet or a Windows Domain" via le registre
def check_minimize_connections():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
        key_name = "fMinimizeConnections"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                if value == 3:
                    print(f"{GREEN}18.6.21.1 Minimize the number of simultaneous connections to the Internet or a Windows Domain: Conforme (Valeur Relevée: 3 = Prevent Wi-Fi when on Ethernet){RESET}")
                else:
                    print(f"{RED}18.6.21.1 Minimize the number of simultaneous connections to the Internet or a Windows Domain: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.6.21.1 Minimize the number of simultaneous connections to the Internet or a Windows Domain: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.6.21.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.6.21.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.6.23.2.1 : Vérifier "Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services" via le registre
def check_auto_connect_open_hotspots():
    try:
        registry_path = r"SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
        key_name = "AutoConnectAllowedOEM"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                if value == 0:
                    print(f"{GREEN}18.6.23.2.1 Allow Windows to automatically connect to suggested open hotspots: Conforme (Valeur Relevée: Disabled){RESET}")
                else:
                    print(f"{RED}18.6.23.2.1 Allow Windows to automatically connect to suggested open hotspots: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.6.23.2.1 Allow Windows to automatically connect to suggested open hotspots: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.6.23.2.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.6.23.2.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.7.1 : Vérifier "Allow Print Spooler to accept client connections" via le registre
def check_print_spooler_remote_rpc():
    try:
        registry_path = r"Software\Policies\Microsoft\Windows NT\Printers"
        key_name = "RegisterSpoolerRemoteRpcEndPoint"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                if value == 2:
                    print(f"{GREEN}18.7.1 Allow Print Spooler to accept client connections: Conforme (Valeur Relevée: Disabled){RESET}")
                else:
                    print(f"{RED}18.7.1 Allow Print Spooler to accept client connections: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.7.1 Allow Print Spooler to accept client connections: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.7.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.7.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.7.2 : Vérifier "Configure Redirection Guard" via le registre
def check_redirection_guard():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Printers"
        key_name = "RedirectionguardPolicy"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                if value == 1:
                    print(f"{GREEN}18.7.2 Configure Redirection Guard: Conforme (Valeur Relevée: Enabled) Redirection Guard Enabled{RESET}")
                else:
                    print(f"{RED}18.7.2 Configure Redirection Guard: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.7.2 Configure Redirection Guard: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.7.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.7.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.7.3 : Vérifier "Configure RPC connection settings: Protocol to use for outgoing RPC connections" via le registre
def check_rpc_connection_protocol():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
        key_name = "RpcUseNamedPipeProtocol"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                if value == 0:
                    print(f"{GREEN}18.7.3 Configure RPC connection settings: Protocol to use for outgoing RPC connections: Conforme (Valeur Relevée: RPC over TCP){RESET}")
                else:
                    print(f"{RED}18.7.3 Configure RPC connection settings: Protocol to use for outgoing RPC connections: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.7.3 Configure RPC connection settings: Protocol to use for outgoing RPC connections: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.7.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.7.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.7.4 : Vérifier "Configure RPC connection settings: Use authentication for outgoing RPC connections" via le registre
def check_rpc_authentication():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
        key_name = "RpcAuthentication"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                if value == 0:
                    print(f"{GREEN}18.7.4 Configure RPC connection settings: Use authentication for outgoing RPC connections: Conforme (Valeur Relevée: Default){RESET}")
                else:
                    print(f"{RED}18.7.4 Configure RPC connection settings: Use authentication for outgoing RPC connections: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.7.4 Configure RPC connection settings: Use authentication for outgoing RPC connections: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.7.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.7.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.7.5 : Vérifier "Configure RPC listener settings: Protocols to allow for incoming RPC connections" via le registre
def check_rpc_listener_protocol():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
        key_name = "RpcProtocols"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                if value == 5:
                    print(f"{GREEN}18.7.5 Configure RPC listener settings: Protocols to allow for incoming RPC connections: Conforme (Valeur Relevée: RPC over TCP){RESET}")
                else:
                    print(f"{RED}18.7.5 Configure RPC listener settings: Protocols to allow for incoming RPC connections: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.7.5 Configure RPC listener settings: Protocols to allow for incoming RPC connections: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.7.5 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.7.5 : {e}{RESET}")

@compliance_check
# Contrôle 18.7.6 : Vérifier "Configure RPC listener settings: Authentication protocol to use for incoming RPC connections" via le registre
def check_rpc_listener_auth_protocol():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
        key_name = "ForceKerberosForRpc"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value in [0, 1]:
                    print(f"{GREEN}18.7.6 Configure RPC listener settings: Authentication protocol to use for incoming RPC connections: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.7.6 Configure RPC listener settings: Authentication protocol to use for incoming RPC connections: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.7.6 Configure RPC listener settings: Authentication protocol to use for incoming RPC connections: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.7.6 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.7.6 : {e}{RESET}")

@compliance_check
# Contrôle 18.7.7 : Vérifier "Configure RPC over TCP port" via le registre
def check_rpc_tcp_port():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
        key_name = "RpcTcpPort"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.7.7 Configure RPC over TCP port: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.7.7 Configure RPC over TCP port: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.7.7 Configure RPC over TCP port: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.7.7 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.7.7 : {e}{RESET}")

@compliance_check
# Contrôle 18.7.8 : Vérifier "Limits print driver installation to Administrators" via le registre
def check_limit_print_driver_installation():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        key_name = "RestrictDriverInstallationToAdministrators"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.7.8 Limits print driver installation to Administrators: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.7.8 Limits print driver installation to Administrators: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.7.8 Limits print driver installation to Administrators: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.7.8 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.7.8 : {e}{RESET}")

@compliance_check
# Contrôle 18.7.9 : Vérifier "Manage processing of Queue-specific files" via le registre
def check_manage_queue_specific_files():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Printers"
        key_name = "CopyFilesPolicy"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.7.9 Manage processing of Queue-specific files: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.7.9 Manage processing of Queue-specific files: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.7.9 Manage processing of Queue-specific files: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.7.9 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.7.9 : {e}{RESET}")

@compliance_check
# Contrôle 18.7.10 : Vérifier "Point and Print Restrictions: When installing drivers for a new connection" via le registre
def check_point_and_print_restrictions():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        key_name = "NoWarningNoElevationOnInstall"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.7.10 Point and Print Restrictions: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.7.10 Point and Print Restrictions: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.7.10 Point and Print Restrictions: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.7.10 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.7.10 : {e}{RESET}")

@compliance_check
# Contrôle 18.7.11 : Vérifier "Point and Print Restrictions: When updating drivers for an existing connection" via le registre
def check_point_and_print_update_restrictions():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        key_name = "UpdatePromptSettings"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.7.11 Point and Print Restrictions: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.7.11 Point and Print Restrictions: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.7.11 Point and Print Restrictions: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.7.11 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.7.11 : {e}{RESET}")

@compliance_check
# Contrôle 18.8.1.1 : Vérifier "Turn off notifications network usage" via le registre
def check_turn_off_notifications_network_usage():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
        key_name = "NoCloudApplicationNotification"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.8.1.1 Turn off notifications network usage: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.8.1.1 Turn off notifications network usage: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.8.1.1 Turn off notifications network usage: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.8.1.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.8.1.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.8.2 : Vérifier "Remove Personalized Website Recommendations from the Recommended section in the Start Menu" via le registre
def check_remove_personalized_website_recommendations():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Explorer"
        key_name = "HideRecommendedPersonalizedSites"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.8.2 Remove Personalized Website Recommendations: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.8.2 Remove Personalized Website Recommendations: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.8.2 Remove Personalized Website Recommendations: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.8.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.8.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.3.1 : Vérifier "Include command line in process creation events" via le registre
def check_include_command_line_in_process_creation_events():
    try:
        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        key_name = "ProcessCreationIncludeCmdLine_Enabled"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.3.1 Include command line in process creation events: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.3.1 Include command line in process creation events: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.3.1 Include command line in process creation events: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.3.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.3.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.4.1 : Vérifier "Encryption Oracle Remediation" via le registre
def check_encryption_oracle_remediation():
    try:
        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
        key_name = "AllowEncryptionOracle"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.9.4.1 Encryption Oracle Remediation: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.4.1 Encryption Oracle Remediation: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.4.1 Encryption Oracle Remediation: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.4.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.4.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.4.2 : Vérifier si "Remote host allows delegation of non-exportable credentials" est activé
def check_remote_host_delegation():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
        key_name = "AllowProtectedCreds"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.4.2 Remote Host Delegation: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.4.2 Remote Host Delegation: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.4.2 Remote Host Delegation: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.4.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.4.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.5.1 : Vérifier si "Turn On Virtualization Based Security" est activé
def check_virtualization_based_security():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
        key_name = "EnableVirtualizationBasedSecurity"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.5.1 Virtualization Based Security: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.5.1 Virtualization Based Security: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.5.1 Virtualization Based Security: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.5.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.5.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.5.2 : Vérifier si "Turn On Virtualization Based Security: Select Platform Security Level" est défini sur "Secure Boot" ou plus
def check_virtualization_platform_security_level():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
        key_name = "RequirePlatformSecurityFeatures"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1 or value == 3:
                    print(f"{GREEN}18.9.5.2 Platform Security Level: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.5.2 Platform Security Level: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.5.2 Platform Security Level: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.5.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.5.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.5.3 : Vérifier si "Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity" est activé avec verrouillage UEFI
def check_virtualization_based_protection_code_integrity():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
        key_name = "HypervisorEnforcedCodeIntegrity"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.5.3 Code Integrity Protection: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.5.3 Code Integrity Protection: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.5.3 Code Integrity Protection: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.5.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.5.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.5.4 : Vérifier si "Turn On Virtualization Based Security: Require UEFI Memory Attributes Table" est activé (True)
def check_uefi_memory_attributes_table():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
        key_name = "HVCIMATRequired"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.5.4 UEFI Memory Attributes Table: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.5.4 UEFI Memory Attributes Table: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.5.4 UEFI Memory Attributes Table: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.5.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.5.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.5.5 : Vérifier si "Turn On Virtualization Based Security: Credential Guard Configuration" est activé avec verrouillage UEFI
def check_credential_guard_configuration():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
        key_name = "LsaCfgFlags"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.5.5 Credential Guard Configuration: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.5.5 Credential Guard Configuration: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.5.5 Credential Guard Configuration: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.5.5 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.5.5 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.5.6 : Vérifier si "Turn On Virtualization Based Security: Secure Launch Configuration" est activé
def check_secure_launch_configuration():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
        key_name = "ConfigureSystemGuardLaunch"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.5.6 Secure Launch Configuration: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.5.6 Secure Launch Configuration: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.5.6 Secure Launch Configuration: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.5.6 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.5.6 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.5.7 : Vérifier si "Turn On Virtualization Based Security: Kernel-mode Hardware-enforced Stack Protection" est activé en mode de mise en application
def check_kernel_mode_stack_protection():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
        key_name = "ConfigureKernelShadowStacksLaunch"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.5.7 Kernel-mode Hardware-enforced Stack Protection: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.5.7 Kernel-mode Hardware-enforced Stack Protection: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.5.7 Kernel-mode Hardware-enforced Stack Protection: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.5.7 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.5.7 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.7.1.1 : Vérifier si "Prevent installation of devices that match any of these device IDs" est activé
def check_prevent_device_installation():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
        key_name = "DenyDeviceIDs"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.7.1.1 Prevent Device Installation: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.7.1.1 Prevent Device Installation: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.7.1.1 Prevent Device Installation: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.7.1.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.7.1.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.7.1.2 : Vérifier si "Prevent installation of devices that match any of these device IDs" contient "PCI\CC_0C0A"
def check_prevent_device_installation_pci():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"
        key_name = "1"  # Le nom de la clé dans ce cas est "1", qui contient les ID des périphériques

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if "PCI\\CC_0C0A" in value:
                    print(f"{GREEN}18.9.7.1.2 Prevent Device Installation: Conforme (ID matériel trouvé: {value}){RESET}")
                else:
                    print(f"{RED}18.9.7.1.2 Prevent Device Installation: Non conforme (ID matériel attendu 'PCI\\CC_0C0A' non trouvé){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.7.1.2 Prevent Device Installation: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.7.1.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.7.1.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.7.1.3 : Vérifier si "Prevent installation of devices that match any of these device IDs: Also apply to matching devices that are already installed." est activé
def check_prevent_device_installation_retroactive():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
        key_name = "DenyDeviceIDsRetroactive"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.7.1.3 Prevent Device Installation Retroactive: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.7.1.3 Prevent Device Installation Retroactive: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.7.1.3 Prevent Device Installation Retroactive: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.7.1.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.7.1.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.7.1.4 : Vérifier si "Prevent installation of devices using drivers that match these device setup classes" est activé
def check_prevent_device_installation_classes():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
        key_name = "DenyDeviceClasses"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.7.1.4 Prevent Device Installation by Class: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.7.1.4 Prevent Device Installation by Class: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.7.1.4 Prevent Device Installation by Class: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.7.1.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.7.1.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.7.1.5 : Vérifier si "Prevent installation of devices using drivers that match these device setup classes" contient les classes IEEE 1394
def check_prevent_device_installation_ieee1394():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
        key_name = "DenyDeviceClasses"

        # Liste des GUIDs attendus pour IEEE 1394
        expected_guids = [
            "{d48179be-ec20-11d1-b6b8-00c04fa372a7}",  # IEEE 1394 devices that support SBP2 Protocol Class
            "{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}",  # IEEE 1394 devices that support IEC-61883 Protocol Class
            "{c06ff265-ae09-48f0-812c-16753d7cba83}",  # IEEE 1394 devices that support AVC Protocol Class
            "{6bdd1fc1-810f-11d0-bec7-08002be2092f}"   # IEEE 1394 Host Bus Controller Class
        ]

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la présence de tous les GUIDs dans la clé de registre
                if all(guid in value for guid in expected_guids):
                    print(f"{GREEN}18.9.7.1.5 Prevent Device Installation IEEE 1394: Conforme (GUIDs trouvés: {value}){RESET}")
                else:
                    print(f"{RED}18.9.7.1.5 Prevent Device Installation IEEE 1394: Non conforme (GUIDs attendus non trouvés){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.7.1.5 Prevent Device Installation IEEE 1394: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.7.1.5 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.7.1.5 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.7.1.6 : Vérifier si "Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed." est activé
def check_prevent_device_installation_retroactive_classes():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
        key_name = "DenyDeviceClassesRetroactive"

        # Liste des GUIDs attendus pour IEEE 1394
        expected_guids = [
            "{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}",  # IEEE 1394 devices that support IEC-61883 Protocol Class
            "{c06ff265-ae09-48f0-812c-16753d7cba83}",  # IEEE 1394 devices that support AVC Protocol Class
            "{6bdd1fc1-810f-11d0-bec7-08002be2092f}"   # IEEE 1394 Host Bus Controller Class
        ]

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la présence de tous les GUIDs dans la clé de registre
                if all(guid in value for guid in expected_guids):
                    print(f"{GREEN}18.9.7.1.6 Prevent Device Installation Retroactive by Class: Conforme (GUIDs trouvés: {value}){RESET}")
                else:
                    print(f"{RED}18.9.7.1.6 Prevent Device Installation Retroactive by Class: Non conforme (GUIDs attendus non trouvés){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.7.1.6 Prevent Device Installation Retroactive by Class: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.7.1.6 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.7.1.6 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.7.2 : Vérifier si "Prevent device metadata retrieval from the Internet" est activé
def check_prevent_device_metadata_retrieval():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DeviceMetadata"
        key_name = "PreventDeviceMetadataFromNetwork"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.7.2 Prevent Device Metadata Retrieval: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.7.2 Prevent Device Metadata Retrieval: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.7.2 Prevent Device Metadata Retrieval: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.7.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.7.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.13.1 : Vérifier si "Boot-Start Driver Initialization Policy" est défini sur "Enabled: Good, unknown and bad but critical"
def check_boot_start_driver_initialization_policy():
    try:
        registry_path = r"SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
        key_name = "DriverLoadPolicy"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 3:
                    print(f"{GREEN}18.9.13.1 Boot-Start Driver Initialization Policy: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.13.1 Boot-Start Driver Initialization Policy: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.13.1 Boot-Start Driver Initialization Policy: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.13.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.13.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.19.2 : Vérifier si "Continue experiences on this device" est désactivé
def check_continue_experiences_on_device():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\System"
        key_name = "EnableCdp"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.9.19.2 Continue Experiences on this Device: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.19.2 Continue Experiences on this Device: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.19.2 Continue Experiences on this Device: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.19.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.19.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.20.1.1 : Vérifier si "Turn off access to the Store" est activé
def check_turn_off_access_to_store():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Explorer"
        key_name = "NoUseStoreOpenWith"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.20.1.1 Turn off access to the Store: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.20.1.1 Turn off access to the Store: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.20.1.1 Turn off access to the Store: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.20.1.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.20.1.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.20.1.2 : Vérifier si "Turn off downloading of print drivers over HTTP" est activé
def check_turn_off_print_driver_download_http():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Printers"
        key_name = "DisableWebPnPDownload"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.20.1.2 Turn off downloading of print drivers over HTTP: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.20.1.2 Turn off downloading of print drivers over HTTP: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.20.1.2 Turn off downloading of print drivers over HTTP: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.20.1.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.20.1.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.20.1.3 : Vérifier si "Turn off handwriting personalization data sharing" est activé
def check_turn_off_handwriting_personalization_data_sharing():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\TabletPC"
        key_name = "PreventHandwritingDataSharing"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.20.1.3 Turn off Handwriting Personalization Data Sharing: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.20.1.3 Turn off Handwriting Personalization Data Sharing: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.20.1.3 Turn off Handwriting Personalization Data Sharing: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.20.1.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.20.1.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.20.1.4 : Vérifier si "Turn off handwriting recognition error reporting" est activé
def check_turn_off_handwriting_recognition_error_reporting():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"
        key_name = "PreventHandwritingErrorReports"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.20.1.4 Turn off Handwriting Recognition Error Reporting: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.20.1.4 Turn off Handwriting Recognition Error Reporting: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.20.1.4 Turn off Handwriting Recognition Error Reporting: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.20.1.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.20.1.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.20.1.5 : Vérifier si "Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com" est activé
def check_turn_off_internet_connection_wizard():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard"
        key_name = "ExitOnMSICW"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.20.1.5 Turn off Internet Connection Wizard: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.20.1.5 Turn off Internet Connection Wizard: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.20.1.5 Turn off Internet Connection Wizard: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.20.1.5 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.20.1.5 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.20.1.6 : Vérifier si "Turn off Internet download for Web publishing and online ordering wizards" est activé
def check_turn_off_internet_download_for_web_publish_online_ordering():
    try:
        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        key_name = "NoWebServices"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.20.1.6 Turn off Internet download for Web publishing and online ordering wizards: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.20.1.6 Turn off Internet download for Web publishing and online ordering wizards: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.20.1.6 Turn off Internet download for Web publishing and online ordering wizards: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.20.1.6 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.20.1.6 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.20.1.7 : Vérifier si "Turn off printing over HTTP" est activé
def check_turn_off_printing_over_http():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Printers"
        key_name = "DisableHTTPPrinting"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.20.1.7 Turn off Printing over HTTP: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.20.1.7 Turn off Printing over HTTP: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.20.1.7 Turn off Printing over HTTP: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.20.1.7 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.20.1.7 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.20.1.8 : Vérifier si "Turn off Registration if URL connection is referring to Microsoft.com" est activé
def check_turn_off_registration_microsoft_com():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Registration Wizard"
        key_name = "NoRegistration"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.20.1.8 Turn off Registration if URL connection is referring to Microsoft.com: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.20.1.8 Turn off Registration if URL connection is referring to Microsoft.com: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.20.1.8 Turn off Registration if URL connection is referring to Microsoft.com: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.20.1.8 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.20.1.8 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.20.1.9 : Vérifier si "Turn off Search Companion content file updates" est activé
def check_turn_off_search_companion_content_file_updates():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\SearchCompanion"
        key_name = "DisableContentFileUpdates"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.20.1.9 Turn off Search Companion Content File Updates: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.20.1.9 Turn off Search Companion Content File Updates: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.20.1.9 Turn off Search Companion Content File Updates: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.20.1.9 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.20.1.9 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.20.1.10 : Vérifier si "Turn off the 'Order Prints' picture task" est activé
def check_turn_off_order_prints_picture_task():
    try:
        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        key_name = "NoOnlinePrintsWizard"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.20.1.10 Turn off the 'Order Prints' Picture Task: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.20.1.10 Turn off the 'Order Prints' Picture Task: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.20.1.10 Turn off the 'Order Prints' Picture Task: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.20.1.10 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.20.1.10 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.20.1.11 : Vérifier si "Turn off the 'Publish to Web' task for files and folders" est activé
def check_turn_off_publish_to_web_task():
    try:
        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        key_name = "NoPublishingWizard"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.9.20.1.11 Turn off the 'Publish to Web' Task: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.20.1.11 Turn off the 'Publish to Web' Task: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.20.1.11 Turn off the 'Publish to Web' Task: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.20.1.11 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.20.1.11 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.20.1.12 : Vérifier si "Turn off the Windows Messenger Customer Experience Improvement Program" est activé
def check_turn_off_messenger_ceip():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Messenger\Client"
        key_name = "CEIP"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 2:
                    print(f"{GREEN}18.9.20.1.12 Turn off the Windows Messenger CEIP: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.20.1.12 Turn off the Windows Messenger CEIP: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.20.1.12 Turn off the Windows Messenger CEIP: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.20.1.12 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.20.1.12 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.20.1.13 : Vérifier si "Turn off Windows Customer Experience Improvement Program" est activé
def check_turn_off_windows_ceip():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\SQMClient\Windows"
        key_name = "CEIPEnable"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.9.20.1.13 Turn off Windows CEIP: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.20.1.13 Turn off Windows CEIP: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.20.1.13 Turn off Windows CEIP: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.20.1.13 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.20.1.13 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.20.1.14 : Vérifier si "Turn off Windows Error Reporting" est activé
def check_turn_off_windows_error_reporting():
    try:
        # Vérification de la clé de registre pour Disabled
        registry_path_disabled = r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
        key_name_disabled = "Disabled"
        
        try:
            reg_key_disabled = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path_disabled)
            value_disabled, _ = winreg.QueryValueEx(reg_key_disabled, key_name_disabled)
            winreg.CloseKey(reg_key_disabled)
        except FileNotFoundError:
            print(f"{RED}18.9.20.1.14 Clé de registre '{registry_path_disabled}' non trouvée.{RESET}")
            return
        except Exception as e:
            print(f"{RED}Erreur lors de l'accès à la clé '{registry_path_disabled}': {e}{RESET}")
            return

        # Vérification de la clé de registre pour DoReport
        registry_path_doreport = r"SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting"
        key_name_doreport = "DoReport"
        
        try:
            reg_key_doreport = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path_doreport)
            value_doreport, _ = winreg.QueryValueEx(reg_key_doreport, key_name_doreport)
            winreg.CloseKey(reg_key_doreport)
        except FileNotFoundError:
            print(f"{RED}18.9.20.1.14 Clé de registre '{registry_path_doreport}' non trouvée.{RESET}")
            return
        except Exception as e:
            print(f"{RED}Erreur lors de l'accès à la clé '{registry_path_doreport}': {e}{RESET}")
            return

        # Vérification de la valeur des clés de registre
        if value_disabled == 1 and value_doreport == 0:
            print(f"{GREEN}18.9.20.1.14 Turn off Windows Error Reporting: Conforme (Valeurs Relevées: Disabled={value_disabled}, DoReport={value_doreport}){RESET}")
        else:
            print(f"{RED}18.9.20.1.14 Turn off Windows Error Reporting: Non conforme (Valeurs Relevées: Disabled={value_disabled}, DoReport={value_doreport}){RESET}")
        
    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.20.1.14 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.23.1 : Vérifier si "Support device authentication using certificate" est activé
def check_support_device_authentication_using_certificate():
    try:
        # Vérification de la clé de registre DevicePKInitBehavior
        registry_path_behavior = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters"
        key_name_behavior = "DevicePKInitBehavior"
        
        try:
            reg_key_behavior = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path_behavior)
            value_behavior, _ = winreg.QueryValueEx(reg_key_behavior, key_name_behavior)
            winreg.CloseKey(reg_key_behavior)
        except FileNotFoundError:
            print(f"{RED}18.9.23.1 Clé de registre '{registry_path_behavior}' non trouvée.{RESET}")
            return
        except Exception as e:
            print(f"{RED}Erreur lors de l'accès à la clé '{registry_path_behavior}': {e}{RESET}")
            return
        
        # Vérification de la clé de registre DevicePKInitEnabled
        registry_path_enabled = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters"
        key_name_enabled = "DevicePKInitEnabled"
        
        try:
            reg_key_enabled = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path_enabled)
            value_enabled, _ = winreg.QueryValueEx(reg_key_enabled, key_name_enabled)
            winreg.CloseKey(reg_key_enabled)
        except FileNotFoundError:
            print(f"{RED}18.9.23.1 Clé de registre '{registry_path_enabled}' non trouvée.{RESET}")
            return
        except Exception as e:
            print(f"{RED}Erreur lors de l'accès à la clé '{registry_path_enabled}': {e}{RESET}")
            return

        # Vérification des valeurs des deux clés
        if value_behavior == 0 and value_enabled == 1:
            print(f"{GREEN}18.9.23.1 Support device authentication using certificate: Conforme (Valeurs Relevées: DevicePKInitBehavior={value_behavior}, DevicePKInitEnabled={value_enabled}){RESET}")
        else:
            print(f"{RED}18.9.23.1 Support device authentication using certificate: Non conforme (Valeurs Relevées: DevicePKInitBehavior={value_behavior}, DevicePKInitEnabled={value_enabled}){RESET}")
        
    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.23.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.24.1 : Vérifier si "Enumeration policy for external devices incompatible with Kernel DMA Protection" est activé
def check_enumeration_policy_for_external_devices_dma_protection():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection"
        key_name = "DeviceEnumerationPolicy"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.9.24.1 Enumeration policy for external devices incompatible with Kernel DMA Protection: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.24.1 Enumeration policy for external devices incompatible with Kernel DMA Protection: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.24.1 Enumeration policy for external devices incompatible with Kernel DMA Protection: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.24.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.24.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.26.1 : Vérifier si "Allow Custom SSPs and APs to be loaded into LSASS" est désactivé
def check_allow_custom_ssps_aps_in_lsass():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\System"
        key_name = "AllowCustomSSPsAPs"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.9.26.1 Allow Custom SSPs and APs to be loaded into LSASS: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.9.26.1 Allow Custom SSPs and APs to be loaded into LSASS: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.9.26.1 Allow Custom SSPs and APs to be loaded into LSASS: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.9.26.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.26.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.26.2 : Vérifier si "Configures LSASS to run as a protected process" est activé
def check_lsass_run_as_protected_process():
    try:
        registry_path = r"SYSTEM\CurrentControlSet\Control\Lsa"
        key_name = "RunAsPPL"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.9.26.2 Configures LSASS to run as a protected process: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.26.2 Configures LSASS to run as a protected process: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.26.2 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.26.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.26.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.27.1 : Vérifier si "Disallow copying of user input methods to the system account for sign-in" est activé
def check_disallow_copying_user_input_methods():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Control Panel\International"
        key_name = "BlockUserInputMethodsForSignIn"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.9.27.1 Disallow copying of user input methods to the system account for sign-in: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.27.1 Disallow copying of user input methods to the system account for sign-in: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.27.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.27.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.27.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.28.1 : Vérifier si "Block user from showing account details on sign-in" est activé
def check_block_user_from_showing_account_details_on_signin():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\System"
        key_name = "BlockUserFromShowingAccountDetailsOnSignin"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.9.28.1 Block user from showing account details on sign-in: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.28.1 Block user from showing account details on sign-in: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.28.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.28.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.28.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.28.2 : Vérifier si "Do not display network selection UI" est activé
def check_do_not_display_network_selection_ui():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\System"
        key_name = "DontDisplayNetworkSelectionUI"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.9.28.2 Do not display network selection UI: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.28.2 Do not display network selection UI: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.28.2 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.28.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.28.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.28.3 : Vérifier si "Turn off app notifications on the lock screen" est activé
def check_turn_off_app_notifications_on_lock_screen():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\System"
        key_name = "DisableLockScreenAppNotifications"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.9.28.3 Turn off app notifications on the lock screen: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.28.3 Turn off app notifications on the lock screen: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.28.3 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.28.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.28.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.28.4 : Vérifier si "Turn on convenience PIN sign-in" est désactivé
def check_turn_on_convenience_pin_sign_in():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\System"
        key_name = "AllowDomainPINLogon"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 0:
                print(f"{GREEN}18.9.28.4 Turn on convenience PIN sign-in: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.28.4 Turn on convenience PIN sign-in: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.28.4 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.28.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.28.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.31.1 : Vérifier si "Allow Clipboard synchronization across devices" est désactivé
def check_allow_clipboard_synchronization_across_devices():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\System"
        key_name = "AllowCrossDeviceClipboard"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 0:
                print(f"{GREEN}18.9.31.1 Allow Clipboard synchronization across devices: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.31.1 Allow Clipboard synchronization across devices: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.31.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.31.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.31.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.31.2 : Vérifier si "Allow upload of User Activities" est désactivé
def check_allow_upload_of_user_activities():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\System"
        key_name = "UploadUserActivities"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 0:
                print(f"{GREEN}18.9.31.2 Allow upload of User Activities: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.31.2 Allow upload of User Activities: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.31.2 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.31.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.31.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.33.6.1 : Vérifier si "Allow network connectivity during connected-standby (on battery)" est désactivé
def check_allow_network_connectivity_during_connected_standby():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
        key_name = "DCSettingIndex"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 0:
                print(f"{GREEN}18.9.33.6.1 Allow network connectivity during connected-standby (on battery): Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.33.6.1 Allow network connectivity during connected-standby (on battery): Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.33.6.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.33.6.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.33.6.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.33.6.2 : Vérifier si "Allow network connectivity during connected-standby (plugged in)" est désactivé
def check_allow_network_connectivity_during_connected_standby_plugged_in():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
        key_name = "ACSettingIndex"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 0:
                print(f"{GREEN}18.9.33.6.2 Allow network connectivity during connected-standby (plugged in): Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.33.6.2 Allow network connectivity during connected-standby (plugged in): Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.33.6.2 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.33.6.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.33.6.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.33.6.3 : Vérifier si "Allow standby states (S1-S3) when sleeping (on battery)" est désactivé
def check_allow_standby_states_when_sleeping_on_battery():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea171b0ed546ab"
        key_name = "DCSettingIndex"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 0:
                print(f"{GREEN}18.9.33.6.3 Allow standby states (S1-S3) when sleeping (on battery): Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.33.6.3 Allow standby states (S1-S3) when sleeping (on battery): Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.33.6.3 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.33.6.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.33.6.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.33.6.4 : Vérifier si "Allow standby states (S1-S3) when sleeping (plugged in)" est désactivé
def check_allow_standby_states_when_sleeping_plugged_in():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea171b0ed546ab"
        key_name = "ACSettingIndex"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 0:
                print(f"{GREEN}18.9.33.6.4 Allow standby states (S1-S3) when sleeping (plugged in): Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.33.6.4 Allow standby states (S1-S3) when sleeping (plugged in): Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.33.6.4 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.33.6.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.33.6.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.33.6.5 : Vérifier si "Require a password when a computer wakes (on battery)" est activé
def check_require_password_when_computer_wakes_on_battery():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
        key_name = "DCSettingIndex"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.9.33.6.5 Require a password when a computer wakes (on battery): Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.33.6.5 Require a password when a computer wakes (on battery): Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.33.6.5 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.33.6.5 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.33.6.5 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.33.6.6 : Vérifier si "Require a password when a computer wakes (plugged in)" est activé
def check_require_password_when_computer_wakes_plugged_in():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
        key_name = "ACSettingIndex"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.9.33.6.6 Require a password when a computer wakes (plugged in): Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.33.6.6 Require a password when a computer wakes (plugged in): Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.33.6.6 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.33.6.6 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.33.6.6 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.35.1 : Vérifier si "Configure Offer Remote Assistance" est désactivé
def check_configure_offer_remote_assistance():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "fAllowUnsolicited"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 0:
                print(f"{GREEN}18.9.35.1 Configure Offer Remote Assistance: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.35.1 Configure Offer Remote Assistance: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.35.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.35.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.35.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.35.2 : Vérifier si "Configure Solicited Remote Assistance" est désactivé
def check_configure_solicited_remote_assistance():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "fAllowToGetHelp"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 0:
                print(f"{GREEN}18.9.35.2 Configure Solicited Remote Assistance: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.35.2 Configure Solicited Remote Assistance: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.35.2 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.35.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.35.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.36.1 : Vérifier si "Enable RPC Endpoint Mapper Client Authentication" est activé
def check_enable_rpc_endpoint_mapper_client_authentication():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
        key_name = "EnableAuthEpResolution"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.9.36.1 Enable RPC Endpoint Mapper Client Authentication: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.36.1 Enable RPC Endpoint Mapper Client Authentication: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.36.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.36.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.36.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.36.2 : Vérifier si "Restrict Unauthenticated RPC clients" est activé avec la valeur "Authenticated"
def check_restrict_unauthenticated_rpc_clients():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
        key_name = "RestrictRemoteClients"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.9.36.2 Restrict Unauthenticated RPC clients: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.36.2 Restrict Unauthenticated RPC clients: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.36.2 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.36.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.36.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.47.5.1 : Vérifier si "Turn on MSDT interactive communication with support provider" est désactivé
def check_turn_on_msdm_interactive_communication():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy"
        key_name = "DisableQueryRemoteServer"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.9.47.5.1 Turn on MSDT interactive communication with support provider: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.47.5.1 Turn on MSDT interactive communication with support provider: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.47.5.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.47.5.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.47.5.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.47.11.1 : Vérifier si "Enable/Disable PerfTrack" est désactivé
def check_enable_disable_perftrack():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WDI"
        key_name = "{9c5a40da-b965-4fc3-8781-88dd50a6299d}:ScenarioExecutionEnabled"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 0:
                print(f"{GREEN}18.9.47.11.1 Enable/Disable PerfTrack: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.47.11.1 Enable/Disable PerfTrack: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.47.11.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.47.11.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.47.11.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.49.1 : Vérifier si "Turn off the advertising ID" est activé
def check_turn_off_advertising_id():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
        key_name = "DisabledByGroupPolicy"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.9.49.1 Turn off the advertising ID: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.49.1 Turn off the advertising ID: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.49.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.49.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.49.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.9.51.1.1 : Vérifier si "Enable Windows NTP Client" est activé
def check_enable_windows_ntp_client():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"
        key_name = "Enabled"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.9.51.1.1 Enable Windows NTP Client: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.9.51.1.1 Enable Windows NTP Client: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.9.51.1.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.9.51.1.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.9.51.1.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.3.1 : Vérifier si "Allow a Windows app to share application data between users" est désactivé
def check_allow_shared_local_app_data():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager"
        key_name = "AllowSharedLocalAppData"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 0:
                print(f"{GREEN}18.10.3.1 Allow a Windows app to share application data between users: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.10.3.1 Allow a Windows app to share application data between users: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.10.3.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.10.3.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.3.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.3.2 : Vérifier si "Prevent non-admin users from installing packaged Windows apps" est activé
def check_prevent_non_admin_install_apps():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Appx"
        key_name = "BlockNonAdminUserInstall"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.10.3.2 Prevent non-admin users from installing packaged Windows apps: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.10.3.2 Prevent non-admin users from installing packaged Windows apps: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.10.3.2 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.10.3.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.3.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.4.1 : Vérifier si "Let Windows apps activate with voice while the system is locked" est activé avec "Force Deny"
def check_let_apps_activate_with_voice_above_lock():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
        key_name = "LetAppsActivateWithVoiceAboveLock"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 2:
                print(f"{GREEN}18.10.4.1 Let Windows apps activate with voice while the system is locked: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.10.4.1 Let Windows apps activate with voice while the system is locked: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.10.4.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.10.4.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.4.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.5.1 : Vérifier si "Allow Microsoft accounts to be optional" est activé
def check_allow_microsoft_accounts_to_be_optional():
    try:
        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        key_name = "MSAOptional"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.10.5.1 Allow Microsoft accounts to be optional: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.10.5.1 Allow Microsoft accounts to be optional: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.10.5.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.10.5.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.5.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.5.2 : Vérifier si "Block launching Universal Windows apps with Windows Runtime API access from hosted content" est activé
def check_block_hosted_app_access_winrt():
    try:
        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        key_name = "BlockHostedAppAccessWinRT"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.10.5.2 Block launching Universal Windows apps with Windows Runtime API access from hosted content: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.10.5.2 Block launching Universal Windows apps with Windows Runtime API access from hosted content: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.10.5.2 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.10.5.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.5.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.7.1 : Vérifier si "Disallow Autoplay for non-volume devices" est activé
def check_disallow_autoplay_for_non_volume_devices():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Explorer"
        key_name = "NoAutoplayfornonVolume"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.10.7.1 Disallow Autoplay for non-volume devices: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.10.7.1 Disallow Autoplay for non-volume devices: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.10.7.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.10.7.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.7.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.7.2 : Vérifier si "Set the default behavior for AutoRun" est configuré sur "Do not execute any autorun commands"
def check_set_default_behavior_for_autorun():
    try:
        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        key_name = "NoAutorun"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.10.7.2 Set the default behavior for AutoRun: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.10.7.2 Set the default behavior for AutoRun: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.10.7.2 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.10.7.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.7.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.7.3 : Vérifier si "Turn off Autoplay" est configuré sur "Enabled: All drives"
def check_turn_off_autoplay():
    try:
        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        key_name = "NoDriveTypeAutoRun"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 255:
                print(f"{GREEN}18.10.7.3 Turn off Autoplay: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.10.7.3 Turn off Autoplay: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.10.7.3 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.10.7.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.7.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.8.1.1 : Vérifier si "Configure enhanced anti-spoofing" est configuré sur "Enabled"
def check_enhanced_anti_spoofing():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"
        key_name = "EnhancedAntiSpoofing"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)

            # Vérification de la valeur de la clé
            if value == 1:
                print(f"{GREEN}18.10.8.1.1 Configure enhanced anti-spoofing: Conforme (Valeur Relevée: {value}){RESET}")
            else:
                print(f"{RED}18.10.8.1.1 Configure enhanced anti-spoofing: Non conforme (Valeur Relevée: {value}){RESET}")

        except FileNotFoundError:
            print(f"{RED}18.10.8.1.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
            return

    except FileNotFoundError:
        print(f"{RED}18.10.8.1.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
        return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.8.1.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.1.1 : Vérifier si "Allow access to BitLocker-protected fixed data drives from earlier versions of Windows" est configuré sur "Disabled"
def check_bitlocker_access_for_older_versions():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "FDVDiscoveryVolumeType"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la clé de registre, si elle est vide, la politique est configurée comme "Disabled"
                if value == "":
                    print(f"{GREEN}18.10.9.1.1 Allow access to BitLocker-protected fixed data drives from earlier versions of Windows: Conforme (Valeur Relevée: vide) {RESET}")
                else:
                    print(f"{RED}18.10.9.1.1 Allow access to BitLocker-protected fixed data drives from earlier versions of Windows: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.1.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.1.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.1.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.1.2 : Vérifier si "Choose how BitLocker-protected fixed drives can be recovered" est configuré sur "Enabled"
def check_bitlocker_recovery_option():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "FDVRecovery"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé de registre
                if value == 1:
                    print(f"{GREEN}18.10.9.1.2 Choose how BitLocker-protected fixed drives can be recovered: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.1.2 Choose how BitLocker-protected fixed drives can be recovered: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.1.2 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.1.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.1.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.1.3 : Vérifier si "Allow data recovery agent" est configuré sur "Enabled: True"
def check_bitlocker_data_recovery_agent():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "FDVManageDRA"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé de registre
                if value == 1:
                    print(f"{GREEN}18.10.9.1.3 Allow data recovery agent: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.1.3 Allow data recovery agent: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.1.3 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.1.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.1.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.1.4 : Vérifier si "Recovery Password" est configuré sur "Enabled: Allow 48-digit recovery password" ou "Enabled: Require 48-digit recovery password"
def check_bitlocker_recovery_password():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "FDVRecoveryPassword"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé de registre
                if value == 2 or value == 1:
                    print(f"{GREEN}18.10.9.1.4 Recovery Password: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.1.4 Recovery Password: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.1.4 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.1.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.1.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.1.5 : Vérifier si "Recovery Key" est configuré pour permettre une clé de récupération 256 bits ou plus
def check_bitlocker_recovery_key():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "FDVRecoveryKey"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé de registre
                if value == 2 or value == 1:
                    print(f"{GREEN}18.10.9.1.5 Recovery Key: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.1.5 Recovery Key: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.1.5 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.1.5 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.1.5 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.1.6 : Vérifier si "Omit recovery options from the BitLocker setup wizard" est activé
def check_bitlocker_omit_recovery_options():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "FDVHideRecoveryPage"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé de registre
                if value == 1:
                    print(f"{GREEN}18.10.9.1.6 Omit recovery options from the BitLocker setup wizard: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.1.6 Omit recovery options from the BitLocker setup wizard: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.1.6 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.1.6 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.1.6 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.1.7 : Vérifier si "Save BitLocker recovery information to AD DS for fixed data drives" est désactivé
def check_bitlocker_save_recovery_info_to_ad():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "FDVActiveDirectoryBackup"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé de registre
                if value == 0:
                    print(f"{GREEN}18.10.9.1.7 Save BitLocker recovery information to AD DS for fixed data drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.1.7 Save BitLocker recovery information to AD DS for fixed data drives: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.1.7 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.1.7 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.1.7 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.1.8 : Vérifier si "Configure storage of BitLocker recovery information to AD DS" est configuré sur "Enabled: Backup recovery passwords and key packages"
def check_bitlocker_storage_recovery_info_to_ad():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "FDVActiveDirectoryInfoToStore"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé de registre
                if value == 1:
                    print(f"{GREEN}18.10.9.1.8 Configure storage of BitLocker recovery information to AD DS: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.1.8 Configure storage of BitLocker recovery information to AD DS: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.1.8 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.1.8 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.1.8 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.1.9 : Vérifier si "Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives" est configuré sur "Enabled: False"
def check_bitlocker_require_ad_backup():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "FDVRequireActiveDirectoryBackup"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.9.1.9 Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.1.9 Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.1.9 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.1.9 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.1.9 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.1.10 : Vérifier si "Configure use of hardware-based encryption for fixed data drives" est configuré sur "Disabled"
def check_hardware_encryption_disabled():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "FDVHardwareEncryption"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.9.1.10 Configure use of hardware-based encryption for fixed data drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.1.10 Configure use of hardware-based encryption for fixed data drives: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.1.10 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.1.10 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.1.10 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.1.11 : Vérifier si "Configure use of passwords for fixed data drives" est configuré sur "Disabled"
def check_password_for_fixed_drives_disabled():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "FDVPassphrase"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.9.1.11 Configure use of passwords for fixed data drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.1.11 Configure use of passwords for fixed data drives: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.1.11 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.1.11 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.1.11 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.1.12 : Vérifier si "Configure use of smart cards on fixed data drives" est configuré sur "Enabled"
def check_smart_card_on_fixed_drives_enabled():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "FDVAllowUserCert"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.9.1.12 Configure use of smart cards on fixed data drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.1.12 Configure use of smart cards on fixed data drives: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.1.12 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.1.12 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.1.12 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.1.13 : Vérifier si "Configure use of smart cards on fixed data drives: Require use of smart cards on fixed data drives" est configuré sur "Enabled: True"
def check_require_smart_card_on_fixed_drives_enabled():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "FDVEnforceUserCert"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.9.1.13 Configure use of smart cards on fixed data drives: Require use of smart cards on fixed data drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.1.13 Configure use of smart cards on fixed data drives: Require use of smart cards on fixed data drives: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.1.13 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.1.13 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.1.13 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.1 : Vérifier si "Allow enhanced PINs for startup" est configuré sur "Enabled"
def check_allow_enhanced_pins_for_startup_enabled():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "UseEnhancedPin"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.9.2.1 Allow enhanced PINs for startup: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.1 Allow enhanced PINs for startup: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.2 : Vérifier si "Allow Secure Boot for integrity validation" est configuré sur "Enabled"
def check_allow_secure_boot_for_integrity_enabled():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "OSAllowSecureBootForIntegrity"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.9.2.2 Allow Secure Boot for integrity validation: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.2 Allow Secure Boot for integrity validation: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.2 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.3 : Vérifier si "Choose how BitLocker-protected operating system drives can be recovered" est configuré sur "Enabled"
def check_bitlocker_os_recovery_enabled():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "OSRecovery"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.9.2.3 Choose how BitLocker-protected operating system drives can be recovered: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.3 Choose how BitLocker-protected operating system drives can be recovered: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.3 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.4 : Vérifier si "Allow data recovery agent" est configuré sur "Enabled: False"
def check_bitlocker_allow_data_recovery_agent():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "OSManageDRA"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.9.2.4 Choose how BitLocker-protected operating system drives can be recovered: Allow data recovery agent: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.4 Choose how BitLocker-protected operating system drives can be recovered: Allow data recovery agent: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.4 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.5 : Vérifier si "Recovery Password" est configuré sur "Enabled: Require 48-digit recovery password"
def check_bitlocker_recovery_password():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "OSRecoveryPassword"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.9.2.5 Choose how BitLocker-protected operating system drives can be recovered: Recovery Password: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.5 Choose how BitLocker-protected operating system drives can be recovered: Recovery Password: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.5 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.5 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.5 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.6 : Vérifier si "Recovery Key" est configuré sur "Enabled: Do not allow 256-bit recovery key"
def check_bitlocker_recovery_key():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "OSRecoveryKey"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.9.2.6 Choose how BitLocker-protected operating system drives can be recovered: Recovery Key: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.6 Choose how BitLocker-protected operating system drives can be recovered: Recovery Key: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.6 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.6 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.6 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.7 : Vérifier si "Omit recovery options from the BitLocker setup wizard" est configuré sur "Enabled: True"
def check_bitlocker_omit_recovery_page():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "OSHideRecoveryPage"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.9.2.7 Choose how BitLocker-protected operating system drives can be recovered: Omit recovery options from the BitLocker setup wizard: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.7 Choose how BitLocker-protected operating system drives can be recovered: Omit recovery options from the BitLocker setup wizard: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.7 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.7 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.7 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.8 : Vérifier si "Save BitLocker recovery information to AD DS for operating system drives" est configuré sur "Enabled: True"
def check_bitlocker_save_recovery_to_ad():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "OSActiveDirectoryBackup"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.9.2.8 Choose how BitLocker-protected operating system drives can be recovered: Save BitLocker recovery information to AD DS for operating system drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.8 Choose how BitLocker-protected operating system drives can be recovered: Save BitLocker recovery information to AD DS for operating system drives: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.8 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.8 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.8 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.9 : Vérifier si "Configure storage of BitLocker recovery information to AD DS" est configuré sur "Enabled: Store recovery passwords and key packages"
def check_bitlocker_store_recovery_to_ad():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "OSActiveDirectoryInfoToStore"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.9.2.9 Choose how BitLocker-protected operating system drives can be recovered: Configure storage of BitLocker recovery information to AD DS: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.9 Choose how BitLocker-protected operating system drives can be recovered: Configure storage of BitLocker recovery information to AD DS: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.9 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.9 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.9 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.10 : Vérifier si "Do not enable BitLocker until recovery information is stored to AD DS" est activé
def check_bitlocker_ad_backup_requirement():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "OSRequireActiveDirectoryBackup"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.9.2.10 Choose how BitLocker-protected operating system drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.10 Choose how BitLocker-protected operating system drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.10 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.10 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.10 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.11 : Vérifier si "Configure use of hardware-based encryption for operating system drives" est désactivé
def check_hardware_encryption_for_os_drives():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "OSHardwareEncryption"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.9.2.11 Configure use of hardware-based encryption for operating system drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.11 Configure use of hardware-based encryption for operating system drives: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.11 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.11 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.11 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.12 : Vérifier si "Configure use of passwords for operating system drives" est désactivé
def check_passwords_for_os_drives():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "OSPassphrase"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.9.2.12 Configure use of passwords for operating system drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.12 Configure use of passwords for operating system drives: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.12 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.12 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.12 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.13 : Vérifier si "Require additional authentication at startup" est activé
def check_additional_authentication_at_startup():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "UseAdvancedStartup"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.9.2.13 Require additional authentication at startup: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.13 Require additional authentication at startup: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.13 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.13 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.13 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.14 : Vérifier si "Allow BitLocker without a compatible TPM" est désactivé
def check_allow_bitlocker_without_tpm():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "EnableBDEWithNoTPM"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.9.2.14 Allow BitLocker without a compatible TPM: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.14 Allow BitLocker without a compatible TPM: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.14 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.14 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.14 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.15 : Vérifier si "Configure TPM startup" est configuré pour ne pas autoriser TPM
def check_configure_tpm_startup():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "UseTPM"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.9.2.15 Configure TPM startup: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.15 Configure TPM startup: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.15 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.15 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.15 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.16 : Vérifier si "Configure TPM startup PIN" est configuré pour exiger un PIN de démarrage avec TPM
def check_configure_tpm_startup_pin():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "UseTPMPIN"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.9.2.16 Configure TPM startup PIN: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.16 Configure TPM startup PIN: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.16 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.16 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.16 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.17 : Vérifier si "Configure TPM startup key" est configuré pour ne pas autoriser la clé TPM
def check_configure_tpm_startup_key():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "UseTPMKey"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.9.2.17 Configure TPM startup key: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.17 Configure TPM startup key: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.17 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.17 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.17 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.2.18 : Vérifier si "Configure TPM startup key and PIN" est configuré pour ne pas autoriser la clé TPM et le PIN
def check_configure_tpm_startup_key_and_pin():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "UseTPMKeyPIN"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.9.2.18 Configure TPM startup key and PIN: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.2.18 Configure TPM startup key and PIN: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.2.18 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.2.18 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.2.18 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.3.1 : Vérifier si "Allow access to BitLocker-protected removable data drives from earlier versions of Windows" est désactivé
def check_allow_access_to_bitlocker_protected_removable_drives():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "RDVDiscoveryVolumeType"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification si la clé est vide (ce qui indique que la configuration est correcte)
                if value == '':
                    print(f"{GREEN}18.10.9.3.1 Allow access to BitLocker-protected removable data drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.3.1 Allow access to BitLocker-protected removable data drives: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.3.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.3.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.3.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.3.2 : Vérifier si "Choose how BitLocker-protected removable drives can be recovered" est activé
def check_choose_how_bitlocker_protected_removable_drives_can_be_recovered():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "RDVRecovery"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification si la valeur est bien 1
                if value == 1:
                    print(f"{GREEN}18.10.9.3.2 Choose how BitLocker-protected removable drives can be recovered: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.3.2 Choose how BitLocker-protected removable drives can be recovered: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.3.2 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.3.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.3.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.3.3 : Vérifier si "Allow data recovery agent" est activé pour les lecteurs amovibles protégés par BitLocker
def check_allow_data_recovery_agent_for_removable_drives():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "RDVManageDRA"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification si la valeur est bien 1
                if value == 1:
                    print(f"{GREEN}18.10.9.3.3 Choose how BitLocker-protected removable drives can be recovered: Allow data recovery agent: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.3.3 Choose how BitLocker-protected removable drives can be recovered: Allow data recovery agent: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.3.3 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.3.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.3.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.3.4 : Vérifier si "Recovery Password" est désactivé pour les lecteurs amovibles protégés par BitLocker
def check_recovery_password_for_removable_drives():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "RDVRecoveryPassword"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification si la valeur est bien 0
                if value == 0:
                    print(f"{GREEN}18.10.9.3.4 Choose how BitLocker-protected removable drives can be recovered: Recovery Password: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.3.4 Choose how BitLocker-protected removable drives can be recovered: Recovery Password: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.3.4 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.3.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.3.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.3.5 : Vérifier si "Recovery Key" est désactivé pour les lecteurs amovibles protégés par BitLocker
def check_recovery_key_for_removable_drives():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "RDVRecoveryKey"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification si la valeur est bien 0
                if value == 0:
                    print(f"{GREEN}18.10.9.3.5 Choose how BitLocker-protected removable drives can be recovered: Recovery Key: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.3.5 Choose how BitLocker-protected removable drives can be recovered: Recovery Key: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.3.5 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.3.5 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.3.5 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.3.6 : Vérifier si l'option "Omit recovery options from the BitLocker setup wizard" est activée
def check_omit_recovery_options():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "RDVHideRecoveryPage"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification si la valeur est bien 1
                if value == 1:
                    print(f"{GREEN}18.10.9.3.6 Choose how BitLocker-protected removable drives can be recovered: Omit recovery options: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.3.6 Choose how BitLocker-protected removable drives can be recovered: Omit recovery options: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.3.6 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.3.6 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.3.6 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.3.7 : Vérifier si "Save BitLocker recovery information to AD DS for removable data drives" est désactivé
def check_save_recovery_info_to_ad_ds_for_removable_drives():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "RDVActiveDirectoryBackup"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification si la valeur est bien 0 (désactivée)
                if value == 0:
                    print(f"{GREEN}18.10.9.3.7 Save BitLocker recovery information to AD DS for removable data drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.3.7 Save BitLocker recovery information to AD DS for removable data drives: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.3.7 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.3.7 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.3.7 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.3.8 : Vérifier si la politique "Configure storage of BitLocker recovery information to AD DS" est configurée correctement
def check_configure_storage_of_bitlocker_recovery_info_to_ad_ds():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "RDVActiveDirectoryInfoToStore"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification si la valeur est correcte (1 = Backup recovery passwords and key packages)
                if value == 1:
                    print(f"{GREEN}18.10.9.3.8 Configure storage of BitLocker recovery information to AD DS: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.3.8 Configure storage of BitLocker recovery information to AD DS: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.3.8 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.3.8 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.3.8 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.3.9 : Vérifier si la politique "Do not enable BitLocker until recovery information is stored to AD DS for removable data drives" est configurée correctement
def check_bitlocker_recovery_info_to_ad_ds_for_removable_drives():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "RDVRequireActiveDirectoryBackup"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification si la valeur est correcte (0 = False)
                if value == 0:
                    print(f"{GREEN}18.10.9.3.9 Do not enable BitLocker until recovery information is stored to AD DS for removable data drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.3.9 Do not enable BitLocker until recovery information is stored to AD DS for removable data drives: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.3.9 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.3.9 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.3.9 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.3.10 : Vérifier si la politique "Configure use of hardware-based encryption for removable data drives" est configurée correctement
def check_bitlocker_hardware_encryption_for_removable_drives():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "RDVHardwareEncryption"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification si la valeur est correcte (0 = Disabled)
                if value == 0:
                    print(f"{GREEN}18.10.9.3.10 Configure use of hardware-based encryption for removable data drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.3.10 Configure use of hardware-based encryption for removable data drives: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.3.10 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.3.10 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.3.10 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.3.11 : Vérifier si la politique "Configure use of passwords for removable data drives" est configurée correctement
def check_bitlocker_password_for_removable_drives():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "RDVPassphrase"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification si la valeur est correcte (0 = Disabled)
                if value == 0:
                    print(f"{GREEN}18.10.9.3.11 Configure use of passwords for removable data drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.3.11 Configure use of passwords for removable data drives: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.3.11 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.3.11 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.3.11 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.3.12 : Vérifier si la politique "Configure use of smart cards on removable data drives" est configurée correctement
def check_bitlocker_smartcards_for_removable_drives():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "RDVAllowUserCert"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification si la valeur est correcte (1 = Enabled)
                if value == 1:
                    print(f"{GREEN}18.10.9.3.12 Configure use of smart cards on removable data drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.3.12 Configure use of smart cards on removable data drives: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.3.12 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.3.12 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.3.12 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.3.13 : Vérifier si la politique "Require use of smart cards on removable data drives" est configurée correctement
def check_bitlocker_smartcards_enforce_for_removable_drives():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "RDVEnforceUserCert"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification si la valeur est correcte (1 = Enabled)
                if value == 1:
                    print(f"{GREEN}18.10.9.3.13 Configure use of smart cards on removable data drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.3.13 Configure use of smart cards on removable data drives: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.3.13 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.3.13 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.3.13 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.3.14 : Vérifier si la politique "Deny write access to removable drives not protected by BitLocker" est configurée correctement
def check_bitlocker_deny_write_access_to_non_bitlocker_drives():
    try:
        # Chemin de la clé de registre
        registry_path = r"SYSTEM\CurrentControlSet\Policies\Microsoft\FVE"
        key_name = "RDVDenyWriteAccess"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification si la valeur est correcte (1 = Enabled)
                if value == 1:
                    print(f"{GREEN}18.10.9.3.14 Deny write access to removable drives not protected by BitLocker: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.3.14 Deny write access to removable drives not protected by BitLocker: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.3.14 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.3.14 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.3.14 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.3.15 : Vérifier si la politique "Do not allow write access to devices configured in another organization" est configurée correctement
def check_bitlocker_deny_write_access_to_other_organizations():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "RDVDenyCrossOrg"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification si la valeur est correcte (0 = Disabled)
                if value == 0:
                    print(f"{GREEN}18.10.9.3.15 Deny write access to removable drives not protected by BitLocker: Do not allow write access to devices configured in another organization: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.3.15 Deny write access to removable drives not protected by BitLocker: Do not allow write access to devices configured in another organization: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.3.15 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.3.15 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.3.15 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.9.4 : Vérifier si la politique "Disable new DMA devices when this computer is locked" est configurée correctement
def check_disable_new_dma_devices_when_locked():
    try:
        # Chemin de la clé de registre
        registry_path = r"SOFTWARE\Policies\Microsoft\FVE"
        key_name = "DisableExternalDMAUnderLock"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification si la valeur est correcte (1 = Enabled)
                if value == 1:
                    print(f"{GREEN}18.10.9.4 Disable new DMA devices when this computer is locked: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.9.4 Disable new DMA devices when this computer is locked: Non conforme (Valeur Relevée: {value}){RESET}")
            except FileNotFoundError:
                print(f"{RED}18.10.9.4 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.9.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.9.4 : {e}{RESET}")

@compliance_check
# Fonction de vérification et modification pour la politique "Allow Use of Camera"
def check_and_configure_allow_use_of_camera():
    try:
        # Chemin de la clé de registre pour la politique "Allow Use of Camera"
        registry_path = r"SOFTWARE\Policies\Microsoft\Camera"
        key_name = "AllowCamera"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path, 0, winreg.KEY_SET_VALUE | winreg.KEY_READ)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérifier si la valeur est correcte (0 = Disabled)
                if value == 0:
                    print(f"{GREEN}18.10.10.1 'Allow Use of Camera' : Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.10.1 'Allow Use of Camera' : Non conforme (Valeur Relevée: {value}){RESET}")
                    # Configuration de la valeur à 0 (Disabled)
                    reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path, 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(reg_key, key_name, 0, winreg.REG_DWORD, 0)
                    winreg.CloseKey(reg_key)
                    print(f"{YELLOW}18.10.10.1 'Allow Use of Camera' : Modifiée à 'Disabled'.{RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.10.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.10.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.10.1 : {e}{RESET}")

@compliance_check
# Fonction de vérification et modification pour la politique "Turn off cloud consumer account state content"
def check_and_configure_disable_consumer_account_state_content():
    try:
        # Chemin de la clé de registre pour la politique "Turn off cloud consumer account state content"
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        key_name = "DisableConsumerAccountStateContent"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path, 0, winreg.KEY_SET_VALUE | winreg.KEY_READ)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérifier si la valeur est correcte (1 = Enabled)
                if value == 1:
                    print(f"{GREEN}18.10.12.1 'Turn off cloud consumer account state content' : Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.12.1 'Turn off cloud consumer account state content' : Non conforme (Valeur Relevée: {value}){RESET}")
                    # Configuration de la valeur à 1 (Enabled)
                    reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path, 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(reg_key, key_name, 0, winreg.REG_DWORD, 1)
                    winreg.CloseKey(reg_key)
                    print(f"{YELLOW}18.10.12.1 'Turn off cloud consumer account state content' : Modifiée à 'Enabled'.{RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.12.1 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.12.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.12.1 : {e}{RESET}")

@compliance_check
# Fonction de vérification et modification pour la politique "Turn off cloud optimized content"
def check_and_configure_disable_cloud_optimized_content():
    try:
        # Chemin de la clé de registre pour la politique "Turn off cloud optimized content"
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        key_name = "DisableCloudOptimizedContent"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path, 0, winreg.KEY_SET_VALUE | winreg.KEY_READ)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérifier si la valeur est correcte (1 = Enabled)
                if value == 1:
                    print(f"{GREEN}18.10.12.2 'Turn off cloud optimized content' : Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.12.2 'Turn off cloud optimized content' : Non conforme (Valeur Relevée: {value}){RESET}")
                    # Configuration de la valeur à 1 (Enabled)
                    reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path, 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(reg_key, key_name, 0, winreg.REG_DWORD, 1)
                    winreg.CloseKey(reg_key)
                    print(f"{YELLOW}18.10.12.2 'Turn off cloud optimized content' : Modifiée à 'Enabled'.{RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.12.2 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.12.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.12.2 : {e}{RESET}")

@compliance_check
# Fonction de vérification et modification pour la politique "Turn off Microsoft consumer experiences"
def check_and_configure_disable_microsoft_consumer_experiences():
    try:
        # Chemin de la clé de registre pour la politique "Turn off Microsoft consumer experiences"
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        key_name = "DisableWindowsConsumerFeatures"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path, 0, winreg.KEY_SET_VALUE | winreg.KEY_READ)
            try:
                # Récupérer la valeur de la clé de registre
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérifier si la valeur est correcte (1 = Enabled)
                if value == 1:
                    print(f"{GREEN}18.10.12.3 'Turn off Microsoft consumer experiences' : Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.12.3 'Turn off Microsoft consumer experiences' : Non conforme (Valeur Relevée: {value}){RESET}")
                    # Configuration de la valeur à 1 (Enabled)
                    reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path, 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(reg_key, key_name, 0, winreg.REG_DWORD, 1)
                    winreg.CloseKey(reg_key)
                    print(f"{YELLOW}18.10.12.3 'Turn off Microsoft consumer experiences' : Modifiée à 'Enabled'.{RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.12.3 Clé de registre '{key_name}' non trouvée dans '{registry_path}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.12.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.12.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.13.1 : Vérifier "Require pin for pairing" dans le registre
def check_require_pin_for_pairing():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Connect"
        key_name = "RequirePinForPairing"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1 or value == 2:
                    print(f"{GREEN}18.10.13.1 Require pin for pairing: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.13.1 Require pin for pairing: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.13.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.13.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.13.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.14.1 : Vérifier "Do not display the password reveal button" dans le registre
def check_disable_password_reveal():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\CredUI"
        key_name = "DisablePasswordReveal"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.14.1 Do not display the password reveal button: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.14.1 Do not display the password reveal button: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.14.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.14.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.14.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.14.2 : Vérifier "Enumerate administrator accounts on elevation" dans le registre
def check_enumerate_administrator_accounts():
    try:
        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
        key_name = "EnumerateAdministrators"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.14.2 Enumerate administrator accounts on elevation: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.14.2 Enumerate administrator accounts on elevation: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.14.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.14.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.14.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.14.3 : Vérifier "Prevent the use of security questions for local accounts" dans le registre
def check_prevent_security_questions_for_local_accounts():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\System"
        key_name = "NoLocalPasswordResetQuestions"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.14.3 Prevent the use of security questions for local accounts: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.14.3 Prevent the use of security questions for local accounts: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.14.3 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.14.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.14.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.15.1 : Vérifier "Allow Diagnostic Data" dans le registre
def check_allow_diagnostic_data():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        key_name = "AllowTelemetry"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0 or value == 1:
                    print(f"{GREEN}18.10.15.1 Allow Diagnostic Data: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.15.1 Allow Diagnostic Data: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.15.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.15.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.15.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.15.2 : Vérifier "Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service" dans le registre
def check_disable_authenticated_proxy_usage():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        key_name = "DisableEnterpriseAuthProxy"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.15.2 Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.15.2 Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.15.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.15.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.15.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.15.3 : Vérifier "Disable OneSettings Downloads" dans le registre
def check_disable_onesettings_downloads():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        key_name = "DisableOneSettingsDownloads"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.15.3 Disable OneSettings Downloads: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.15.3 Disable OneSettings Downloads: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.15.3 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.15.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.15.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.15.4 : Vérifier "Do not show feedback notifications" dans le registre
def check_do_not_show_feedback_notifications():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        key_name = "DoNotShowFeedbackNotifications"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.15.4 Do not show feedback notifications: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.15.4 Do not show feedback notifications: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.15.4 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.15.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.15.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.15.5 : Vérifier "Enable OneSettings Auditing" dans le registre
def check_enable_onesettings_auditing():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        key_name = "EnableOneSettingsAuditing"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.15.5 Enable OneSettings Auditing: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.15.5 Enable OneSettings Auditing: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.15.5 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.15.5 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.15.5 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.15.6 : Vérifier "Limit Diagnostic Log Collection" dans le registre
def check_limit_diagnostic_log_collection():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        key_name = "LimitDiagnosticLogCollection"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.15.6 Limit Diagnostic Log Collection: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.15.6 Limit Diagnostic Log Collection: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.15.6 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.15.6 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.15.6 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.15.7 : Vérifier "Limit Dump Collection" dans le registre
def check_limit_dump_collection():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        key_name = "LimitDumpCollection"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.15.7 Limit Dump Collection: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.15.7 Limit Dump Collection: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.15.7 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.15.7 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.15.7 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.15.8 : Vérifier "Toggle user control over Insider builds" dans le registre
def check_toggle_user_control_over_insider_builds():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
        key_name = "AllowBuildPreview"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.15.8 Toggle user control over Insider builds: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.15.8 Toggle user control over Insider builds: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.15.8 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.15.8 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.15.8 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.16.1 : Vérifier "Download Mode" dans le registre
def check_download_mode():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
        key_name = "DODownloadMode"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value != 3:
                    print(f"{GREEN}18.10.16.1 Download Mode: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.16.1 Download Mode: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.16.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.16.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.16.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.17.1 : Vérifier "Enable App Installer" dans le registre
def check_enable_app_installer():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
        key_name = "EnableAppInstaller"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.17.1 Enable App Installer: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.17.1 Enable App Installer: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.17.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.17.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.17.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.17.2 : Vérifier "Enable App Installer Experimental Features" dans le registre
def check_enable_experimental_features():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
        key_name = "EnableExperimentalFeatures"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.17.2 Enable App Installer Experimental Features: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.17.2 Enable App Installer Experimental Features: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.17.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.17.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.17.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.17.3 : Vérifier "Enable App Installer Hash Override" dans le registre
def check_enable_hash_override():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
        key_name = "EnableHashOverride"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.17.3 Enable App Installer Hash Override: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.17.3 Enable App Installer Hash Override: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.17.3 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.17.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.17.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.17.4 : Vérifier "Enable App Installer ms-appinstaller protocol" dans le registre
def check_enable_ms_appinstaller_protocol():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
        key_name = "EnableMSAppInstallerProtocol"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.17.4 Enable App Installer ms-appinstaller protocol: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.17.4 Enable App Installer ms-appinstaller protocol: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.17.4 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.17.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.17.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.25.1.1 : Vérifier "Control Event Log behavior when the log file reaches its maximum size" dans le registre
def check_event_log_retention():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
        key_name = "Retention"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == '0':
                    print(f"{GREEN}18.10.25.1.1 Control Event Log behavior when the log file reaches its maximum size: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.25.1.1 Control Event Log behavior when the log file reaches its maximum size: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.25.1.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.25.1.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.25.1.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.25.1.2 : Vérifier "Specify the maximum log file size (KB)" dans le registre
def check_max_log_file_size():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
        key_name = "MaxSize"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value >= 32768:
                    print(f"{GREEN}18.10.25.1.2 Specify the maximum log file size (KB): Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.25.1.2 Specify the maximum log file size (KB): Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.25.1.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.25.1.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.25.1.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.25.2.1 : Vérifier "Control Event Log behavior when the log file reaches its maximum size" pour la sécurité dans le registre
def check_security_event_log_retention():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
        key_name = "Retention"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == '0':
                    print(f"{GREEN}18.10.25.2.1 Control Event Log behavior when the log file reaches its maximum size: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.25.2.1 Control Event Log behavior when the log file reaches its maximum size: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.25.2.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.25.2.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.25.2.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.25.2.2 : Vérifier "Specify the maximum log file size (KB)" pour la sécurité dans le registre
def check_security_max_log_file_size():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
        key_name = "MaxSize"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value >= 196608:
                    print(f"{GREEN}18.10.25.2.2 Specify the maximum log file size (KB): Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.25.2.2 Specify the maximum log file size (KB): Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.25.2.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.25.2.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.25.2.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.25.3.1 : Vérifier "Control Event Log behavior when the log file reaches its maximum size" pour la configuration dans le registre
def check_setup_event_log_retention():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
        key_name = "Retention"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == '0':
                    print(f"{GREEN}18.10.25.3.1 Control Event Log behavior when the log file reaches its maximum size: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.25.3.1 Control Event Log behavior when the log file reaches its maximum size: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.25.3.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.25.3.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.25.3.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.25.3.2 : Vérifier "Specify the maximum log file size (KB)" pour la configuration dans le registre
def check_setup_max_log_file_size():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
        key_name = "MaxSize"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value >= 32768:
                    print(f"{GREEN}18.10.25.3.2 Specify the maximum log file size (KB): Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.25.3.2 Specify the maximum log file size (KB): Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.25.3.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.25.3.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.25.3.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.25.4.1 : Vérifier "Control Event Log behavior when the log file reaches its maximum size" pour le système dans le registre
def check_system_event_log_retention():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
        key_name = "Retention"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == '0':
                    print(f"{GREEN}18.10.25.4.1 Control Event Log behavior when the log file reaches its maximum size: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.25.4.1 Control Event Log behavior when the log file reaches its maximum size: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.25.4.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.25.4.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.25.4.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.25.4.2 : Vérifier "Specify the maximum log file size (KB)" pour le système dans le registre
def check_system_max_log_file_size():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
        key_name = "MaxSize"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value >= 32768:
                    print(f"{GREEN}18.10.25.4.2 Specify the maximum log file size (KB): Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.25.4.2 Specify the maximum log file size (KB): Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.25.4.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.25.4.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.25.4.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.28.2 : Vérifier "Turn off account-based insights, recent, favorite, and recommended files in File Explorer" dans le registre
def check_disable_account_based_insights():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Explorer"
        key_name = "DisableGraphRecentItems"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.28.2 Turn off account-based insights, recent, favorite, and recommended files in File Explorer: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.28.2 Turn off account-based insights, recent, favorite, and recommended files in File Explorer: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.28.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.28.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.28.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.28.3 : Vérifier "Turn off Data Execution Prevention for Explorer" dans le registre
def check_disable_data_execution_prevention_for_explorer():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Explorer"
        key_name = "NoDataExecutionPrevention"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.28.3 Turn off Data Execution Prevention for Explorer: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.28.3 Turn off Data Execution Prevention for Explorer: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.28.3 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.28.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.28.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.28.4 : Vérifier "Turn off heap termination on corruption" dans le registre
def check_no_heap_termination_on_corruption():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Explorer"
        key_name = "NoHeapTerminationOnCorruption"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.28.4 Turn off heap termination on corruption: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.28.4 Turn off heap termination on corruption: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.28.4 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.28.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.28.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.28.5 : Vérifier "Turn off shell protocol protected mode" dans le registre
def check_shell_protocol_protected_mode():
    try:
        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        key_name = "PreXPSP2ShellProtocolBehavior"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.28.5 Turn off shell protocol protected mode: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.28.5 Turn off shell protocol protected mode: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.28.5 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.28.5 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.28.5 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.36.1 : Vérifier "Turn off location" dans le registre
def check_turn_off_location():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
        key_name = "DisableLocation"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.36.1 Turn off location: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.36.1 Turn off location: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.36.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.36.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.36.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.40.1 : Vérifier "Allow Message Service Cloud Sync" dans le registre
def check_allow_message_service_cloud_sync():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Messaging"
        key_name = "AllowMessageSync"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.40.1 Allow Message Service Cloud Sync: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.40.1 Allow Message Service Cloud Sync: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.40.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.40.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.40.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.41.1 : Vérifier "Block all consumer Microsoft account user authentication" dans le registre
def check_block_consumer_microsoft_account_authentication():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\MicrosoftAccount"
        key_name = "DisableUserAuth"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.41.1 Block all consumer Microsoft account user authentication: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.41.1 Block all consumer Microsoft account user authentication: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.41.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.41.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.41.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.42.5.1 : Vérifier "Configure local setting override for reporting to Microsoft MAPS" dans le registre
def check_local_setting_override_for_map_reporting():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
        key_name = "LocalSettingOverrideSpynetReporting"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.42.5.1 Configure local setting override for reporting to Microsoft MAPS: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.42.5.1 Configure local setting override for reporting to Microsoft MAPS: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.42.5.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.42.5.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.42.5.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.42.5.2 : Vérifier "Join Microsoft MAPS" dans le registre
def check_join_microsoft_maps():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
        key_name = "SpynetReporting"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.42.5.2 Join Microsoft MAPS: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.42.5.2 Join Microsoft MAPS: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.42.5.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.42.5.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.42.5.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.42.6.1.1 : Vérifier "Configure Attack Surface Reduction rules" dans le registre
def check_configure_attack_surface_reduction_rules():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
        key_name = "ExploitGuard_ASR_Rules"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.42.6.1.1 Configure Attack Surface Reduction rules: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.42.6.1.1 Configure Attack Surface Reduction rules: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.42.6.1.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.42.6.1.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.42.6.1.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.42.6.1.2 : Vérifier "Set the state for each ASR rule" dans le registre
def check_asr_rules():
    asr_rule_ids = [
        "26190899-1602-49e8-8b27-eb1d0a1ce869",
        "3b576869-a4ec-4529-8536-b80a7769e899",
        "56a863a9-875e-4185-98a7-b882c64b5ce5",
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
        "d3e037e1-3eb8-44c8-a917-57927947596d",
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
        "e6db77e5-3df2-4cf1-b95a-636979351e5b"
    ]
    
    registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
    
    try:
        for rule_id in asr_rule_ids:
            rule_path = f"{registry_path}:{rule_id}"
            try:
                reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rule_path)
                value, _ = winreg.QueryValueEx(reg_key, "")
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de chaque règle ASR
                if value == 1:
                    print(f"{GREEN}18.10.42.6.1.2 ASR Rule {rule_id}: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.42.6.1.2 ASR Rule {rule_id}: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.42.6.1.2 Clé de registre pour ASR Rule {rule_id} non trouvée.{RESET}")
                return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.42.6.1.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.42.6.3.1 : Vérifier "Prevent users and apps from accessing dangerous websites" dans le registre
def check_prevent_access_to_dangerous_websites():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
        key_name = "EnableNetworkProtection"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.42.6.3.1 Prevent users and apps from accessing dangerous websites: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.42.6.3.1 Prevent users and apps from accessing dangerous websites: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.42.6.3.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.42.6.3.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.42.6.3.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.42.7.1 : Vérifier "Enable file hash computation feature" dans le registre
def check_enable_file_hash_computation():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"
        key_name = "EnableFileHashComputation"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.42.7.1 Enable file hash computation feature: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.42.7.1 Enable file hash computation feature: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.42.7.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.42.7.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.42.7.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.42.10.1 : Vérifier "Scan all downloaded files and attachments" dans le registre
def check_scan_all_downloaded_files_and_attachments():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        key_name = "DisableIOAVProtection"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.42.10.1 Scan all downloaded files and attachments: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.42.10.1 Scan all downloaded files and attachments: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.42.10.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.42.10.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.42.10.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.42.10.2 : Vérifier "Turn off real-time protection" dans le registre
def check_turn_off_real_time_protection():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        key_name = "DisableRealtimeMonitoring"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.42.10.2 Turn off real-time protection: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.42.10.2 Turn off real-time protection: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.42.10.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.42.10.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.42.10.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.42.10.3 : Vérifier "Turn on behavior monitoring" dans le registre
def check_turn_on_behavior_monitoring():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        key_name = "DisableBehaviorMonitoring"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.42.10.3 Turn on behavior monitoring: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.42.10.3 Turn on behavior monitoring: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.42.10.3 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.42.10.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.42.10.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.42.10.4 : Vérifier "Turn on script scanning" dans le registre
def check_turn_on_script_scanning():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        key_name = "DisableScriptScanning"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.42.10.4 Turn on script scanning: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.42.10.4 Turn on script scanning: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.42.10.4 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.42.10.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.42.10.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.42.12.1 : Vérifier "Configure Watson events" dans le registre
def check_configure_watson_events():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"
        key_name = "DisableGenericRePorts"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.42.12.1 Configure Watson events: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.42.12.1 Configure Watson events: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.42.12.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.42.12.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.42.12.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.42.13.1 : Vérifier "Scan packed executables" dans le registre
def check_scan_packed_executables():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
        key_name = "DisablePackedExeScanning"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.42.13.1 Scan packed executables: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.42.13.1 Scan packed executables: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.42.13.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.42.13.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.42.13.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.42.13.2 : Vérifier "Scan removable drives" dans le registre
def check_scan_removable_drives():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
        key_name = "DisableRemovableDriveScanning"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.42.13.2 Scan removable drives: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.42.13.2 Scan removable drives: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.42.13.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.42.13.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.42.13.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.42.13.3 : Vérifier "Turn on e-mail scanning" dans le registre
def check_turn_on_email_scanning():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
        key_name = "DisableEmailScanning"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.42.13.3 Turn on e-mail scanning: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.42.13.3 Turn on e-mail scanning: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.42.13.3 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.42.13.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.42.13.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.42.16 : Vérifier "Configure detection for potentially unwanted applications" dans le registre
def check_configure_detection_for_pua():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender"
        key_name = "PUAProtection"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.42.16 Configure detection for potentially unwanted applications: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.42.16 Configure detection for potentially unwanted applications: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.42.16 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.42.16 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.42.16 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.42.17 : Vérifier "Turn off Microsoft Defender AntiVirus" dans le registre
def check_turn_off_microsoft_defender_anti_virus():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender"
        key_name = "DisableAntiSpyware"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.42.17 Turn off Microsoft Defender AntiVirus: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.42.17 Turn off Microsoft Defender AntiVirus: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.42.17 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.42.17 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.42.17 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.43.1 : Vérifier "Allow auditing events in Microsoft Defender Application Guard" dans le registre
def check_allow_auditing_events_in_app_guard():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\AppHVSI"
        key_name = "AuditApplicationGuard"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.43.1 Allow auditing events in Microsoft Defender Application Guard: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.43.1 Allow auditing events in Microsoft Defender Application Guard: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.43.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.43.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.43.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.43.2 : Vérifier "Allow camera and microphone access in Microsoft Defender Application Guard" dans le registre
def check_allow_camera_microphone_access_in_app_guard():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\AppHVSI"
        key_name = "AllowCameraMicrophoneRedirection"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.43.2 Allow camera and microphone access in Microsoft Defender Application Guard: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.43.2 Allow camera and microphone access in Microsoft Defender Application Guard: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.43.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.43.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.43.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.43.3 : Vérifier "Allow data persistence for Microsoft Defender Application Guard" dans le registre
def check_allow_data_persistence_for_app_guard():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\AppHVSI"
        key_name = "AllowPersistence"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.43.3 Allow data persistence for Microsoft Defender Application Guard: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.43.3 Allow data persistence for Microsoft Defender Application Guard: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.43.3 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.43.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.43.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.43.4 : Vérifier "Allow files to download and save to the host operating system from Microsoft Defender Application Guard" dans le registre
def check_allow_files_to_download_and_save_to_host():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\AppHVSI"
        key_name = "SaveFilesToHost"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.43.4 Allow files to download and save to the host operating system from Microsoft Defender Application Guard: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.43.4 Allow files to download and save to the host operating system from Microsoft Defender Application Guard: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.43.4 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.43.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.43.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.43.5 : Vérifier "Configure Microsoft Defender Application Guard clipboard settings: Clipboard behavior setting" dans le registre
def check_configure_defender_application_guard_clipboard():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\AppHVSI"
        key_name = "AppHVSIClipboardSettings"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.43.5 Configure Microsoft Defender Application Guard clipboard settings: Clipboard behavior setting: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.43.5 Configure Microsoft Defender Application Guard clipboard settings: Clipboard behavior setting: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.43.5 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.43.5 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.43.5 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.43.6 : Vérifier "Turn on Microsoft Defender Application Guard in Managed Mode" dans le registre
def check_turn_on_microsoft_defender_app_guard_managed_mode():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\AppHVSI"
        key_name = "AllowAppHVSI_ProviderSet"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.43.6 Turn on Microsoft Defender Application Guard in Managed Mode: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.43.6 Turn on Microsoft Defender Application Guard in Managed Mode: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.43.6 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.43.6 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.43.6 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.49.1 : Vérifier "Enable news and interests on the taskbar" dans le registre
def check_enable_news_and_interests_on_taskbar():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"
        key_name = "EnableFeeds"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.49.1 Enable news and interests on the taskbar: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.49.1 Enable news and interests on the taskbar: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.49.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.49.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.49.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.50.1 : Vérifier "Prevent the usage of OneDrive for file storage" dans le registre
def check_prevent_usage_of_onedrive_for_file_storage():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\OneDrive"
        key_name = "DisableFileSyncNGSC"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.50.1 Prevent the usage of OneDrive for file storage: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.50.1 Prevent the usage of OneDrive for file storage: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.50.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.50.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.50.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.55.1 : Vérifier "Turn off Push To Install service" dans le registre
def check_turn_off_push_to_install_service():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\PushToInstall"
        key_name = "DisablePushToInstall"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.55.1 Turn off Push To Install service: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.55.1 Turn off Push To Install service: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.55.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.55.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.55.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.56.2.2 : Vérifier "Disable Cloud Clipboard integration for server-to-client data transfer" dans le registre
def check_disable_cloud_clipboard_integration():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client"
        key_name = "DisableCloudClipboardIntegration"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.56.2.2 Disable Cloud Clipboard integration for server-to-client data transfer: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.2.2 Disable Cloud Clipboard integration for server-to-client data transfer: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.2.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.2.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.2.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.56.2.3 : Vérifier "Do not allow passwords to be saved" dans le registre
def check_do_not_allow_passwords_to_be_saved():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "DisablePasswordSaving"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.56.2.3 Do not allow passwords to be saved: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.2.3 Do not allow passwords to be saved: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.2.3 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.2.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.2.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.56.3.2.1 : Vérifier "Allow users to connect remotely by using Remote Desktop Services" dans le registre
def check_allow_users_to_connect_remotely():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "fDenyTSConnections"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.56.3.2.1 Allow users to connect remotely by using Remote Desktop Services: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.3.2.1 Allow users to connect remotely by using Remote Desktop Services: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.3.2.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.3.2.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.3.2.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.56.3.3.1 : Vérifier "Allow UI Automation redirection" dans le registre
def check_allow_ui_automation_redirection():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "EnableUiaRedirection"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.56.3.3.1 Allow UI Automation redirection: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.3.3.1 Allow UI Automation redirection: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.3.3.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.3.3.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.3.3.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.56.3.3.2 : Vérifier "Do not allow COM port redirection" dans le registre
def check_do_not_allow_com_port_redirection():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "fDisableCcm"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.56.3.3.2 Do not allow COM port redirection: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.3.3.2 Do not allow COM port redirection: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.3.3.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.3.3.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.3.3.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.56.3.3.3 : Vérifier "Do not allow drive redirection" dans le registre
def check_do_not_allow_drive_redirection():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "fDisableCdm"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.56.3.3.3 Do not allow drive redirection: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.3.3.3 Do not allow drive redirection: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.3.3.3 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.3.3.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.3.3.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.56.3.3.4 : Vérifier "Do not allow location redirection" dans le registre
def check_do_not_allow_location_redirection():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "fDisableLocationRedir"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.56.3.3.4 Do not allow location redirection: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.3.3.4 Do not allow location redirection: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.3.3.4 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.3.3.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.3.3.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.56.3.3.5 : Vérifier "Do not allow LPT port redirection" dans le registre
def check_do_not_allow_lpt_port_redirection():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "fDisableLPT"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.56.3.3.5 Do not allow LPT port redirection: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.3.3.5 Do not allow LPT port redirection: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.3.3.5 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.3.3.5 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.3.3.5 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.56.3.3.6 : Vérifier "Do not allow supported Plug and Play device redirection" dans le registre
def check_do_not_allow_pnp_device_redirection():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "fDisablePNPRedir"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.56.3.3.6 Do not allow supported Plug and Play device redirection: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.3.3.6 Do not allow supported Plug and Play device redirection: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.3.3.6 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.3.3.6 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.3.3.6 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.56.3.3.7 : Vérifier "Do not allow WebAuthn redirection" dans le registre
def check_do_not_allow_webauthn_redirection():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "fDisableWebAuthn"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.56.3.3.7 Do not allow WebAuthn redirection: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.3.3.7 Do not allow WebAuthn redirection: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.3.3.7 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.3.3.7 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.3.3.7 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.56.3.9.1 : Vérifier "Always prompt for password upon connection" dans le registre
def check_always_prompt_for_password():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "fPromptForPassword"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.56.3.9.1 Always prompt for password upon connection: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.3.9.1 Always prompt for password upon connection: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.3.9.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.3.9.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.3.9.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.56.3.9.2 : Vérifier "Require secure RPC communication" dans le registre
def check_require_secure_rpc_communication():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "fEncryptRPCTraffic"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.56.3.9.2 Require secure RPC communication: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.3.9.2 Require secure RPC communication: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.3.9.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.3.9.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.3.9.2 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration de la clé de registre 'SecurityLayer'
def check_require_specific_security_layer_for_rdp():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "SecurityLayer"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 2:
                    print(f"{GREEN}18.10.56.3.9.3 Require use of specific security layer for RDP connections: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.3.9.3 Require use of specific security layer for RDP connections: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.3.9.3 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.3.9.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.3.9.3 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration de la clé de registre 'UserAuthentication'
def check_require_user_authentication_for_nla():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "UserAuthentication"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.56.3.9.4 Require user authentication for remote connections by using Network Level Authentication: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.3.9.4 Require user authentication for remote connections by using Network Level Authentication: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.3.9.4 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.3.9.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.3.9.4 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration de la clé de registre 'MinEncryptionLevel'
def check_client_connection_encryption_level():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "MinEncryptionLevel"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 3:
                    print(f"{GREEN}18.10.56.3.9.5 Set client connection encryption level: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.3.9.5 Set client connection encryption level: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.3.9.5 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.3.9.5 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.3.9.5 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration du délai d'inactivité des sessions RDS
def check_idle_session_timeout():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "MaxIdleTime"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value > 0 and value <= 900000:
                    print(f"{GREEN}18.10.56.3.10.1 Set time limit for active but idle Remote Desktop Services sessions: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.3.10.1 Set time limit for active but idle Remote Desktop Services sessions: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.3.10.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.3.10.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.3.10.1 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration du délai de déconnexion des sessions RDS
def check_disconnected_session_timeout():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "MaxDisconnectionTime"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 60000:  # 60000 millisecondes = 1 minute
                    print(f"{GREEN}18.10.56.3.10.2 Set time limit for disconnected sessions: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.3.10.2 Set time limit for disconnected sessions: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.3.10.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.3.10.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.3.10.2 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration de la suppression des dossiers temporaires à la fermeture de session RDS
def check_delete_temp_dirs_on_exit():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        key_name = "DeleteTempDirsOnExit"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:  # 0 signifie que la suppression des dossiers temporaires est désactivée
                    print(f"{GREEN}18.10.56.3.11.1 Do not delete temp folders upon exit: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.56.3.11.1 Do not delete temp folders upon exit: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.56.3.11.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.56.3.11.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.56.3.11.1 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration du téléchargement des pièces jointes RSS
def check_disable_enclosure_download():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
        key_name = "DisableEnclosureDownload"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:  # 1 signifie que le téléchargement des pièces jointes est désactivé
                    print(f"{GREEN}18.10.57.1 Prevent downloading of enclosures: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.57.1 Prevent downloading of enclosures: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.57.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.57.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.57.1 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration de la recherche dans le cloud
def check_allow_cloud_search():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        key_name = "AllowCloudSearch"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:  # 0 signifie que la recherche dans le cloud est désactivée
                    print(f"{GREEN}18.10.58.2 Allow Cloud Search: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.58.2 Allow Cloud Search: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.58.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.58.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.58.2 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration de Cortana
def check_allow_cortana():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        key_name = "AllowCortana"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:  # 0 signifie que Cortana est désactivé
                    print(f"{GREEN}18.10.58.3 Allow Cortana: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.58.3 Allow Cortana: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.58.3 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.58.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.58.3 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration de Cortana au-dessus de l'écran de verrouillage
def check_allow_cortana_above_lock():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        key_name = "AllowCortanaAboveLock"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:  # 0 signifie que l'accès Cortana au-dessus du verrouillage est désactivé
                    print(f"{GREEN}18.10.58.4 Allow Cortana above lock screen: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.58.4 Allow Cortana above lock screen: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.58.4 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.58.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.58.4 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration de l'indexation des fichiers chiffrés
def check_allow_indexing_encrypted_files():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        key_name = "AllowIndexingEncryptedStoresOrItems"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:  # 0 signifie que l'indexation des fichiers chiffrés est désactivée
                    print(f"{GREEN}18.10.58.5 Allow indexing of encrypted files: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.58.5 Allow indexing of encrypted files: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.58.5 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.58.5 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.58.5 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration "Allow search and Cortana to use location"
def check_allow_search_to_use_location():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        key_name = "AllowSearchToUseLocation"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:  # 0 signifie que l'accès à la localisation est désactivé
                    print(f"{GREEN}18.10.58.6 Allow search and Cortana to use location: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.58.6 Allow search and Cortana to use location: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.58.6 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.58.6 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.58.6 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration "Allow search highlights"
def check_allow_search_highlights():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        key_name = "EnableDynamicContentInWSB"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:  # 0 signifie que les mises en avant sont désactivées
                    print(f"{GREEN}18.10.58.7 Allow search highlights: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.58.7 Allow search highlights: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.58.7 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.58.7 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.58.7 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration "Turn off KMS Client Online AVS Validation"
def check_turn_off_kms_client_online_avs_validation():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
        key_name = "NoGenTicket"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:  # 1 signifie que l'envoi des données est désactivé
                    print(f"{GREEN}18.10.62.1 Turn off KMS Client Online AVS Validation: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.62.1 Turn off KMS Client Online AVS Validation: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.62.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.62.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.62.1 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration "Disable all apps from Microsoft Store"
def check_disable_store_apps():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\WindowsStore"
        key_name = "DisableStoreApps"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:  # 1 signifie que les applications du Microsoft Store sont désactivées
                    print(f"{GREEN}18.10.65.1 Disable all apps from Microsoft Store: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.65.1 Disable all apps from Microsoft Store: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.65.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.65.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.65.1 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration "Only display the private store within the Microsoft Store"
def check_private_store_only():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\WindowsStore"
        key_name = "RequirePrivateStoreOnly"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:  # 1 signifie que seul le magasin privé est affiché
                    print(f"{GREEN}18.10.65.2 Only display the private store within the Microsoft Store: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.65.2 Only display the private store within the Microsoft Store: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.65.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.65.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.65.2 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration "Turn off Automatic Download and Install of updates"
def check_auto_download_install():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\WindowsStore"
        key_name = "AutoDownload"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 4:  # 4 signifie que le téléchargement automatique est désactivé
                    print(f"{GREEN}18.10.65.3 Turn off Automatic Download and Install of updates: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.65.3 Turn off Automatic Download and Install of updates: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.65.3 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.65.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.65.3 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration "Turn off the offer to update to the latest version of Windows"
def check_off_update_offer():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\WindowsStore"
        key_name = "DisableOSUpgrade"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:  # 1 signifie que l'offre de mise à niveau est désactivée
                    print(f"{GREEN}18.10.65.4 Turn off the offer to update to the latest version of Windows: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.65.4 Turn off the offer to update to the latest version of Windows: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.65.4 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.65.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.65.4 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration "Turn off the Store application"
def check_store_application():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\WindowsStore"
        key_name = "RemoveWindowsStore"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:  # 1 signifie que l'accès à Microsoft Store est désactivé
                    print(f"{GREEN}18.10.65.5 Turn off the Store application: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.65.5 Turn off the Store application: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.65.5 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.65.5 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.65.5 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration "Allow widgets"
def check_allow_widgets():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Dsh"
        key_name = "AllowNewsAndInterests"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:  # 0 signifie que les widgets sont désactivés
                    print(f"{GREEN}18.10.71.1 Allow widgets: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.71.1 Allow widgets: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.71.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.71.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.71.1 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration "Automatic Data Collection"
def check_automatic_data_collection():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
        key_name = "CaptureThreatWindow"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:  # 1 signifie que la collecte des données est activée
                    print(f"{GREEN}18.10.75.1.1 Automatic Data Collection: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.75.1.1 Automatic Data Collection: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.75.1.1 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.75.1.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.75.1.1 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration "Notify Malicious"
def check_notify_malicious():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
        key_name = "NotifyMalicious"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:  # 1 signifie que la notification est activée
                    print(f"{GREEN}18.10.75.1.2 Notify Malicious: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.75.1.2 Notify Malicious: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.75.1.2 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.75.1.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.75.1.2 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration "Notify Password Reuse"
def check_notify_password_reuse():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
        key_name = "NotifyPasswordReuse"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:  # 1 signifie que la notification est activée pour la réutilisation de mot de passe
                    print(f"{GREEN}18.10.75.1.3 Notify Password Reuse: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.75.1.3 Notify Password Reuse: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.75.1.3 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.75.1.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.75.1.3 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration "Notify Unsafe App"
def check_notify_unsafe_app():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
        key_name = "NotifyUnsafeApp"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:  # 1 signifie que la notification est activée pour les applications non sécurisées
                    print(f"{GREEN}18.10.75.1.4 Notify Unsafe App: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.75.1.4 Notify Unsafe App: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.75.1.4 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.75.1.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.75.1.4 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration "Service Enabled"
def check_service_enabled():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
        key_name = "ServiceEnabled"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:  # 1 signifie que la protection renforcée contre le phishing est activée
                    print(f"{GREEN}18.10.75.1.5 Service Enabled: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.75.1.5 Service Enabled: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.75.1.5 Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.75.1.5 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.75.1.5 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration de Windows Defender SmartScreen
def check_defender_smartscreen():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\System"
        enable_smartscreen_key = "EnableSmartScreen"
        shell_smartscreen_level_key = "ShellSmartScreenLevel"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Vérification des valeurs de registre
                enable_smartscreen_value, _ = winreg.QueryValueEx(reg_key, enable_smartscreen_key)
                shell_smartscreen_level_value, _ = winreg.QueryValueEx(reg_key, shell_smartscreen_level_key)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de "EnableSmartScreen"
                if enable_smartscreen_value == 1 and shell_smartscreen_level_value == "Block":
                    print(f"{GREEN}18.10.75.2.1 Windows Defender SmartScreen: Conforme (Valeur Relevée: {enable_smartscreen_value}, {shell_smartscreen_level_value}){RESET}")
                else:
                    print(f"{RED}18.10.75.2.1 Windows Defender SmartScreen: Non conforme (Valeur Relevée: {enable_smartscreen_value}, {shell_smartscreen_level_value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.75.2.1 Clés de registre non trouvées pour 'EnableSmartScreen' ou 'ShellSmartScreenLevel'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.75.2.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.75.2.1 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration de l'enregistrement et de la diffusion de jeux Windows
def check_game_recording():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\GameDVR"
        allow_game_dvr_key = "AllowGameDVR"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Vérification de la valeur de la clé de registre
                allow_game_dvr_value, _ = winreg.QueryValueEx(reg_key, allow_game_dvr_key)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de "AllowGameDVR"
                if allow_game_dvr_value == 0:
                    print(f"{GREEN}18.10.77.1 Windows Game Recording and Broadcasting: Conforme (Valeur Relevée: {allow_game_dvr_value}){RESET}")
                else:
                    print(f"{RED}18.10.77.1 Windows Game Recording and Broadcasting: Non conforme (Valeur Relevée: {allow_game_dvr_value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.77.1 Clé de registre non trouvée pour 'AllowGameDVR'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.77.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.77.1 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration de la sécurité d'authentification améliorée (ESS)
def check_ESS_configuration():
    try:
        registry_path = r"SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics"
        enable_ess_key = "EnableESSwithSupportedPeripherals"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Vérification de la valeur de la clé de registre
                enable_ess_value, _ = winreg.QueryValueEx(reg_key, enable_ess_key)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de "EnableESSwithSupportedPeripherals"
                if enable_ess_value == 1:
                    print(f"{GREEN}18.10.78.1 ESS avec périphériques pris en charge : Conforme (Valeur Relevée: {enable_ess_value}){RESET}")
                else:
                    print(f"{RED}18.10.78.1 ESS avec périphériques pris en charge : Non conforme (Valeur Relevée: {enable_ess_value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.78.1 Clé de registre non trouvée pour 'EnableESSwithSupportedPeripherals'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.78.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.78.1 : {e}{RESET}")

@compliance_check
# Fonction pour vérifier la configuration de la fonctionnalité "Suggested Apps"
def check_suggested_apps_configuration():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
        suggested_apps_key = "AllowSuggestedAppsInWindowsInkWorkspace"

        try:
            # Ouverture de la clé de registre
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                # Vérification de la valeur de la clé de registre
                suggested_apps_value, _ = winreg.QueryValueEx(reg_key, suggested_apps_key)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur "AllowSuggestedAppsInWindowsInkWorkspace"
                if suggested_apps_value == 0:
                    print(f"{GREEN}18.10.79.1 Suggestions d'applications dans Windows Ink Workspace : Conforme (Valeur Relevée: {suggested_apps_value}){RESET}")
                else:
                    print(f"{RED}18.10.79.1 Suggestions d'applications dans Windows Ink Workspace : Non conforme (Valeur Relevée: {suggested_apps_value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.79.1 Clé de registre non trouvée pour 'AllowSuggestedAppsInWindowsInkWorkspace'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.79.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.79.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.79.2 : Vérifier "Allow Windows Ink Workspace" via le registre
def check_allow_windows_ink_workspace():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
        key_name = "AllowWindowsInkWorkspace"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0 or value == 1:
                    print(f"{GREEN}18.10.79.2 Allow Windows Ink Workspace: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.79.2 Allow Windows Ink Workspace: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.79.2 Allow Windows Ink Workspace: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.79.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.79.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.80.1 : Vérifier "Allow user control over installs" via le registre
def check_allow_user_control_over_installs():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Installer"
        key_name = "EnableUserControl"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.80.1 Allow user control over installs: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.80.1 Allow user control over installs: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.80.1 Allow user control over installs: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.80.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.80.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.80.2 : Vérifier "Always install with elevated privileges" via le registre
def check_always_install_elevated_privileges():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Installer"
        key_name = "AlwaysInstallElevated"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.80.2 Always install with elevated privileges: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.80.2 Always install with elevated privileges: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.80.2 Always install with elevated privileges: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.80.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.80.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.80.3 : Vérifier "Prevent Internet Explorer security prompt for Windows Installer scripts" via le registre
def check_prevent_ie_security_prompt_for_installer_scripts():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Installer"
        key_name = "SafeForScripting"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.80.3 Prevent Internet Explorer security prompt for Windows Installer scripts: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.80.3 Prevent Internet Explorer security prompt for Windows Installer scripts: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.80.3 Prevent Internet Explorer security prompt for Windows Installer scripts: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.80.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.80.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.81.1 : Vérifier "Enable MPR notifications for the system" via le registre
def check_enable_mpr_notifications_for_system():
    try:
        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        key_name = "EnableMPR"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.81.1 Enable MPR notifications for the system: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.81.1 Enable MPR notifications for the system: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.81.1 Enable MPR notifications for the system: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.81.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.81.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.81.2 : Vérifier "Sign-in and lock last interactive user automatically after a restart" via le registre
def check_sign_in_and_lock_last_user_after_restart():
    try:
        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        key_name = "DisableAutomaticRestartSignOn"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.81.2 Sign-in and lock last interactive user automatically after a restart: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.81.2 Sign-in and lock last interactive user automatically after a restart: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.81.2 Sign-in and lock last interactive user automatically after a restart: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.81.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.81.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.86.1 : Vérifier "Turn on PowerShell Script Block Logging" via le registre
def check_turn_on_powershell_script_block_logging():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        key_name = "EnableScriptBlockLogging"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.86.1 Turn on PowerShell Script Block Logging: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.86.1 Turn on PowerShell Script Block Logging: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.86.1 Turn on PowerShell Script Block Logging: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.86.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.86.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.86.2 : Vérifier "Turn on PowerShell Transcription" via le registre
def check_turn_on_powershell_transcription():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        key_name = "EnableTranscripting"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.86.2 Turn on PowerShell Transcription: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.86.2 Turn on PowerShell Transcription: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.86.2 Turn on PowerShell Transcription: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.86.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.86.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.88.1.1 : Vérifier "Allow Basic authentication" via le registre
def check_allow_basic_authentication():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
        key_name = "AllowBasic"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.88.1.1 Allow Basic authentication: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.88.1.1 Allow Basic authentication: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.88.1.1 Allow Basic authentication: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.88.1.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.88.1.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.88.1.2 : Vérifier "Allow unencrypted traffic" via le registre
def check_allow_unencrypted_traffic():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
        key_name = "AllowUnencryptedTraffic"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.88.1.2 Allow unencrypted traffic: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.88.1.2 Allow unencrypted traffic: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.88.1.2 Allow unencrypted traffic: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.88.1.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.88.1.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.88.1.3 : Vérifier "Disallow Digest authentication" via le registre
def check_disallow_digest_authentication():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
        key_name = "AllowDigest"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.88.1.3 Disallow Digest authentication: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.88.1.3 Disallow Digest authentication: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.88.1.3 Disallow Digest authentication: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.88.1.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.88.1.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.88.2.1 : Vérifier "Allow Basic authentication" via le registre (WinRM Service)
def check_allow_basic_authentication_winrm_service():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        key_name = "AllowBasic"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.88.2.1 Allow Basic authentication (WinRM Service): Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.88.2.1 Allow Basic authentication (WinRM Service): Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.88.2.1 Allow Basic authentication (WinRM Service): Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.88.2.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.88.2.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.88.2.2 : Vérifier "Allow remote server management through WinRM" via le registre
def check_allow_remote_server_management_through_winrm():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        key_name = "AllowAutoConfig"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.88.2.2 Allow remote server management through WinRM: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.88.2.2 Allow remote server management through WinRM: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.88.2.2 Allow remote server management through WinRM: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.88.2.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.88.2.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.88.2.3 : Vérifier "Allow unencrypted traffic" via le registre (WinRM Service)
def check_allow_unencrypted_traffic_winrm_service():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        key_name = "AllowUnencryptedTraffic"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.88.2.3 Allow unencrypted traffic (WinRM Service): Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.88.2.3 Allow unencrypted traffic (WinRM Service): Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.88.2.3 Allow unencrypted traffic (WinRM Service): Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.88.2.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.88.2.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.88.2.4 : Vérifier "Disallow WinRM from storing RunAs credentials" via le registre (WinRM Service)
def check_disallow_winrm_storing_runas_credentials():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        key_name = "DisableRunAs"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.88.2.4 Disallow WinRM from storing RunAs credentials: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.88.2.4 Disallow WinRM from storing RunAs credentials: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.88.2.4 Disallow WinRM from storing RunAs credentials: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.88.2.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.88.2.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.89.1 : Vérifier "Allow Remote Shell Access" via le registre (WinRM Service)
def check_allow_remote_shell_access():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS"
        key_name = "AllowRemoteShellAccess"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.89.1 Allow Remote Shell Access: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.89.1 Allow Remote Shell Access: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.89.1 Allow Remote Shell Access: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.89.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.89.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.90.1 : Vérifier "Allow clipboard sharing with Windows Sandbox" via le registre
def check_allow_clipboard_sharing_with_windows_sandbox():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Sandbox"
        key_name = "AllowClipboardRedirection"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.90.1 Allow clipboard sharing with Windows Sandbox: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.90.1 Allow clipboard sharing with Windows Sandbox: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.90.1 Allow clipboard sharing with Windows Sandbox: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.90.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.90.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.90.2 : Vérifier "Allow networking in Windows Sandbox" via le registre
def check_allow_networking_in_windows_sandbox():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Sandbox"
        key_name = "AllowNetworking"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.90.2 Allow networking in Windows Sandbox: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.90.2 Allow networking in Windows Sandbox: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.90.2 Allow networking in Windows Sandbox: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.90.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.90.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.91.2.1 : Vérifier "Prevent users from modifying settings" via le registre
def check_prevent_users_from_modifying_settings():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"
        key_name = "DisallowExploitProtectionOverride"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.91.2.1 Prevent users from modifying settings: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.91.2.1 Prevent users from modifying settings: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.91.2.1 Prevent users from modifying settings: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.91.2.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.91.2.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.92.1.1 : Vérifier "No auto-restart with logged on users for scheduled automatic updates installations" via le registre
def check_no_auto_restart_with_logged_on_users():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        key_name = "NoAutoRebootWithLoggedOnUsers"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.92.1.1 No auto-restart with logged on users: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.92.1.1 No auto-restart with logged on users: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.92.1.1 No auto-restart with logged on users: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.92.1.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.92.1.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.92.2.1 : Vérifier "Configure Automatic Updates" via le registre
def check_configure_automatic_updates():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        key_name = "NoAutoUpdate"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.92.2.1 Configure Automatic Updates: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.92.2.1 Configure Automatic Updates: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.92.2.1 Configure Automatic Updates: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.92.2.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.92.2.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.92.2.2 : Vérifier "Configure Automatic Updates: Scheduled install day" via le registre
def check_configure_automatic_updates_scheduled_install_day():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        key_name = "ScheduledInstallDay"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.92.2.2 Configure Automatic Updates: Scheduled install day: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.92.2.2 Configure Automatic Updates: Scheduled install day: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.92.2.2 Configure Automatic Updates: Scheduled install day: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.92.2.2 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.92.2.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.92.2.3 : Vérifier "Enable features introduced via servicing that are off by default" via le registre
def check_enable_features_introduced_via_servicing():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        key_name = "AllowTemporaryEnterpriseFeatureControl"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.92.2.3 Enable features introduced via servicing that are off by default: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.92.2.3 Enable features introduced via servicing that are off by default: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.92.2.3 Enable features introduced via servicing that are off by default: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.92.2.3 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.92.2.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.92.2.4 : Vérifier "Remove access to 'Pause updates' feature" via le registre
def check_remove_access_to_pause_updates():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        key_name = "SetDisablePauseUXAccess"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.92.2.4 Remove access to 'Pause updates' feature: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.92.2.4 Remove access to 'Pause updates' feature: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.92.2.4 Remove access to 'Pause updates' feature: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.92.2.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.92.2.4 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.92.4.1 : Vérifier "Manage preview builds" via le registre
def check_manage_preview_builds():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        key_name = "ManagePreviewBuildsPolicyValue"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}18.10.92.4.1 Manage preview builds: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.92.4.1 Manage preview builds: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.92.4.1 Manage preview builds: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.92.4.1 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.92.4.1 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.92.4.2 : Vérifier "Select when Preview Builds and Feature Updates are received" via le registre
def check_select_when_preview_builds_and_feature_updates_are_received():
    try:
        registry_path_1 = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        key_name_1 = "DeferFeatureUpdates"
        
        registry_path_2 = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        key_name_2 = "DeferFeatureUpdatesPeriodInDays"

        try:
            # Vérifier la clé DeferFeatureUpdates
            reg_key_1 = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path_1)
            try:
                value_1, _ = winreg.QueryValueEx(reg_key_1, key_name_1)
                winreg.CloseKey(reg_key_1)

                # Vérification de la valeur de la clé DeferFeatureUpdates
                if value_1 == 1:
                    print(f"{GREEN}18.10.92.4.2 Defer Feature Updates: Conforme (Valeur Relevée: {value_1}){RESET}")
                else:
                    print(f"{RED}18.10.92.4.2 Defer Feature Updates: Non conforme (Valeur Relevée: {value_1}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.92.4.2 Clé de registre '{key_name_1}' non trouvée.{RESET}")
                return

            # Vérifier la clé DeferFeatureUpdatesPeriodInDays
            reg_key_2 = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path_2)
            try:
                value_2, _ = winreg.QueryValueEx(reg_key_2, key_name_2)
                winreg.CloseKey(reg_key_2)

                # Vérification de la valeur de la clé DeferFeatureUpdatesPeriodInDays
                if value_2 == 180:
                    print(f"{GREEN}18.10.92.4.2 Defer Feature Updates Period (180 days): Conforme (Valeur Relevée: {value_2}){RESET}")
                else:
                    print(f"{RED}18.10.92.4.2 Defer Feature Updates Period: Non conforme (Valeur Relevée: {value_2}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.92.4.2 Clé de registre '{key_name_2}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.92.4.2 La clé de registre '{registry_path_1}' ou '{registry_path_2}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.92.4.2 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.92.4.3 : Vérifier "Select when Quality Updates are received" via le registre
def check_select_when_quality_updates_are_received():
    try:
        registry_path_1 = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        key_name_1 = "DeferQualityUpdates"
        
        registry_path_2 = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        key_name_2 = "DeferQualityUpdatesPeriodInDays"

        try:
            # Vérifier la clé DeferQualityUpdates
            reg_key_1 = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path_1)
            try:
                value_1, _ = winreg.QueryValueEx(reg_key_1, key_name_1)
                winreg.CloseKey(reg_key_1)

                # Vérification de la valeur de la clé DeferQualityUpdates
                if value_1 == 1:
                    print(f"{GREEN}18.10.92.4.3 Defer Quality Updates: Conforme (Valeur Relevée: {value_1}){RESET}")
                else:
                    print(f"{RED}18.10.92.4.3 Defer Quality Updates: Non conforme (Valeur Relevée: {value_1}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.92.4.3 Clé de registre '{key_name_1}' non trouvée.{RESET}")
                return

            # Vérifier la clé DeferQualityUpdatesPeriodInDays
            reg_key_2 = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path_2)
            try:
                value_2, _ = winreg.QueryValueEx(reg_key_2, key_name_2)
                winreg.CloseKey(reg_key_2)

                # Vérification de la valeur de la clé DeferQualityUpdatesPeriodInDays
                if value_2 == 0:
                    print(f"{GREEN}18.10.92.4.3 Defer Quality Updates Period (0 days): Conforme (Valeur Relevée: {value_2}){RESET}")
                else:
                    print(f"{RED}18.10.92.4.3 Defer Quality Updates Period: Non conforme (Valeur Relevée: {value_2}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.92.4.3 Clé de registre '{key_name_2}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.92.4.3 La clé de registre '{registry_path_1}' ou '{registry_path_2}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.92.4.3 : {e}{RESET}")

@compliance_check
# Contrôle 18.10.92.4.4 : Vérifier "Enable optional updates" via le registre
def check_enable_optional_updates():
    try:
        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        key_name = "AllowOptionalContent"

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}18.10.92.4.4 Enable optional updates: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}18.10.92.4.4 Enable optional updates: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}18.10.92.4.4 Enable optional updates: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}18.10.92.4.4 La clé de registre '{registry_path}' n'existe pas.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 18.10.92.4.4 : {e}{RESET}")

@compliance_check
# Contrôle 19.5.1.1 : Vérifier "Turn off toast notifications on the lock screen" via le registre
def check_turn_off_toast_notifications_on_lock_screen():
    try:
        # Obtenir le SID de l'utilisateur (l'exemple ici utilise un SID générique pour le test)
        user_sid = r"S-1-5-21-1234567890-123456789-1234567890"  # Remplace ceci par le SID approprié

        registry_path = fr"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
        key_name = "NoToastApplicationNotificationOnLockScreen"

        # Vérification de la clé de registre pour l'utilisateur spécifié
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_USERS, user_sid + "\\" + registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}19.5.1.1 Turn off toast notifications on the lock screen: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}19.5.1.1 Turn off toast notifications on the lock screen: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}19.5.1.1 Turn off toast notifications on the lock screen: Clé de registre '{key_name}' non trouvée.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}19.5.1.1 La clé de registre '{registry_path}' n'existe pas pour l'utilisateur '{user_sid}'.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 19.5.1.1 : {e}{RESET}")

@compliance_check
# Contrôle 19.6.6.1.1 : Vérifier "Turn off Help Experience Improvement Program" via le registre
def check_turn_off_help_experience_improvement_program():
    try:
        # Obtenir le SID de l'utilisateur (l'exemple ici utilise un SID générique pour le test)
        user_sid = r"S-1-5-21-1234567890-123456789-1234567890"  # Remplace ceci par le SID approprié

        registry_path = r"SOFTWARE\Policies\Microsoft\Assistance\Client\1.0"
        key_name = "NoImplicitFeedback"

        # Vérification de la clé de registre pour l'utilisateur spécifié
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_USERS, user_sid + "\\" + registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}19.6.6.1.1 Turn off Help Experience Improvement Program: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}19.6.6.1.1 Turn off Help Experience Improvement Program: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}19.6.6.1.1 Clé de registre '{key_name}' non trouvée pour l'utilisateur '{user_sid}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}19.6.6.1.1 La clé de registre '{registry_path}' n'existe pas pour l'utilisateur '{user_sid}'.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 19.6.6.1.1 : {e}{RESET}")

@compliance_check
# Contrôle 19.7.5.1 : Vérifier "Do not preserve zone information in file attachments" via le registre
def check_do_not_preserve_zone_information_in_file_attachments():
    try:
        # Obtenir le SID de l'utilisateur (l'exemple ici utilise un SID générique pour le test)
        user_sid = r"S-1-5-21-1234567890-123456789-1234567890"  # Remplace ceci par le SID approprié

        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
        key_name = "SaveZoneInformation"

        # Vérification de la clé de registre pour l'utilisateur spécifié
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_USERS, user_sid + "\\" + registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 2:
                    print(f"{GREEN}19.7.5.1 Do not preserve zone information in file attachments: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}19.7.5.1 Do not preserve zone information in file attachments: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}19.7.5.1 Clé de registre '{key_name}' non trouvée pour l'utilisateur '{user_sid}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}19.7.5.1 La clé de registre '{registry_path}' n'existe pas pour l'utilisateur '{user_sid}'.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 19.7.5.1 : {e}{RESET}")

@compliance_check
# Contrôle 19.7.5.2 : Vérifier "Notify antivirus programs when opening attachments" via le registre
def check_notify_antivirus_programs_when_opening_attachments():
    try:
        # Obtenir le SID de l'utilisateur (l'exemple ici utilise un SID générique pour le test)
        user_sid = r"S-1-5-21-1234567890-123456789-1234567890"  # Remplace ceci par le SID approprié

        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
        key_name = "ScanWithAntiVirus"

        # Vérification de la clé de registre pour l'utilisateur spécifié
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_USERS, user_sid + "\\" + registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 3:
                    print(f"{GREEN}19.7.5.2 Notify antivirus programs when opening attachments: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}19.7.5.2 Notify antivirus programs when opening attachments: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}19.7.5.2 Clé de registre '{key_name}' non trouvée pour l'utilisateur '{user_sid}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}19.7.5.2 La clé de registre '{registry_path}' n'existe pas pour l'utilisateur '{user_sid}'.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 19.7.5.2 : {e}{RESET}")

@compliance_check
# Contrôle 19.7.8.1 : Vérifier "Configure Windows spotlight on lock screen" via le registre
def check_configure_windows_spotlight_on_lock_screen():
    try:
        # Obtenir le SID de l'utilisateur (l'exemple ici utilise un SID générique pour le test)
        user_sid = r"S-1-5-21-1234567890-123456789-1234567890"  # Remplace ceci par le SID approprié

        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        key_name = "ConfigureWindowsSpotlight"

        # Vérification de la clé de registre pour l'utilisateur spécifié
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_USERS, user_sid + "\\" + registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 2:
                    print(f"{GREEN}19.7.8.1 Configure Windows spotlight on lock screen: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}19.7.8.1 Configure Windows spotlight on lock screen: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}19.7.8.1 Clé de registre '{key_name}' non trouvée pour l'utilisateur '{user_sid}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}19.7.8.1 La clé de registre '{registry_path}' n'existe pas pour l'utilisateur '{user_sid}'.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 19.7.8.1 : {e}{RESET}")

@compliance_check
# Contrôle 19.7.8.2 : Vérifier "Do not suggest third-party content in Windows spotlight" via le registre
def check_do_not_suggest_third_party_content_in_windows_spotlight():
    try:
        # Obtenir le SID de l'utilisateur (l'exemple ici utilise un SID générique pour le test)
        user_sid = r"S-1-5-21-1234567890-123456789-1234567890"  # Remplace ceci par le SID approprié

        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        key_name = "DisableThirdPartySuggestions"

        # Vérification de la clé de registre pour l'utilisateur spécifié
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_USERS, user_sid + "\\" + registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}19.7.8.2 Do not suggest third-party content in Windows spotlight: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}19.7.8.2 Do not suggest third-party content in Windows spotlight: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}19.7.8.2 Clé de registre '{key_name}' non trouvée pour l'utilisateur '{user_sid}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}19.7.8.2 La clé de registre '{registry_path}' n'existe pas pour l'utilisateur '{user_sid}'.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 19.7.8.2 : {e}{RESET}")

@compliance_check
# Contrôle 19.7.8.3 : Vérifier "Do not use diagnostic data for tailored experiences" via le registre
def check_do_not_use_diagnostic_data_for_tailored_experiences():
    try:
        # Obtenir le SID de l'utilisateur (l'exemple ici utilise un SID générique pour le test)
        user_sid = r"S-1-5-21-1234567890-123456789-1234567890"  # Remplace ceci par le SID approprié

        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        key_name = "DisableTailoredExperiencesWithDiagnosticData"

        # Vérification de la clé de registre pour l'utilisateur spécifié
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_USERS, user_sid + "\\" + registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}19.7.8.3 Do not use diagnostic data for tailored experiences: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}19.7.8.3 Do not use diagnostic data for tailored experiences: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}19.7.8.3 Clé de registre '{key_name}' non trouvée pour l'utilisateur '{user_sid}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}19.7.8.3 La clé de registre '{registry_path}' n'existe pas pour l'utilisateur '{user_sid}'.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 19.7.8.3 : {e}{RESET}")

@compliance_check
# Contrôle 19.7.8.4 : Vérifier "Turn off all Windows spotlight features" via le registre
def check_turn_off_all_windows_spotlight_features():
    try:
        # Obtenir le SID de l'utilisateur (l'exemple ici utilise un SID générique pour le test)
        user_sid = r"S-1-5-21-1234567890-123456789-1234567890"  # Remplace ceci par le SID approprié

        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        key_name = "DisableWindowsSpotlightFeatures"

        # Vérification de la clé de registre pour l'utilisateur spécifié
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_USERS, user_sid + "\\" + registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}19.7.8.4 Turn off all Windows spotlight features: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}19.7.8.4 Turn off all Windows spotlight features: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}19.7.8.4 Clé de registre '{key_name}' non trouvée pour l'utilisateur '{user_sid}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}19.7.8.4 La clé de registre '{registry_path}' n'existe pas pour l'utilisateur '{user_sid}'.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 19.7.8.4 : {e}{RESET}")

@compliance_check
# Contrôle 19.7.8.5 : Vérifier "Turn off Spotlight collection on Desktop" via le registre
def check_turn_off_spotlight_collection_on_desktop():
    try:
        # Obtenir le SID de l'utilisateur (l'exemple ici utilise un SID générique pour le test)
        user_sid = r"S-1-5-21-1234567890-123456789-1234567890"  # Remplace ceci par le SID approprié

        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        key_name = "DisableSpotlightCollectionOnDesktop"

        # Vérification de la clé de registre pour l'utilisateur spécifié
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_USERS, user_sid + "\\" + registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}19.7.8.5 Turn off Spotlight collection on Desktop: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}19.7.8.5 Turn off Spotlight collection on Desktop: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}19.7.8.5 Clé de registre '{key_name}' non trouvée pour l'utilisateur '{user_sid}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}19.7.8.5 La clé de registre '{registry_path}' n'existe pas pour l'utilisateur '{user_sid}'.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 19.7.8.5 : {e}{RESET}")

@compliance_check
# Contrôle 19.7.26.1 : Vérifier "Prevent users from sharing files within their profile" via le registre
def check_prevent_users_from_sharing_files_within_their_profile():
    try:
        # Obtenir le SID de l'utilisateur (l'exemple ici utilise un SID générique pour le test)
        user_sid = r"S-1-5-21-1234567890-123456789-1234567890"  # Remplace ceci par le SID approprié

        registry_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        key_name = "NoInplaceSharing"

        # Vérification de la clé de registre pour l'utilisateur spécifié
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_USERS, user_sid + "\\" + registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}19.7.26.1 Prevent users from sharing files within their profile: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}19.7.26.1 Prevent users from sharing files within their profile: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}19.7.26.1 Clé de registre '{key_name}' non trouvée pour l'utilisateur '{user_sid}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}19.7.26.1 La clé de registre '{registry_path}' n'existe pas pour l'utilisateur '{user_sid}'.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 19.7.26.1 : {e}{RESET}")

@compliance_check
# Contrôle 19.7.38.1 : Vérifier "Turn off Windows Copilot" via le registre
def check_turn_off_windows_copilot():
    try:
        # Obtenir le SID de l'utilisateur (l'exemple ici utilise un SID générique pour le test)
        user_sid = r"S-1-5-21-1234567890-123456789-1234567890"  # Remplace ceci par le SID approprié

        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
        key_name = "TurnOffWindowsCopilot"

        # Vérification de la clé de registre pour l'utilisateur spécifié
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_USERS, user_sid + "\\" + registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}19.7.38.1 Turn off Windows Copilot: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}19.7.38.1 Turn off Windows Copilot: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}19.7.38.1 Clé de registre '{key_name}' non trouvée pour l'utilisateur '{user_sid}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}19.7.38.1 La clé de registre '{registry_path}' n'existe pas pour l'utilisateur '{user_sid}'.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 19.7.38.1 : {e}{RESET}")

@compliance_check
# Contrôle 19.7.42.1 : Vérifier "Always install with elevated privileges" via le registre
def check_always_install_with_elevated_privileges():
    try:
        # Obtenir le SID de l'utilisateur (l'exemple ici utilise un SID générique pour le test)
        user_sid = r"S-1-5-21-1234567890-123456789-1234567890"  # Remplace ceci par le SID approprié

        registry_path = r"SOFTWARE\Policies\Microsoft\Windows\Installer"
        key_name = "AlwaysInstallElevated"

        # Vérification de la clé de registre pour l'utilisateur spécifié
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_USERS, user_sid + "\\" + registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 0:
                    print(f"{GREEN}19.7.42.1 Always install with elevated privileges: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}19.7.42.1 Always install with elevated privileges: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}19.7.42.1 Clé de registre '{key_name}' non trouvée pour l'utilisateur '{user_sid}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}19.7.42.1 La clé de registre '{registry_path}' n'existe pas pour l'utilisateur '{user_sid}'.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 19.7.42.1 : {e}{RESET}")

@compliance_check
# Contrôle 19.7.44.2.1 : Vérifier "Prevent Codec Download" via le registre
def check_prevent_codec_download():
    try:
        # Obtenir le SID de l'utilisateur (l'exemple ici utilise un SID générique pour le test)
        user_sid = r"S-1-5-21-1234567890-123456789-1234567890"  # Remplace ceci par le SID approprié

        registry_path = r"SOFTWARE\Policies\Microsoft\WindowsMediaPlayer"
        key_name = "PreventCodecDownload"

        # Vérification de la clé de registre pour l'utilisateur spécifié
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_USERS, user_sid + "\\" + registry_path)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key_name)
                winreg.CloseKey(reg_key)

                # Vérification de la valeur de la clé
                if value == 1:
                    print(f"{GREEN}19.7.44.2.1 Prevent Codec Download: Conforme (Valeur Relevée: {value}){RESET}")
                else:
                    print(f"{RED}19.7.44.2.1 Prevent Codec Download: Non conforme (Valeur Relevée: {value}){RESET}")

            except FileNotFoundError:
                print(f"{RED}19.7.44.2.1 Clé de registre '{key_name}' non trouvée pour l'utilisateur '{user_sid}'.{RESET}")
                return

        except FileNotFoundError:
            print(f"{RED}19.7.44.2.1 La clé de registre '{registry_path}' n'existe pas pour l'utilisateur '{user_sid}'.{RESET}")
            return

    except Exception as e:
        print(f"{RED}Erreur lors de l'exécution du contrôle 19.7.44.2.1 : {e}{RESET}")



# Exécution des contrôles
check_password_history() #controle 1.1.1
check_maximum_password_age() #controle 1.1.2
check_minimum_password_age() #controle 1.1.3
check_minimum_password_length() #controle 1.1.4
check_password_complexity() #controle 1.1.5
check_relax_minimum_password_length_limits()  # Ajout du contrôle 1.1.6
check_reversible_encryption()  # Ajout du contrôle 1.1.7
check_account_lockout_duration() # Ajout du contrôle 1.2.1
check_account_lockout_threshold() # Ajout du contrôle 1.2.2
check_administrator_account_lockout() # Ajout du contrôle 1.2.3
check_reset_account_lockout_counter() # Ajout du contrôle 1.2.4
check_access_credential_manager() # Ajout du contrôle 2.2.1
check_access_computer_from_network() # Ajout du contrôle 2.2.2
check_act_as_part_of_os() #2.2.3
check_adjust_memory_quotas() #2.2.4
check_allow_log_on_locally() #2.2.5
check_allow_log_on_remote_desktop() #2.2.6
check_back_up_files_and_directories() #2.2.7
check_change_system_time() #2.2.8
check_change_time_zone() #2.2.9
check_create_pagefile() # Contrôle 2.2.10
check_create_token_object() # Contrôle 2.2.11
check_create_global_objects() #2.2.12
check_create_permanent_shared_objects()  #2.2.13
check_create_symbolic_links()  #2.2.14
check_debug_programs()  #2.2.15
check_deny_access_to_network() #2.2.16
check_deny_log_on_as_batch_job()  #2.2.17
check_deny_log_on_as_service() #2.2.18
check_deny_log_on_locally() #2.2.19
check_deny_log_on_remote_desktop() #2.2.20
check_trusted_for_delegation()#2.2.21
check_force_shutdown_remote()#2.2.22
check_generate_security_audits()#2.2.23
check_impersonate_client_after_authentication()#2.2.24
check_increase_scheduling_priority()#2.2.25
check_load_and_unload_device_drivers()#2.2.26
check_lock_pages_in_memory()#2.2.27
check_log_on_as_batch_job()#2.2.28
check_log_on_as_a_service()#2.2.29
check_manage_auditing_and_security_log()#2.2.30
check_modify_object_label()#2.2.31
check_modify_firmware_environment_values()#2.2.32
check_perform_volume_maintenance_tasks()#2.2.33
check_profile_single_process() #2.2.34
check_profile_system_performance() #2.2.35
check_replace_process_level_token() #2.2.36
check_restore_files_and_directories() #2.2.37
check_shut_down_the_system() #2.2.38
check_take_ownership_of_files_or_other_objects() #2.2.39
check_block_microsoft_accounts() #2.3.1.1
check_guest_account_status() #2.3.1.2
check_limit_blank_password_use() #2.3.1.3
check_rename_administrator_account() #2.3.1.4
check_rename_guest_account() #2.3.1.5
check_force_audit_policy_subcategory() #2.3.2.1
check_shut_down_system_if_unable_to_log_audits() #2.3.2.2
check_prevent_users_from_installing_printer_drivers() #2.3.4.1
check_disable_ctrl_alt_del() #2.3.7.1
check_dont_display_last_user_name() #2.3.7.2
check_machine_account_lockout_threshold() #2.3.7.3
check_machine_inactivity_limit() #2.3.7.4
check_message_text_for_users() #2.3.7.5
check_message_title_for_users() #2.3.7.6
check_prompt_user_to_change_password() #2.3.7.7
check_smart_card_removal_behavior() #2.3.7.8
check_microsoft_network_client_signing() #2.3.8.1
check_microsoft_network_client_signing_if_server_agrees() #2.3.8.2
check_microsoft_network_client_send_unencrypted_password() #2.3.8.3
check_microsoft_network_server_idle_time() #2.3.9.1
check_microsoft_network_server_signing()#2.3.9.2
check_microsoft_network_server_signing_if_client_agrees()#2.3.9.3
check_microsoft_network_server_disconnect_clients()#2.3.9.4
check_smb_server_spn_validation()#2.3.9.5
check_anonymous_sid_name_translation()#2.3.10.1
check_anonymous_enum_sam_accounts()#2.3.10.2
check_anonymous_enum_sam_and_shares()#2.3.10.3
check_no_storage_of_credentials()#2.3.10.4
check_let_everyone_permissions_apply()#2.3.10.5
check_named_pipes_access()#2.3.10.6
check_remotely_accessible_registry_paths() #2.3.10.7
check_remotely_accessible_registry_paths_and_sub_paths()#2.3.10.8
check_restrict_anonymous_access()#2.3.10.9
check_restrict_clients_remote_sam()#2.3.10.10
check_shares_accessed_anonymously()#2.3.10.11
check_sharing_security_model()#2.3.10.12
check_local_system_ntlm_identity()#2.3.11.1
check_local_system_null_session_fallback()#2.3.11.2
check_allow_pku2u_online_identity()#2.3.11.3
check_kerberos_encryption()#2.3.11.4
check_no_lan_manager_hash()#2.3.11.5
check_force_logoff_when_logon_hours_expire()#2.3.11.6
check_lan_manager_authentication_level() # Contrôle 2.3.11.7
check_ldap_client_signing_requirements()  # Contrôle 2.3.11.8
check_ntlm_minimum_session_security() # Contrôle 2.3.11.9
check_ntlm_minimum_session_security_servers()# Contrôle 2.3.11.10
check_restrict_ntlm_audit_incoming_traffic()  # Contrôle 2.3.11.11
check_restrict_ntlm_outgoing_traffic()  # Contrôle 2.3.11.12
check_force_strong_key_protection()  # Contrôle 2.3.14.1
check_require_case_insensitivity_for_non_windows_subsystems()  # Contrôle 2.3.15.1
check_strengthen_default_permissions_of_system_objects()  # Contrôle 2.3.15.2
check_admin_approval_mode_for_builtin_administrator()  # Contrôle 2.3.17.1
check_elevation_prompt_behavior_for_admins()  # Contrôle 2.3.17.2
check_elevation_prompt_behavior_for_standard_users()  # Contrôle 2.3.17.3
check_detect_application_installations_and_prompt_for_elevation()  # Contrôle 2.3.17.4
check_only_elevate_uiaccess_in_secure_locations()  # Contrôle 2.3.17.5
check_run_all_administrators_in_admin_approval_mode()  # Contrôle 2.3.17.6
check_switch_to_secure_desktop_when_prompting_for_elevation()  # Contrôle 2.3.17.7
check_virtualize_file_and_registry_write_failures()  # Contrôle 2.3.17.8
check_bluetooth_audio_gateway_service()  # Contrôle 5.1
check_bluetooth_support_service()  # Contrôle 5.2
check_computer_browser_service()  # Contrôle 5.3
check_downloaded_maps_manager_service()  # Contrôle 5.4
check_geolocation_service()  # Contrôle 5.5
check_iis_admin_service()  # Contrôle 5.6
check_infrared_monitor_service()  # Contrôle 5.7
check_link_layer_topology_discovery_mapper_service()  # Contrôle 5.8
check_lxss_manager_service()  # Contrôle 5.9
check_microsoft_ftp_service()  # Contrôle 5.10
check_microsoft_iscsi_initiator_service()  # Contrôle 5.11
check_openssh_ssh_server_service()  # Contrôle 5.12
check_peer_name_resolution_protocol_service()  # Contrôle 5.13
check_peer_networking_grouping_service()  # Contrôle 5.14
check_peer_networking_identity_manager_service()  # Contrôle 5.15
check_pnrp_machine_name_publication_service()  # Contrôle 5.16
check_print_spooler_service()  # Contrôle 5.17
check_problem_reports_and_solutions_control_panel_support_service()  # Contrôle 5.18
check_remote_access_auto_connection_manager_service()  # Contrôle 5.19
check_remote_desktop_configuration_service()  # Contrôle 5.20
check_remote_desktop_services_service()  # Contrôle 5.21
check_remote_desktop_services_usermode_port_redirector_service()  # Contrôle 5.22
check_rpc_locator_service()  # Contrôle 5.23
check_remote_registry_service()  # Contrôle 5.24
check_routing_and_remote_access_service()  # Contrôle 5.25
check_server_lanmanserver_service()  # Contrôle 5.26
check_simple_tcp_ip_services_service()  # Contrôle 5.27
check_snmp_service()  # Contrôle 5.28
check_special_administration_console_helper_service()  # Contrôle 5.29
check_ssdp_discovery_service()  # Contrôle 5.30
check_upnp_device_host_service()  # Contrôle 5.31
check_web_management_service()  # Contrôle 5.32
check_windows_error_reporting_service()  # Contrôle 5.33
check_windows_event_collector_service()  # Contrôle 5.34
check_wmp_network_sharing_service()  # Contrôle 5.35
check_windows_mobile_hotspot_service()  # Contrôle 5.36
check_wpn_service()  # Contrôle 5.37
check_push_to_install_service()  # Contrôle 5.38
check_winrm_service()  # Contrôle 5.39
check_www_publishing_service()  # Contrôle 5.40
check_xbox_accessory_management_service()  # Contrôle 5.41
check_xbox_live_auth_manager()  # Contrôle 5.42
check_xbox_live_game_save()  # Contrôle 5.43
check_xbox_live_networking_service()  # Contrôle 5.44
check_private_firewall_state()  # Contrôle 9.2.1
check_private_inbound_connections()  # Contrôle 9.2.2
check_private_firewall_notification()  # Contrôle 9.2.3
check_private_firewall_log_file()  # Contrôle 9.2.4
check_private_firewall_log_size_limit()  # Contrôle 9.2.5
check_private_firewall_log_dropped_packets()  # Contrôle 9.2.6
check_private_firewall_log_successful_connections()  # Contrôle 9.2.7
check_public_firewall_state()  # Contrôle 9.3.1
check_public_firewall_inbound_connections()  # Contrôle 9.3.2
check_public_firewall_display_notification()  # Contrôle 9.3.3
check_public_firewall_apply_local_rules()  # Contrôle 9.3.4
check_public_firewall_apply_local_ipsec_rules()  # Contrôle 9.3.5
check_public_firewall_log_file_path()  # Contrôle 9.3.6
check_public_firewall_log_file_size()  # Contrôle 9.3.7
check_public_firewall_log_dropped_packets()  # Contrôle 9.3.8
check_public_firewall_log_successful_connections()  # Contrôle 9.3.9
check_audit_credential_validation()  # Contrôle 17.1.1
check_audit_application_group_management()  # Contrôle 17.2.1
check_audit_security_group_management()  # Contrôle 17.2.2
check_audit_user_account_management()  # Contrôle 17.2.3
check_audit_pnp_activity()  # Contrôle 17.3.1
check_audit_process_creation()  # Contrôle 17.3.2
check_audit_account_lockout()  # Contrôle 17.5.1
check_audit_group_membership()  # Contrôle 17.5.2
check_audit_logoff()  # Contrôle 17.5.3
check_audit_logon()  # Contrôle 17.5.4
check_audit_other_logon_logoff_events()  # Contrôle 17.5.5
check_audit_special_logon()  # Contrôle 17.5.6
check_audit_detailed_file_share()  # Contrôle 17.6.1
check_audit_file_share()  # Contrôle 17.6.2
check_audit_other_object_access_events()  # Contrôle 17.6.3
check_audit_removable_storage()  # Contrôle 17.6.4
check_audit_audit_policy_change()  # Contrôle 17.7.1
check_audit_authentication_policy_change()  # Contrôle 17.7.2
check_audit_authorization_policy_change()  # Contrôle 17.7.3
check_audit_mpssvc_rule_level_policy_change()  # Contrôle 17.7.4
check_audit_other_policy_change_events()  # Contrôle 17.7.5
check_audit_sensitive_privilege_use()  # Contrôle 17.8.1
check_audit_ipsec_driver()  # Contrôle 17.9.1
check_audit_other_system_events()  # Contrôle 17.9.2
check_audit_security_state_change()  # Contrôle 17.9.3
check_audit_security_system_extension()  # Contrôle 17.9.4
check_audit_system_integrity()  # Contrôle 17.9.5
check_prevent_lock_screen_camera()  # Contrôle 18.1.1.1
check_prevent_lock_screen_slide_show()  # Contrôle 18.1.1.2
check_allow_online_speech_recognition()  # Contrôle 18.1.2.2
check_allow_online_tips()  # Contrôle 18.1.3
check_rpc_packet_level_privacy()  # Contrôle 18.4.1
check_smb_v1_client_driver()  # Contrôle 18.4.2
check_smb_v1_server()  # Contrôle 18.4.3
check_enable_certificate_padding()  # Contrôle 18.4.4
check_sehop() # Exécuter le contrôle 18.4.5
check_netbt_node_type() # Exécuter le contrôle 18.4.6
check_wdigest_authentication()# Exécuter le contrôle 18.4.7
check_auto_admin_logon()# Exécuter le contrôle 18.5.1
check_disable_ip_source_routing()# Exécuter le contrôle 18.5.2
check_disable_ip_source_routing_tcpip()# Exécuter le contrôle 18.5.3
check_disable_save_password()# Exécuter le contrôle 18.5.4
check_enable_icmp_redirect()# Exécuter le contrôle 18.5.5
check_keep_alive_time()# Exécuter le contrôle 18.5.6
check_no_name_release_on_demand()# Exécuter le contrôle 18.5.7
check_perform_router_discovery()# Exécuter le contrôle 18.5.8
check_safe_dll_search_mode()# Exécuter le contrôle 18.5.9
check_screensaver_grace_period()# Exécuter le contrôle 18.5.10
check_tcp_max_data_retransmissions_ipv6()# Exécuter le contrôle 18.5.11
check_tcp_max_data_retransmissions()# Exécuter le contrôle 18.5.12
check_warning_level()# Exécuter le contrôle 18.5.13
check_doh_policy()# Exécuter le contrôle 18.6.4.1
check_enable_font_providers()# Exécuter le contrôle 18.6.5.1
check_insecure_guest_logons()# Exécuter le contrôle 18.6.8.1
check_mapper_io_driver()# Exécuter le contrôle 18.6.9.1
check_responder_driver()# Exécuter le contrôle 18.6.9.2
check_turn_off_peer_to_peer_services()# Exécuter le contrôle 18.6.10.2
check_prohibit_network_bridge()# Exécuter le contrôle 18.6.11.2
check_prohibit_internet_connection_sharing()# Exécuter le contrôle 18.6.11.3
check_hardened_unc_paths()# Exécuter le contrôle 18.6.14.1
check_wireless_settings_windows_connect_now()# Exécuter le contrôle 18.6.20.1
check_prohibit_wcn_wizards()#Contrôle 18.6.20.2 
check_minimize_connections()# Contrôle 18.6.21.1
check_auto_connect_open_hotspots()# Contrôle 18.6.23.2.1
check_print_spooler_remote_rpc()# Contrôle 18.7.1 
check_redirection_guard()# Contrôle 18.7.2 
check_rpc_connection_protocol()# Contrôle 18.7.3 
check_rpc_authentication()# Contrôle 18.7.4 
check_rpc_listener_protocol()# Contrôle 18.7.5 
check_rpc_listener_auth_protocol()# Contrôle 18.7.6 
check_rpc_tcp_port()# Contrôle 18.7.7
check_limit_print_driver_installation()#18.7.8
check_manage_queue_specific_files()#18.7.9
check_point_and_print_restrictions()#18.7.10
check_point_and_print_update_restrictions()#18.7.11
check_turn_off_notifications_network_usage()# Contrôle 18.8.1.1
check_remove_personalized_website_recommendations()# Contrôle 18.8.2 
check_include_command_line_in_process_creation_events()# Contrôle 18.9.3.1
check_encryption_oracle_remediation()# Contrôle 18.9.4.1
check_remote_host_delegation()# Contrôle 18.9.4.2 
check_virtualization_based_security()  # Contrôle 18.9.5.1
check_virtualization_platform_security_level()  # Contrôle 18.9.5.2
check_virtualization_based_protection_code_integrity()  # Contrôle 18.9.5.3
check_uefi_memory_attributes_table()  # Contrôle 18.9.5.4
check_credential_guard_configuration()  # Contrôle 18.9.5.5
check_secure_launch_configuration()  # Contrôle 18.9.5.6
check_kernel_mode_stack_protection()  # Contrôle 18.9.5.7
check_prevent_device_installation()  # Contrôle 18.9.7.1.1
check_prevent_device_installation_pci()  # Contrôle 18.9.7.1.2
check_prevent_device_installation_retroactive()  # Contrôle 18.9.7.1.3
check_prevent_device_installation_classes()  # Contrôle 18.9.7.1.4
check_prevent_device_installation_ieee1394()  # Contrôle 18.9.7.1.5
check_prevent_device_installation_retroactive_classes()  # Contrôle 18.9.7.1.6
check_prevent_device_metadata_retrieval()  # Contrôle 18.9.7.2
check_boot_start_driver_initialization_policy()  # Contrôle 18.9.13.1
check_continue_experiences_on_device()  # Contrôle 18.9.19.2
check_turn_off_access_to_store()  # Contrôle 18.9.20.1.1
check_turn_off_print_driver_download_http()  # Contrôle 18.9.20.1.2
check_turn_off_handwriting_personalization_data_sharing()  # Contrôle 18.9.20.1.3
check_turn_off_handwriting_recognition_error_reporting()  # Contrôle 18.9.20.1.4
check_turn_off_internet_connection_wizard()  # Contrôle 18.9.20.1.5
check_turn_off_internet_download_for_web_publish_online_ordering()  # Contrôle 18.9.20.1.6
check_turn_off_printing_over_http()  # Contrôle 18.9.20.1.7
check_turn_off_registration_microsoft_com()  # Contrôle 18.9.20.1.8
check_turn_off_search_companion_content_file_updates()  # Contrôle 18.9.20.1.9
check_turn_off_order_prints_picture_task()  # Contrôle 18.9.20.1.10
check_turn_off_publish_to_web_task()  # Contrôle 18.9.20.1.11
check_turn_off_messenger_ceip()  # Contrôle 18.9.20.1.12
check_turn_off_windows_ceip()  # Contrôle 18.9.20.1.13
check_turn_off_windows_error_reporting()  # Contrôle 18.9.20.1.14
check_support_device_authentication_using_certificate()  # Contrôle 18.9.23.1
check_enumeration_policy_for_external_devices_dma_protection()  # Contrôle 18.9.24.1
check_allow_custom_ssps_aps_in_lsass()  # Contrôle 18.9.26.1
check_lsass_run_as_protected_process()  # Contrôle 18.9.26.2
check_disallow_copying_user_input_methods()  # Contrôle 18.9.27.1
check_block_user_from_showing_account_details_on_signin()  # Contrôle 18.9.28.1
check_do_not_display_network_selection_ui()  # Contrôle 18.9.28.2
check_turn_off_app_notifications_on_lock_screen()  # Contrôle 18.9.28.3
check_turn_on_convenience_pin_sign_in()  # Contrôle 18.9.28.4
check_allow_clipboard_synchronization_across_devices()  # Contrôle 18.9.31.1
check_allow_upload_of_user_activities()  # Contrôle 18.9.31.2
check_allow_network_connectivity_during_connected_standby()  # Contrôle 18.9.33.6.1
check_allow_network_connectivity_during_connected_standby_plugged_in()  # Contrôle 18.9.33.6.2
check_allow_standby_states_when_sleeping_on_battery()  # Contrôle 18.9.33.6.3
check_allow_standby_states_when_sleeping_plugged_in()  # Contrôle 18.9.33.6.4
check_require_password_when_computer_wakes_on_battery()  # Contrôle 18.9.33.6.5
check_require_password_when_computer_wakes_plugged_in()  # Contrôle 18.9.33.6.6
check_configure_offer_remote_assistance()  # Contrôle 18.9.35.1
check_configure_solicited_remote_assistance()  # Contrôle 18.9.35.2
check_enable_rpc_endpoint_mapper_client_authentication()  # Contrôle 18.9.36.1
check_restrict_unauthenticated_rpc_clients()  # Contrôle 18.9.36.2
check_turn_on_msdm_interactive_communication()  # Contrôle 18.9.47.5.1
check_enable_disable_perftrack()  # Contrôle 18.9.47.11.1
check_turn_off_advertising_id()  # Contrôle 18.9.49.1
check_enable_windows_ntp_client()  # Contrôle 18.9.51.1.1
check_allow_shared_local_app_data()  # Contrôle 18.10.3.1
check_prevent_non_admin_install_apps()  # Contrôle 18.10.3.2
check_let_apps_activate_with_voice_above_lock()  # Contrôle 18.10.4.1
check_allow_microsoft_accounts_to_be_optional()  # Contrôle 18.10.5.1
check_block_hosted_app_access_winrt()  # Contrôle 18.10.5.2
check_disallow_autoplay_for_non_volume_devices()  # Contrôle 18.10.7.1
check_set_default_behavior_for_autorun()  # Contrôle 18.10.7.2
check_turn_off_autoplay()  # Contrôle 18.10.7.3
check_enhanced_anti_spoofing()  # Contrôle 18.10.8.1.1
check_bitlocker_access_for_older_versions()  # Contrôle 18.10.9.1.1
check_bitlocker_recovery_option()  # Contrôle 18.10.9.1.2
check_bitlocker_data_recovery_agent()  # Contrôle 18.10.9.1.3
check_bitlocker_recovery_password()  # Contrôle 18.10.9.1.4
check_bitlocker_recovery_key()  # Contrôle 18.10.9.1.5
check_bitlocker_omit_recovery_options()  # Contrôle 18.10.9.1.6
check_bitlocker_save_recovery_info_to_ad()  # Contrôle 18.10.9.1.7
check_bitlocker_storage_recovery_info_to_ad()  # Contrôle 18.10.9.1.8
check_bitlocker_require_ad_backup()  # Contrôle 18.10.9.1.9
check_hardware_encryption_disabled()  # Contrôle 18.10.9.1.10
check_password_for_fixed_drives_disabled()  # Contrôle 18.10.9.1.11
check_smart_card_on_fixed_drives_enabled()  # Contrôle 18.10.9.1.12
check_require_smart_card_on_fixed_drives_enabled()  # Contrôle 18.10.9.1.13
check_allow_enhanced_pins_for_startup_enabled()  # Contrôle 18.10.9.2.1
check_allow_secure_boot_for_integrity_enabled()  # Contrôle 18.10.9.2.2
check_bitlocker_os_recovery_enabled()  # Contrôle 18.10.9.2.3
check_bitlocker_allow_data_recovery_agent()  # Contrôle 18.10.9.2.4
check_bitlocker_recovery_password()  # Contrôle 18.10.9.2.5
check_bitlocker_recovery_key()  # Contrôle 18.10.9.2.6
check_bitlocker_omit_recovery_page()  # Contrôle 18.10.9.2.7
check_bitlocker_save_recovery_to_ad()  # Contrôle 18.10.9.2.8
check_bitlocker_store_recovery_to_ad()  # Contrôle 18.10.9.2.9
check_bitlocker_ad_backup_requirement()  # Contrôle 18.10.9.2.10
check_hardware_encryption_for_os_drives()  # Contrôle 18.10.9.2.11
check_passwords_for_os_drives()  # Contrôle 18.10.9.2.12
check_additional_authentication_at_startup()  # Contrôle 18.10.9.2.13
check_allow_bitlocker_without_tpm()  # Contrôle 18.10.9.2.14
check_configure_tpm_startup()  # Contrôle 18.10.9.2.15
check_configure_tpm_startup_pin()  # Contrôle 18.10.9.2.16
check_configure_tpm_startup_key()  # Contrôle 18.10.9.2.17
check_configure_tpm_startup_key_and_pin()  # Contrôle 18.10.9.2.18
check_allow_access_to_bitlocker_protected_removable_drives()  # Contrôle 18.10.9.3.1
check_choose_how_bitlocker_protected_removable_drives_can_be_recovered()  # Contrôle 18.10.9.3.2
check_allow_data_recovery_agent_for_removable_drives()  # Contrôle 18.10.9.3.3
check_recovery_password_for_removable_drives()  # Contrôle 18.10.9.3.4
check_recovery_key_for_removable_drives()  # Contrôle 18.10.9.3.5
check_omit_recovery_options()  # Contrôle 18.10.9.3.6
check_save_recovery_info_to_ad_ds_for_removable_drives()  # Contrôle 18.10.9.3.7
check_configure_storage_of_bitlocker_recovery_info_to_ad_ds()  # Contrôle 18.10.9.3.8
check_bitlocker_recovery_info_to_ad_ds_for_removable_drives()  # Contrôle 18.10.9.3.9
check_bitlocker_hardware_encryption_for_removable_drives()  # Contrôle 18.10.9.3.10
check_bitlocker_password_for_removable_drives()  # Contrôle 18.10.9.3.11
check_bitlocker_smartcards_for_removable_drives()  # Contrôle 18.10.9.3.12
check_bitlocker_smartcards_enforce_for_removable_drives()  # Contrôle 18.10.9.3.13
check_bitlocker_deny_write_access_to_non_bitlocker_drives()  # Contrôle 18.10.9.3.14
check_bitlocker_deny_write_access_to_other_organizations()  # Contrôle 18.10.9.3.15
check_disable_new_dma_devices_when_locked()  # Contrôle 18.10.9.4
check_and_configure_allow_use_of_camera()  # Contrôle 18.10.10.1
check_and_configure_disable_consumer_account_state_content()  # Contrôle 18.10.12.1
check_and_configure_disable_cloud_optimized_content()  # Contrôle 18.10.12.2
check_and_configure_disable_microsoft_consumer_experiences()  # Contrôle 18.10.12.3
check_require_pin_for_pairing() #Contrôle 18.10.13.1
check_disable_password_reveal() # Contrôle 18.10.14.1
check_enumerate_administrator_accounts() # Contrôle 18.10.14.2
check_prevent_security_questions_for_local_accounts() # Contrôle 18.10.14.3
check_allow_diagnostic_data() # Contrôle 18.10.15.1
check_disable_authenticated_proxy_usage() # Contrôle 18.10.15.2
check_disable_onesettings_downloads() # Contrôle 18.10.15.3
check_do_not_show_feedback_notifications() # Contrôle 18.10.15.4
check_enable_onesettings_auditing() # Contrôle 18.10.15.5
check_limit_diagnostic_log_collection() # Contrôle 18.10.15.6
check_limit_dump_collection() # Contrôle 18.10.15.7
check_toggle_user_control_over_insider_builds() # Contrôle 18.10.15.8
check_download_mode() # Contrôle 18.10.16.1
check_enable_app_installer() # Contrôle 18.10.17.1
check_enable_experimental_features() # Contrôle 18.10.17.2
check_enable_hash_override() # Contrôle 18.10.17.3
check_enable_ms_appinstaller_protocol() # Contrôle 18.10.17.4
check_event_log_retention() # Contrôle 18.10.25.1.1
check_max_log_file_size() # Contrôle 18.10.25.1.2
check_security_event_log_retention() # Contrôle 18.10.25.2.1
check_security_max_log_file_size() # Contrôle 18.10.25.2.2
check_setup_event_log_retention() # Contrôle 18.10.25.3.1
check_setup_max_log_file_size() # Contrôle 18.10.25.3.2
check_system_event_log_retention() # Contrôle 18.10.25.4.1
check_system_max_log_file_size() # Contrôle 18.10.25.4.2
check_disable_account_based_insights() # Contrôle 18.10.28.2
check_disable_data_execution_prevention_for_explorer() # Contrôle 18.10.28.3
check_no_heap_termination_on_corruption() # Contrôle 18.10.28.4
check_shell_protocol_protected_mode() # Contrôle 18.10.28.5
check_turn_off_location() # Contrôle 18.10.36.1
check_allow_message_service_cloud_sync() # Contrôle 18.10.40.1
check_block_consumer_microsoft_account_authentication() # Contrôle 18.10.41.1
check_local_setting_override_for_map_reporting() # Contrôle 18.10.42.5.1
check_join_microsoft_maps() # Contrôle 18.10.42.5.2
check_configure_attack_surface_reduction_rules() # Contrôle 18.10.42.6.1.1
check_asr_rules() # Contrôle 18.10.42.6.1.2
check_prevent_access_to_dangerous_websites() # Contrôle 18.10.42.6.3.1
check_enable_file_hash_computation() # Contrôle 18.10.42.7.1
check_scan_all_downloaded_files_and_attachments() # Contrôle 18.10.42.10.1
check_turn_off_real_time_protection() # Contrôle 18.10.42.10.2
check_turn_on_behavior_monitoring() # Contrôle 18.10.42.10.3
check_turn_on_script_scanning() # Contrôle 18.10.42.10.4
check_configure_watson_events() # Contrôle 18.10.42.12.1
check_scan_packed_executables() # Contrôle 18.10.42.13.1
check_scan_removable_drives() # Contrôle 18.10.42.13.2
check_turn_on_email_scanning() # Contrôle 18.10.42.13.3
check_configure_detection_for_pua() # Contrôle 18.10.42.16
check_turn_off_microsoft_defender_anti_virus() # Contrôle 18.10.42.17
check_allow_auditing_events_in_app_guard() # Contrôle 18.10.43.1
check_allow_camera_microphone_access_in_app_guard() # Contrôle 18.10.43.2
check_allow_data_persistence_for_app_guard() # Contrôle 18.10.43.3
check_allow_files_to_download_and_save_to_host() # Contrôle 18.10.43.4
check_configure_defender_application_guard_clipboard() # Contrôle 18.10.43.5
check_turn_on_microsoft_defender_app_guard_managed_mode() # Contrôle 18.10.43.6
check_enable_news_and_interests_on_taskbar() # Contrôle 18.10.49.1
check_prevent_usage_of_onedrive_for_file_storage() # Contrôle 18.10.50.1
check_turn_off_push_to_install_service() # Contrôle 18.10.55.1
check_disable_cloud_clipboard_integration() # Contrôle 18.10.56.2.2
check_do_not_allow_passwords_to_be_saved() # Contrôle 18.10.56.2.3
check_allow_users_to_connect_remotely() # Contrôle 18.10.56.3.2.1
check_allow_ui_automation_redirection() # Contrôle 18.10.56.3.3.1
check_do_not_allow_com_port_redirection() # Contrôle 18.10.56.3.3.2
check_do_not_allow_drive_redirection() # Contrôle 18.10.56.3.3.3
check_do_not_allow_location_redirection() # Contrôle 18.10.56.3.3.4
check_do_not_allow_lpt_port_redirection() # Contrôle 18.10.56.3.3.5
check_do_not_allow_pnp_device_redirection() # Contrôle 18.10.56.3.3.6
check_do_not_allow_webauthn_redirection() # Contrôle 18.10.56.3.3.7
check_always_prompt_for_password()  # Contrôle 18.10.56.3.9.1
check_require_secure_rpc_communication()  # Contrôle 18.10.56.3.9.2
check_require_specific_security_layer_for_rdp()  # Contrôle 18.10.56.3.9.3
check_require_user_authentication_for_nla()  # Contrôle 18.10.56.3.9.4
check_client_connection_encryption_level()  # Contrôle 18.10.56.3.9.5
check_idle_session_timeout()  # Contrôle 18.10.56.3.10.1
check_disconnected_session_timeout()  # Contrôle 18.10.56.3.10.2    
check_delete_temp_dirs_on_exit()  # Contrôle 18.10.56.3.11.1
check_disable_enclosure_download()  # Contrôle 18.10.57.1
check_allow_cloud_search()  # Contrôle 18.10.58.2
check_allow_cortana()  # Contrôle 18.10.58.3
check_allow_cortana_above_lock()  # Contrôle 18.10.58.4
check_allow_indexing_encrypted_files()  # Contrôle 18.10.58.5
check_allow_search_to_use_location()  # Contrôle 18.10.58.6
check_allow_search_highlights()  # Contrôle 18.10.58.7
check_turn_off_kms_client_online_avs_validation()  # Contrôle 18.10.62.1
check_disable_store_apps()  # Contrôle 18.10.65.1
check_private_store_only()  # Contrôle 18.10.65.2
check_auto_download_install()  # Contrôle 18.10.65.3
check_off_update_offer()  # Contrôle 18.10.65.4
check_store_application()  # Contrôle 18.10.65.5
check_allow_widgets()  # Contrôle 18.10.71.1
check_automatic_data_collection()  # Contrôle 18.10.75.1.1
check_notify_malicious()  # Contrôle 18.10.75.1.2
check_notify_password_reuse()  # Contrôle 18.10.75.1.3
check_notify_unsafe_app()  # Contrôle 18.10.75.1.4
check_service_enabled()  # Contrôle 18.10.75.1.5
check_defender_smartscreen()  # Contrôle 18.10.75.2.1
check_game_recording()  # Contrôle 18.10.77.1
check_ESS_configuration()  # Contrôle 18.10.78.1
check_suggested_apps_configuration()  # Contrôle 18.10.79.1
check_allow_windows_ink_workspace()  # Contrôle 18.10.79.2
check_allow_user_control_over_installs()  # Contrôle 18.10.80.1
check_always_install_elevated_privileges()  # Contrôle 18.10.80.2
check_prevent_ie_security_prompt_for_installer_scripts()  # Contrôle 18.10.80.3
check_enable_mpr_notifications_for_system()  # Contrôle 18.10.81.1
check_sign_in_and_lock_last_user_after_restart()  # Contrôle 18.10.81.2
check_turn_on_powershell_script_block_logging()  # Contrôle 18.10.86.1
check_turn_on_powershell_transcription()  # Contrôle 18.10.86.2
check_allow_basic_authentication()  # Contrôle 18.10.88.1.1
check_allow_unencrypted_traffic()  # Contrôle 18.10.88.1.2
check_disallow_digest_authentication()  # Contrôle 18.10.88.1.3
check_allow_basic_authentication_winrm_service()  # Contrôle 18.10.88.2.1
check_allow_remote_server_management_through_winrm()  # Contrôle 18.10.88.2.2
check_allow_unencrypted_traffic_winrm_service()  # Contrôle 18.10.88.2.3
check_disallow_winrm_storing_runas_credentials()  # Contrôle 18.10.88.2.4
check_allow_remote_shell_access()  # Contrôle 18.10.89.1
check_allow_clipboard_sharing_with_windows_sandbox()  # Contrôle 18.10.90.1
check_allow_networking_in_windows_sandbox()  # Contrôle 18.10.90.2
check_prevent_users_from_modifying_settings()  # Contrôle 18.10.91.2.1
check_no_auto_restart_with_logged_on_users()  # Contrôle 18.10.92.1.1
check_configure_automatic_updates()  # Contrôle 18.10.92.2.1
check_configure_automatic_updates_scheduled_install_day()  # Contrôle 18.10.92.2.2
check_enable_features_introduced_via_servicing()  # Contrôle 18.10.92.2.3
check_remove_access_to_pause_updates()  # Contrôle 18.10.92.2.4
check_manage_preview_builds()  # Contrôle 18.10.92.4.1
check_select_when_preview_builds_and_feature_updates_are_received()  # Contrôle 18.10.92.4.2
check_select_when_quality_updates_are_received()  # Contrôle 18.10.92.4.3
check_enable_optional_updates()  # Contrôle 18.10.92.4.4
check_turn_off_toast_notifications_on_lock_screen()  # Contrôle 19.5.1.1
check_turn_off_help_experience_improvement_program()  # Contrôle 19.6.6.1.1
check_do_not_preserve_zone_information_in_file_attachments()  # Contrôle 19.7.5.1
check_notify_antivirus_programs_when_opening_attachments()  # Contrôle 19.7.5.2
check_configure_windows_spotlight_on_lock_screen()  # Contrôle 19.7.8.1
check_do_not_suggest_third_party_content_in_windows_spotlight()  # Contrôle 19.7.8.2
check_do_not_use_diagnostic_data_for_tailored_experiences()  # Contrôle 19.7.8.3
check_turn_off_all_windows_spotlight_features()  # Contrôle 19.7.8.4
check_turn_off_spotlight_collection_on_desktop()  # Contrôle 19.7.8.5
check_prevent_users_from_sharing_files_within_their_profile()  # Contrôle 19.7.26.1
check_turn_off_windows_copilot()  # Contrôle 19.7.38.1
check_always_install_with_elevated_privileges()  # Contrôle 19.7.42.1
check_prevent_codec_download()  # Contrôle 19.7.44.2.1

# Liste de toutes vos fonctions
checks = [
    check_password_history, 
    check_maximum_password_age, 
    check_minimum_password_age, 
    check_minimum_password_length, 
    check_password_complexity, #controle 1.1.5
    check_relax_minimum_password_length_limits,  # Ajout du contrôle 1.1.6
    check_reversible_encryption,  # Ajout du contrôle 1.1.7
    check_account_lockout_duration, # Ajout du contrôle 1.2.1
    check_account_lockout_threshold, # Ajout du contrôle 1.2.2
    check_administrator_account_lockout, # Ajout du contrôle 1.2.3
    check_reset_account_lockout_counter, # Ajout du contrôle 1.2.4
    check_access_credential_manager, # Ajout du contrôle 2.2.1
    check_access_computer_from_network, # Ajout du contrôle 2.2.2
    check_act_as_part_of_os, #2.2.3
    check_adjust_memory_quotas, #2.2.4
    check_allow_log_on_locally, #2.2.5
    check_allow_log_on_remote_desktop, #2.2.6
    check_back_up_files_and_directories, #2.2.7
    check_change_system_time, #2.2.8
    check_change_time_zone, #2.2.9
    check_create_pagefile, # Contrôle 2.2.10
    check_create_token_object, # Contrôle 2.2.11
    check_create_global_objects, #2.2.12
    check_create_permanent_shared_objects,  #2.2.13
    check_create_symbolic_links,  #2.2.14
    check_debug_programs,  #2.2.15
    check_deny_access_to_network, #2.2.16
    check_deny_log_on_as_batch_job,  #2.2.17
    check_deny_log_on_as_service, #2.2.18
    check_deny_log_on_locally, #2.2.19
    check_deny_log_on_remote_desktop, #2.2.20
    check_trusted_for_delegation, #2.2.21
    check_force_shutdown_remote, #2.2.22
    check_generate_security_audits, #2.2.23
    check_impersonate_client_after_authentication, #2.2.24
    check_increase_scheduling_priority, #2.2.25
    check_load_and_unload_device_drivers, #2.2.26
    check_lock_pages_in_memory, #2.2.27
    check_log_on_as_batch_job, #2.2.28
    check_log_on_as_a_service, #2.2.29
    check_manage_auditing_and_security_log, #2.2.30
    check_modify_object_label, #2.2.31
    check_modify_firmware_environment_values, #2.2.32
    check_perform_volume_maintenance_tasks, #2.2.33
    check_profile_single_process, #2.2.34
    check_profile_system_performance, #2.2.35
    check_replace_process_level_token, #2.2.36
    check_restore_files_and_directories, #2.2.37
    check_shut_down_the_system, #2.2.38
    check_take_ownership_of_files_or_other_objects, #2.2.39
    check_block_microsoft_accounts, #2.3.1.1
    check_guest_account_status, #2.3.1.2
    check_limit_blank_password_use, #2.3.1.3
    check_rename_administrator_account, #2.3.1.4
    check_rename_guest_account, #2.3.1.5
    check_force_audit_policy_subcategory, #2.3.2.1
    check_shut_down_system_if_unable_to_log_audits, #2.3.2.2
    check_prevent_users_from_installing_printer_drivers, #2.3.4.1
    check_disable_ctrl_alt_del, #2.3.7.1
    check_dont_display_last_user_name, #2.3.7.2
    check_machine_account_lockout_threshold, #2.3.7.3
    check_machine_inactivity_limit, #2.3.7.4
    check_message_text_for_users, #2.3.7.5
    check_message_title_for_users, #2.3.7.6
    check_prompt_user_to_change_password, #2.3.7.7
    check_smart_card_removal_behavior, #2.3.7.8
    check_microsoft_network_client_signing, #2.3.8.1
    check_microsoft_network_client_signing_if_server_agrees, #2.3.8.2
    check_microsoft_network_client_send_unencrypted_password, #2.3.8.3
    check_microsoft_network_server_idle_time, #2.3.9.1
    check_microsoft_network_server_signing, #2.3.9.2
    check_microsoft_network_server_signing_if_client_agrees, #2.3.9.3
    check_microsoft_network_server_disconnect_clients, #2.3.9.4
    check_smb_server_spn_validation, #2.3.9.5
    check_anonymous_sid_name_translation, #2.3.10.1
    check_anonymous_enum_sam_accounts, #2.3.10.2
    check_anonymous_enum_sam_and_shares, #2.3.10.3
    check_no_storage_of_credentials, #2.3.10.4
    check_let_everyone_permissions_apply, #2.3.10.5
    check_named_pipes_access, #2.3.10.6
    check_remotely_accessible_registry_paths, #2.3.10.7
    check_remotely_accessible_registry_paths_and_sub_paths, #2.3.10.8
    check_restrict_anonymous_access, #2.3.10.9
    check_restrict_clients_remote_sam, #2.3.10.10
    check_shares_accessed_anonymously, #2.3.10.11
    check_sharing_security_model, #2.3.10.12
    check_local_system_ntlm_identity, #2.3.11.1
    check_local_system_null_session_fallback, #2.3.11.2
    check_allow_pku2u_online_identity, #2.3.11.3
    check_kerberos_encryption, #2.3.11.4
    check_no_lan_manager_hash, #2.3.11.5
    check_force_logoff_when_logon_hours_expire, #2.3.11.6
    check_lan_manager_authentication_level, # Contrôle 2.3.11.7
    check_ldap_client_signing_requirements,  # Contrôle 2.3.11.8
    check_ntlm_minimum_session_security,  # Contrôle 2.3.11.9
    check_ntlm_minimum_session_security_servers, # Contrôle 2.3.11.10
    check_restrict_ntlm_audit_incoming_traffic,   # Contrôle 2.3.11.11
    check_restrict_ntlm_outgoing_traffic,   # Contrôle 2.3.11.12
    check_force_strong_key_protection,   # Contrôle 2.3.14.1
    check_require_case_insensitivity_for_non_windows_subsystems,   # Contrôle 2.3.15.1
    check_strengthen_default_permissions_of_system_objects,   # Contrôle 2.3.15.2
    check_admin_approval_mode_for_builtin_administrator,   # Contrôle 2.3.17.1
    check_elevation_prompt_behavior_for_admins,   # Contrôle 2.3.17.2
    check_elevation_prompt_behavior_for_standard_users,   # Contrôle 2.3.17.3
    check_detect_application_installations_and_prompt_for_elevation,   # Contrôle 2.3.17.4
    check_only_elevate_uiaccess_in_secure_locations,   # Contrôle 2.3.17.5
    check_run_all_administrators_in_admin_approval_mode,   # Contrôle 2.3.17.6
    check_switch_to_secure_desktop_when_prompting_for_elevation,   # Contrôle 2.3.17.7
    check_virtualize_file_and_registry_write_failures,   # Contrôle 2.3.17.8
    check_bluetooth_audio_gateway_service,   # Contrôle 5.1
    check_bluetooth_support_service,   # Contrôle 5.2
    check_computer_browser_service,   # Contrôle 5.3
    check_downloaded_maps_manager_service,   # Contrôle 5.4
    check_geolocation_service,   # Contrôle 5.5
    check_iis_admin_service,   # Contrôle 5.6
    check_infrared_monitor_service,   # Contrôle 5.7
    check_link_layer_topology_discovery_mapper_service,   # Contrôle 5.8
    check_lxss_manager_service,   # Contrôle 5.9
    check_microsoft_ftp_service,   # Contrôle 5.10
    check_microsoft_iscsi_initiator_service,   # Contrôle 5.11
    check_openssh_ssh_server_service,   # Contrôle 5.12
    check_peer_name_resolution_protocol_service,   # Contrôle 5.13
    check_peer_networking_grouping_service,   # Contrôle 5.14
    check_peer_networking_identity_manager_service,   # Contrôle 5.15
    check_pnrp_machine_name_publication_service,   # Contrôle 5.16
    check_print_spooler_service,   # Contrôle 5.17
    check_problem_reports_and_solutions_control_panel_support_service,   # Contrôle 5.18
    check_remote_access_auto_connection_manager_service,   # Contrôle 5.19
    check_remote_desktop_configuration_service,   # Contrôle 5.20
    check_remote_desktop_services_service,   # Contrôle 5.21
    check_remote_desktop_services_usermode_port_redirector_service,   # Contrôle 5.22
    check_rpc_locator_service,   # Contrôle 5.23
    check_remote_registry_service,   # Contrôle 5.24
    check_routing_and_remote_access_service,   # Contrôle 5.25
    check_server_lanmanserver_service,   # Contrôle 5.26
    check_simple_tcp_ip_services_service,   # Contrôle 5.27
    check_snmp_service,   # Contrôle 5.28
    check_special_administration_console_helper_service,   # Contrôle 5.29
    check_ssdp_discovery_service,   # Contrôle 5.30
    check_upnp_device_host_service,   # Contrôle 5.31
    check_web_management_service,   # Contrôle 5.32
    check_windows_error_reporting_service,   # Contrôle 5.33
    check_windows_event_collector_service,   # Contrôle 5.34
    check_wmp_network_sharing_service,   # Contrôle 5.35
    check_windows_mobile_hotspot_service,   # Contrôle 5.36
    check_wpn_service,   # Contrôle 5.37
    check_push_to_install_service,   # Contrôle 5.38
    check_winrm_service,   # Contrôle 5.39
    check_www_publishing_service,   # Contrôle 5.40
    check_xbox_accessory_management_service,   # Contrôle 5.41
    check_xbox_live_auth_manager,   # Contrôle 5.42
    check_xbox_live_game_save,   # Contrôle 5.43
    check_xbox_live_networking_service,   # Contrôle 5.44
    check_private_firewall_state,   # Contrôle 9.2.1
    check_private_inbound_connections,   # Contrôle 9.2.2
    check_private_firewall_notification,   # Contrôle 9.2.3
    check_private_firewall_log_file,   # Contrôle 9.2.4
    check_private_firewall_log_size_limit,   # Contrôle 9.2.5
    check_private_firewall_log_dropped_packets,   # Contrôle 9.2.6
    check_private_firewall_log_successful_connections,   # Contrôle 9.2.7
    check_public_firewall_state,   # Contrôle 9.3.1
    check_public_firewall_inbound_connections,   # Contrôle 9.3.2
    check_public_firewall_display_notification,   # Contrôle 9.3.3
    check_public_firewall_apply_local_rules,   # Contrôle 9.3.4
    check_public_firewall_apply_local_ipsec_rules,   # Contrôle 9.3.5
    check_public_firewall_log_file_path,   # Contrôle 9.3.6
    check_public_firewall_log_file_size,   # Contrôle 9.3.7
    check_public_firewall_log_dropped_packets,   # Contrôle 9.3.8
    check_public_firewall_log_successful_connections,   # Contrôle 9.3.9
    check_audit_credential_validation,   # Contrôle 17.1.1
    check_audit_application_group_management,   # Contrôle 17.2.1
    check_audit_security_group_management,   # Contrôle 17.2.2
    check_audit_user_account_management,   # Contrôle 17.2.3
    check_audit_pnp_activity,   # Contrôle 17.3.1
    check_audit_process_creation,   # Contrôle 17.3.2
    check_audit_account_lockout,   # Contrôle 17.5.1
    check_audit_group_membership,   # Contrôle 17.5.2
    check_audit_logoff,   # Contrôle 17.5.3
    check_audit_logon,   # Contrôle 17.5.4
    check_audit_other_logon_logoff_events,   # Contrôle 17.5.5
    check_audit_special_logon,   # Contrôle 17.5.6
    check_audit_detailed_file_share,   # Contrôle 17.6.1
    check_audit_file_share,   # Contrôle 17.6.2
    check_audit_other_object_access_events,   # Contrôle 17.6.3
    check_audit_removable_storage,   # Contrôle 17.6.4
    check_audit_audit_policy_change,   # Contrôle 17.7.1
    check_audit_authentication_policy_change,   # Contrôle 17.7.2
    check_audit_authorization_policy_change,   # Contrôle 17.7.3
    check_audit_mpssvc_rule_level_policy_change,   # Contrôle 17.7.4
    check_audit_other_policy_change_events,   # Contrôle 17.7.5
    check_audit_sensitive_privilege_use,   # Contrôle 17.8.1
    check_audit_ipsec_driver,   # Contrôle 17.9.1
    check_audit_other_system_events,   # Contrôle 17.9.2
    check_audit_security_state_change,   # Contrôle 17.9.3
    check_audit_security_system_extension,   # Contrôle 17.9.4
    check_audit_system_integrity,   # Contrôle 17.9.5
    check_prevent_lock_screen_camera,   # Contrôle 18.1.1.1
    check_prevent_lock_screen_slide_show,   # Contrôle 18.1.1.2
    check_allow_online_speech_recognition,   # Contrôle 18.1.2.2
    check_allow_online_tips,   # Contrôle 18.1.3
    check_rpc_packet_level_privacy,   # Contrôle 18.4.1
    check_smb_v1_client_driver,   # Contrôle 18.4.2
    check_smb_v1_server,   # Contrôle 18.4.3
    check_enable_certificate_padding,   # Contrôle 18.4.4
    check_sehop,  # Exécuter le contrôle 18.4.5
    check_netbt_node_type,  # Exécuter le contrôle 18.4.6
    check_wdigest_authentication, # Exécuter le contrôle 18.4.7
    check_auto_admin_logon, # Exécuter le contrôle 18.5.1
    check_disable_ip_source_routing, # Exécuter le contrôle 18.5.2
    check_disable_ip_source_routing_tcpip, # Exécuter le contrôle 18.5.3
    check_disable_save_password, # Exécuter le contrôle 18.5.4
    check_enable_icmp_redirect, # Exécuter le contrôle 18.5.5
    check_keep_alive_time, # Exécuter le contrôle 18.5.6
    check_no_name_release_on_demand, # Exécuter le contrôle 18.5.7
    check_perform_router_discovery, # Exécuter le contrôle 18.5.8
    check_safe_dll_search_mode, # Exécuter le contrôle 18.5.9
    check_screensaver_grace_period, # Exécuter le contrôle 18.5.10
    check_tcp_max_data_retransmissions_ipv6, # Exécuter le contrôle 18.5.11
    check_tcp_max_data_retransmissions, # Exécuter le contrôle 18.5.12
    check_warning_level, # Exécuter le contrôle 18.5.13
    check_doh_policy, # Exécuter le contrôle 18.6.4.1
    check_enable_font_providers, # Exécuter le contrôle 18.6.5.1
    check_insecure_guest_logons, # Exécuter le contrôle 18.6.8.1
    check_mapper_io_driver, # Exécuter le contrôle 18.6.9.1
    check_responder_driver, # Exécuter le contrôle 18.6.9.2
    check_turn_off_peer_to_peer_services, # Exécuter le contrôle 18.6.10.2
    check_prohibit_network_bridge, # Exécuter le contrôle 18.6.11.2
    check_prohibit_internet_connection_sharing, # Exécuter le contrôle 18.6.11.3
    check_hardened_unc_paths, # Exécuter le contrôle 18.6.14.1
    check_wireless_settings_windows_connect_now, # Exécuter le contrôle 18.6.20.1
    check_prohibit_wcn_wizards, #Contrôle 18.6.20.2 
    check_minimize_connections, # Contrôle 18.6.21.1
    check_auto_connect_open_hotspots, # Contrôle 18.6.23.2.1
    check_print_spooler_remote_rpc, # Contrôle 18.7.1 
    check_redirection_guard, # Contrôle 18.7.2 
    check_rpc_connection_protocol, # Contrôle 18.7.3 
    check_rpc_authentication, # Contrôle 18.7.4 
    check_rpc_listener_protocol, # Contrôle 18.7.5 
    check_rpc_listener_auth_protocol, # Contrôle 18.7.6 
    check_rpc_tcp_port, # Contrôle 18.7.7
    check_limit_print_driver_installation, #18.7.8
    check_manage_queue_specific_files, #18.7.9
    check_point_and_print_restrictions, #18.7.10
    check_point_and_print_update_restrictions, #18.7.11
    check_turn_off_notifications_network_usage, # Contrôle 18.8.1.1
    check_remove_personalized_website_recommendations, # Contrôle 18.8.2 
    check_include_command_line_in_process_creation_events, # Contrôle 18.9.3.1
    check_encryption_oracle_remediation, # Contrôle 18.9.4.1
    check_remote_host_delegation, # Contrôle 18.9.4.2 
    check_virtualization_based_security,   # Contrôle 18.9.5.1
    check_virtualization_platform_security_level,   # Contrôle 18.9.5.2
    check_virtualization_based_protection_code_integrity,   # Contrôle 18.9.5.3
    check_uefi_memory_attributes_table,   # Contrôle 18.9.5.4
    check_credential_guard_configuration,   # Contrôle 18.9.5.5
    check_secure_launch_configuration,   # Contrôle 18.9.5.6
    check_kernel_mode_stack_protection,   # Contrôle 18.9.5.7
    check_prevent_device_installation,   # Contrôle 18.9.7.1.1
    check_prevent_device_installation_pci,   # Contrôle 18.9.7.1.2
    check_prevent_device_installation_retroactive,   # Contrôle 18.9.7.1.3
    check_prevent_device_installation_classes,   # Contrôle 18.9.7.1.4
    check_prevent_device_installation_ieee1394,   # Contrôle 18.9.7.1.5
    check_prevent_device_installation_retroactive_classes,   # Contrôle 18.9.7.1.6
    check_prevent_device_metadata_retrieval,   # Contrôle 18.9.7.2
    check_boot_start_driver_initialization_policy,   # Contrôle 18.9.13.1
    check_continue_experiences_on_device,   # Contrôle 18.9.19.2
    check_turn_off_access_to_store,   # Contrôle 18.9.20.1.1
    check_turn_off_print_driver_download_http,   # Contrôle 18.9.20.1.2
    check_turn_off_handwriting_personalization_data_sharing,   # Contrôle 18.9.20.1.3
    check_turn_off_handwriting_recognition_error_reporting,   # Contrôle 18.9.20.1.4
    check_turn_off_internet_connection_wizard,   # Contrôle 18.9.20.1.5
    check_turn_off_internet_download_for_web_publish_online_ordering,   # Contrôle 18.9.20.1.6
    check_turn_off_printing_over_http,   # Contrôle 18.9.20.1.7
    check_turn_off_registration_microsoft_com,   # Contrôle 18.9.20.1.8
    check_turn_off_search_companion_content_file_updates,   # Contrôle 18.9.20.1.9
    check_turn_off_order_prints_picture_task,   # Contrôle 18.9.20.1.10
    check_turn_off_publish_to_web_task,   # Contrôle 18.9.20.1.11
    check_turn_off_messenger_ceip,   # Contrôle 18.9.20.1.12
    check_turn_off_windows_ceip,   # Contrôle 18.9.20.1.13
    check_turn_off_windows_error_reporting,   # Contrôle 18.9.20.1.14
    check_support_device_authentication_using_certificate,   # Contrôle 18.9.23.1
    check_enumeration_policy_for_external_devices_dma_protection,   # Contrôle 18.9.24.1
    check_allow_custom_ssps_aps_in_lsass,   # Contrôle 18.9.26.1
    check_lsass_run_as_protected_process,   # Contrôle 18.9.26.2
    check_disallow_copying_user_input_methods,   # Contrôle 18.9.27.1
    check_block_user_from_showing_account_details_on_signin,   # Contrôle 18.9.28.1
    check_do_not_display_network_selection_ui,   # Contrôle 18.9.28.2
    check_turn_off_app_notifications_on_lock_screen,   # Contrôle 18.9.28.3
    check_turn_on_convenience_pin_sign_in,   # Contrôle 18.9.28.4
    check_allow_clipboard_synchronization_across_devices,   # Contrôle 18.9.31.1
    check_allow_upload_of_user_activities,   # Contrôle 18.9.31.2
    check_allow_network_connectivity_during_connected_standby,   # Contrôle 18.9.33.6.1
    check_allow_network_connectivity_during_connected_standby_plugged_in,   # Contrôle 18.9.33.6.2
    check_allow_standby_states_when_sleeping_on_battery,   # Contrôle 18.9.33.6.3
    check_allow_standby_states_when_sleeping_plugged_in,   # Contrôle 18.9.33.6.4
    check_require_password_when_computer_wakes_on_battery,   # Contrôle 18.9.33.6.5
    check_require_password_when_computer_wakes_plugged_in,   # Contrôle 18.9.33.6.6
    check_configure_offer_remote_assistance,   # Contrôle 18.9.35.1
    check_configure_solicited_remote_assistance,   # Contrôle 18.9.35.2
    check_enable_rpc_endpoint_mapper_client_authentication,   # Contrôle 18.9.36.1
    check_restrict_unauthenticated_rpc_clients,   # Contrôle 18.9.36.2
    check_turn_on_msdm_interactive_communication,   # Contrôle 18.9.47.5.1
    check_enable_disable_perftrack,   # Contrôle 18.9.47.11.1
    check_turn_off_advertising_id,   # Contrôle 18.9.49.1
    check_enable_windows_ntp_client,   # Contrôle 18.9.51.1.1
    check_allow_shared_local_app_data,   # Contrôle 18.10.3.1
    check_prevent_non_admin_install_apps,   # Contrôle 18.10.3.2
    check_let_apps_activate_with_voice_above_lock,   # Contrôle 18.10.4.1
    check_allow_microsoft_accounts_to_be_optional,   # Contrôle 18.10.5.1
    check_block_hosted_app_access_winrt,   # Contrôle 18.10.5.2
    check_disallow_autoplay_for_non_volume_devices,   # Contrôle 18.10.7.1
    check_set_default_behavior_for_autorun,   # Contrôle 18.10.7.2
    check_turn_off_autoplay,   # Contrôle 18.10.7.3
    check_enhanced_anti_spoofing,   # Contrôle 18.10.8.1.1
    check_bitlocker_access_for_older_versions,   # Contrôle 18.10.9.1.1
    check_bitlocker_recovery_option,   # Contrôle 18.10.9.1.2
    check_bitlocker_data_recovery_agent,   # Contrôle 18.10.9.1.3
    check_bitlocker_recovery_password,   # Contrôle 18.10.9.1.4
    check_bitlocker_recovery_key,   # Contrôle 18.10.9.1.5
    check_bitlocker_omit_recovery_options,   # Contrôle 18.10.9.1.6
    check_bitlocker_save_recovery_info_to_ad,   # Contrôle 18.10.9.1.7
    check_bitlocker_storage_recovery_info_to_ad,   # Contrôle 18.10.9.1.8
    check_bitlocker_require_ad_backup,   # Contrôle 18.10.9.1.9
    check_hardware_encryption_disabled,   # Contrôle 18.10.9.1.10
    check_password_for_fixed_drives_disabled,   # Contrôle 18.10.9.1.11
    check_smart_card_on_fixed_drives_enabled,   # Contrôle 18.10.9.1.12
    check_require_smart_card_on_fixed_drives_enabled,   # Contrôle 18.10.9.1.13
    check_allow_enhanced_pins_for_startup_enabled,   # Contrôle 18.10.9.2.1
    check_allow_secure_boot_for_integrity_enabled,   # Contrôle 18.10.9.2.2
    check_bitlocker_os_recovery_enabled,   # Contrôle 18.10.9.2.3
    check_bitlocker_allow_data_recovery_agent,   # Contrôle 18.10.9.2.4
    check_bitlocker_recovery_password,   # Contrôle 18.10.9.2.5
    check_bitlocker_recovery_key,   # Contrôle 18.10.9.2.6
    check_bitlocker_omit_recovery_page,   # Contrôle 18.10.9.2.7
    check_bitlocker_save_recovery_to_ad,   # Contrôle 18.10.9.2.8
    check_bitlocker_store_recovery_to_ad,   # Contrôle 18.10.9.2.9
    check_bitlocker_ad_backup_requirement,   # Contrôle 18.10.9.2.10
    check_hardware_encryption_for_os_drives,   # Contrôle 18.10.9.2.11
    check_passwords_for_os_drives,   # Contrôle 18.10.9.2.12
    check_additional_authentication_at_startup,   # Contrôle 18.10.9.2.13
    check_allow_bitlocker_without_tpm,   # Contrôle 18.10.9.2.14
    check_configure_tpm_startup,   # Contrôle 18.10.9.2.15
    check_configure_tpm_startup_pin,   # Contrôle 18.10.9.2.16
    check_configure_tpm_startup_key,   # Contrôle 18.10.9.2.17
    check_configure_tpm_startup_key_and_pin,   # Contrôle 18.10.9.2.18
    check_allow_access_to_bitlocker_protected_removable_drives,   # Contrôle 18.10.9.3.1
    check_choose_how_bitlocker_protected_removable_drives_can_be_recovered,   # Contrôle 18.10.9.3.2
    check_allow_data_recovery_agent_for_removable_drives,   # Contrôle 18.10.9.3.3
    check_recovery_password_for_removable_drives,   # Contrôle 18.10.9.3.4
    check_recovery_key_for_removable_drives,   # Contrôle 18.10.9.3.5
    check_omit_recovery_options,   # Contrôle 18.10.9.3.6
    check_save_recovery_info_to_ad_ds_for_removable_drives,   # Contrôle 18.10.9.3.7
    check_configure_storage_of_bitlocker_recovery_info_to_ad_ds,   # Contrôle 18.10.9.3.8
    check_bitlocker_recovery_info_to_ad_ds_for_removable_drives,   # Contrôle 18.10.9.3.9
    check_bitlocker_hardware_encryption_for_removable_drives,   # Contrôle 18.10.9.3.10
    check_bitlocker_password_for_removable_drives,   # Contrôle 18.10.9.3.11
    check_bitlocker_smartcards_for_removable_drives,   # Contrôle 18.10.9.3.12
    check_bitlocker_smartcards_enforce_for_removable_drives,   # Contrôle 18.10.9.3.13
    check_bitlocker_deny_write_access_to_non_bitlocker_drives,   # Contrôle 18.10.9.3.14
    check_bitlocker_deny_write_access_to_other_organizations,   # Contrôle 18.10.9.3.15
    check_disable_new_dma_devices_when_locked,   # Contrôle 18.10.9.4
    check_and_configure_allow_use_of_camera,   # Contrôle 18.10.10.1
    check_and_configure_disable_consumer_account_state_content,   # Contrôle 18.10.12.1
    check_and_configure_disable_cloud_optimized_content,   # Contrôle 18.10.12.2
    check_and_configure_disable_microsoft_consumer_experiences,   # Contrôle 18.10.12.3
    check_require_pin_for_pairing,  #Contrôle 18.10.13.1
    check_disable_password_reveal,  # Contrôle 18.10.14.1
    check_enumerate_administrator_accounts,  # Contrôle 18.10.14.2
    check_prevent_security_questions_for_local_accounts,  # Contrôle 18.10.14.3
    check_allow_diagnostic_data,  # Contrôle 18.10.15.1
    check_disable_authenticated_proxy_usage,  # Contrôle 18.10.15.2
    check_disable_onesettings_downloads,  # Contrôle 18.10.15.3
    check_do_not_show_feedback_notifications,  # Contrôle 18.10.15.4
    check_enable_onesettings_auditing,  # Contrôle 18.10.15.5
    check_limit_diagnostic_log_collection,  # Contrôle 18.10.15.6
    check_limit_dump_collection,  # Contrôle 18.10.15.7
    check_toggle_user_control_over_insider_builds,  # Contrôle 18.10.15.8
    check_download_mode,  # Contrôle 18.10.16.1
    check_enable_app_installer,  # Contrôle 18.10.17.1
    check_enable_experimental_features,  # Contrôle 18.10.17.2
    check_enable_hash_override,  # Contrôle 18.10.17.3
    check_enable_ms_appinstaller_protocol,  # Contrôle 18.10.17.4
    check_event_log_retention,  # Contrôle 18.10.25.1.1
    check_max_log_file_size,  # Contrôle 18.10.25.1.2
    check_security_event_log_retention,  # Contrôle 18.10.25.2.1
    check_security_max_log_file_size,  # Contrôle 18.10.25.2.2
    check_setup_event_log_retention,  # Contrôle 18.10.25.3.1
    check_setup_max_log_file_size,  # Contrôle 18.10.25.3.2
    check_system_event_log_retention,  # Contrôle 18.10.25.4.1
    check_system_max_log_file_size,  # Contrôle 18.10.25.4.2
    check_disable_account_based_insights,  # Contrôle 18.10.28.2
    check_disable_data_execution_prevention_for_explorer,  # Contrôle 18.10.28.3
    check_no_heap_termination_on_corruption,  # Contrôle 18.10.28.4
    check_shell_protocol_protected_mode,  # Contrôle 18.10.28.5
    check_turn_off_location,  # Contrôle 18.10.36.1
    check_allow_message_service_cloud_sync,  # Contrôle 18.10.40.1
    check_block_consumer_microsoft_account_authentication,  # Contrôle 18.10.41.1
    check_local_setting_override_for_map_reporting,  # Contrôle 18.10.42.5.1
    check_join_microsoft_maps,  # Contrôle 18.10.42.5.2
    check_configure_attack_surface_reduction_rules,  # Contrôle 18.10.42.6.1.1
    check_asr_rules,  # Contrôle 18.10.42.6.1.2
    check_prevent_access_to_dangerous_websites,  # Contrôle 18.10.42.6.3.1
    check_enable_file_hash_computation,  # Contrôle 18.10.42.7.1
    check_scan_all_downloaded_files_and_attachments,  # Contrôle 18.10.42.10.1
    check_turn_off_real_time_protection,  # Contrôle 18.10.42.10.2
    check_turn_on_behavior_monitoring,  # Contrôle 18.10.42.10.3
    check_turn_on_script_scanning,  # Contrôle 18.10.42.10.4
    check_configure_watson_events,  # Contrôle 18.10.42.12.1
    check_scan_packed_executables,  # Contrôle 18.10.42.13.1
    check_scan_removable_drives,  # Contrôle 18.10.42.13.2
    check_turn_on_email_scanning,  # Contrôle 18.10.42.13.3
    check_configure_detection_for_pua,  # Contrôle 18.10.42.16
    check_turn_off_microsoft_defender_anti_virus,  # Contrôle 18.10.42.17
    check_allow_auditing_events_in_app_guard,  # Contrôle 18.10.43.1
    check_allow_camera_microphone_access_in_app_guard,  # Contrôle 18.10.43.2
    check_allow_data_persistence_for_app_guard,  # Contrôle 18.10.43.3
    check_allow_files_to_download_and_save_to_host,  # Contrôle 18.10.43.4
    check_configure_defender_application_guard_clipboard,  # Contrôle 18.10.43.5
    check_turn_on_microsoft_defender_app_guard_managed_mode,  # Contrôle 18.10.43.6
    check_enable_news_and_interests_on_taskbar,  # Contrôle 18.10.49.1
    check_prevent_usage_of_onedrive_for_file_storage,  # Contrôle 18.10.50.1
    check_turn_off_push_to_install_service,  # Contrôle 18.10.55.1
    check_disable_cloud_clipboard_integration,  # Contrôle 18.10.56.2.2
    check_do_not_allow_passwords_to_be_saved,  # Contrôle 18.10.56.2.3
    check_allow_users_to_connect_remotely,  # Contrôle 18.10.56.3.2.1
    check_allow_ui_automation_redirection,  # Contrôle 18.10.56.3.3.1
    check_do_not_allow_com_port_redirection,  # Contrôle 18.10.56.3.3.2
    check_do_not_allow_drive_redirection,  # Contrôle 18.10.56.3.3.3
    check_do_not_allow_location_redirection,  # Contrôle 18.10.56.3.3.4
    check_do_not_allow_lpt_port_redirection,  # Contrôle 18.10.56.3.3.5
    check_do_not_allow_pnp_device_redirection,  # Contrôle 18.10.56.3.3.6
    check_do_not_allow_webauthn_redirection,  # Contrôle 18.10.56.3.3.7
    check_always_prompt_for_password,   # Contrôle 18.10.56.3.9.1
    check_require_secure_rpc_communication,   # Contrôle 18.10.56.3.9.2
    check_require_specific_security_layer_for_rdp,   # Contrôle 18.10.56.3.9.3
    check_require_user_authentication_for_nla,   # Contrôle 18.10.56.3.9.4
    check_client_connection_encryption_level,   # Contrôle 18.10.56.3.9.5
    check_idle_session_timeout,   # Contrôle 18.10.56.3.10.1
    check_disconnected_session_timeout,   # Contrôle 18.10.56.3.10.2    
    check_delete_temp_dirs_on_exit,   # Contrôle 18.10.56.3.11.1
    check_disable_enclosure_download,   # Contrôle 18.10.57.1
    check_allow_cloud_search,   # Contrôle 18.10.58.2
    check_allow_cortana,   # Contrôle 18.10.58.3
    check_allow_cortana_above_lock,   # Contrôle 18.10.58.4
    check_allow_indexing_encrypted_files,   # Contrôle 18.10.58.5
    check_allow_search_to_use_location,   # Contrôle 18.10.58.6
    check_allow_search_highlights,   # Contrôle 18.10.58.7
    check_turn_off_kms_client_online_avs_validation,   # Contrôle 18.10.62.1
    check_disable_store_apps,   # Contrôle 18.10.65.1
    check_private_store_only,   # Contrôle 18.10.65.2
    check_auto_download_install,   # Contrôle 18.10.65.3
    check_off_update_offer,   # Contrôle 18.10.65.4
    check_store_application,   # Contrôle 18.10.65.5
    check_allow_widgets,   # Contrôle 18.10.71.1
    check_automatic_data_collection,   # Contrôle 18.10.75.1.1
    check_notify_malicious,   # Contrôle 18.10.75.1.2
    check_notify_password_reuse,   # Contrôle 18.10.75.1.3
    check_notify_unsafe_app,   # Contrôle 18.10.75.1.4
    check_service_enabled,   # Contrôle 18.10.75.1.5
    check_defender_smartscreen,   # Contrôle 18.10.75.2.1
    check_game_recording,   # Contrôle 18.10.77.1
    check_ESS_configuration,   # Contrôle 18.10.78.1
    check_suggested_apps_configuration,   # Contrôle 18.10.79.1
    check_allow_windows_ink_workspace,   # Contrôle 18.10.79.2
    check_allow_user_control_over_installs,   # Contrôle 18.10.80.1
    check_always_install_elevated_privileges,   # Contrôle 18.10.80.2
    check_prevent_ie_security_prompt_for_installer_scripts,   # Contrôle 18.10.80.3
    check_enable_mpr_notifications_for_system,   # Contrôle 18.10.81.1
    check_sign_in_and_lock_last_user_after_restart,   # Contrôle 18.10.81.2
    check_turn_on_powershell_script_block_logging,   # Contrôle 18.10.86.1
    check_turn_on_powershell_transcription,   # Contrôle 18.10.86.2
    check_allow_basic_authentication,   # Contrôle 18.10.88.1.1
    check_allow_unencrypted_traffic,   # Contrôle 18.10.88.1.2
    check_disallow_digest_authentication,   # Contrôle 18.10.88.1.3
    check_allow_basic_authentication_winrm_service,   # Contrôle 18.10.88.2.1
    check_allow_remote_server_management_through_winrm,   # Contrôle 18.10.88.2.2
    check_allow_unencrypted_traffic_winrm_service,   # Contrôle 18.10.88.2.3
    check_disallow_winrm_storing_runas_credentials,   # Contrôle 18.10.88.2.4
    check_allow_remote_shell_access,   # Contrôle 18.10.89.1
    check_allow_clipboard_sharing_with_windows_sandbox,   # Contrôle 18.10.90.1
    check_allow_networking_in_windows_sandbox,   # Contrôle 18.10.90.2
    check_prevent_users_from_modifying_settings,   # Contrôle 18.10.91.2.1
    check_no_auto_restart_with_logged_on_users,   # Contrôle 18.10.92.1.1
    check_configure_automatic_updates,   # Contrôle 18.10.92.2.1
    check_configure_automatic_updates_scheduled_install_day,   # Contrôle 18.10.92.2.2
    check_enable_features_introduced_via_servicing,   # Contrôle 18.10.92.2.3
    check_remove_access_to_pause_updates,   # Contrôle 18.10.92.2.4
    check_manage_preview_builds,   # Contrôle 18.10.92.4.1
    check_select_when_preview_builds_and_feature_updates_are_received,   # Contrôle 18.10.92.4.2
    check_select_when_quality_updates_are_received,   # Contrôle 18.10.92.4.3
    check_enable_optional_updates,   # Contrôle 18.10.92.4.4
    check_turn_off_toast_notifications_on_lock_screen,   # Contrôle 19.5.1.1
    check_turn_off_help_experience_improvement_program,   # Contrôle 19.6.6.1.1
    check_do_not_preserve_zone_information_in_file_attachments,   # Contrôle 19.7.5.1
    check_notify_antivirus_programs_when_opening_attachments,   # Contrôle 19.7.5.2
    check_configure_windows_spotlight_on_lock_screen,   # Contrôle 19.7.8.1
    check_do_not_suggest_third_party_content_in_windows_spotlight,   # Contrôle 19.7.8.2
    check_do_not_use_diagnostic_data_for_tailored_experiences,   # Contrôle 19.7.8.3
    check_turn_off_all_windows_spotlight_features,   # Contrôle 19.7.8.4
    check_turn_off_spotlight_collection_on_desktop,   # Contrôle 19.7.8.5
    check_prevent_users_from_sharing_files_within_their_profile,   # Contrôle 19.7.26.1
    check_turn_off_windows_copilot,   # Contrôle 19.7.38.1
    check_always_install_with_elevated_privileges,   # Contrôle 19.7.42.1
    check_prevent_codec_download,   # Contrôle 19.7.44.2.1
    # Ajoutez ici d'autres fonctions
]

# Exécuter toutes les fonctions et collecter leurs résultats
results = [check() for check in checks]


def generate_html_report(results):
    """
    Génère un fichier HTML contenant les résultats des contrôles.
    Supprime le fichier existant avant de le recréer.
    """
    # Récupérer la date actuelle et le nom du hostname
    current_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = socket.gethostname()

    # Calculer le nombre de conformités
    compliant_count = sum(1 for result in results if result.get("status") == "Conforme")
    total_points = 503
    compliance_percentage = (compliant_count / total_points) * 100
    current_dir = os.getcwd()
    script_dir = os.path.dirname(os.path.abspath(__file__))  # Répertoire de l'exécutable
    html_file = os.path.join(current_dir, "compliance_report.html")
    print(f"Chemin prévu pour le rapport : {html_file}")

    # Supprimer le fichier HTML existant s'il est présent
    if os.path.exists(html_file):
        os.remove(html_file)

    # Générer le contenu HTML
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Compliance Report CIS Benchmark 3.0 for Windows 11</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f4f4f4; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            .compliant {{ color: green; }}
            .non-compliant {{ color: red; }}
            .error {{ color: orange; }}
        </style>
    </head>
    <body>
        <h1>Compliance Report CIS Benchmark 3.0 for Windows 11 - {current_date} - {hostname}</h1>
        <h2>Nombre total de conformités : {compliant_count} / {total_points} points soit : {compliance_percentage:.2f}%</h2>
        <table>
            <tr>
                <th>Contrôles</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
    """
    for result in results:
        # Vérifiez si le résultat est un dictionnaire valide
        if not isinstance(result, dict):
            continue  # Ignorer les résultats non valides

        status_class = {
            "Conforme": "compliant",
            "Non conforme": "non-compliant",
            "Erreur": "error"
        }.get(result.get("status", "Non conforme"), "non-compliant")

        html_content += f"""
        <tr>
            <td>{result.get('id', 'N/A')}</td>
            <td class="{status_class}">{result.get('status', 'Non conforme')}</td>
            <td>{result.get('details', 'Aucun détail fourni')}</td>
        </tr>
        """

    # Ajouter l'annexe avant la fermeture de </body>
    html_content += r"""
        </table>
        <h1>Annexe : CIS Benchmark 3.0 for Windows 11</h1>
        <a href="https://downloads.cisecurity.org/#/" target="OPTION">Télécharger le guide CIS 3.0 Benchmark pour Windows11</a>
        </table>
    </body>
    </html>
    """

    with open(html_file, "w", encoding="utf-8") as file:
        file.write(html_content)

    print(f"{GREEN}Rapport généré : {os.path.abspath('compliance_report.html')}{RESET}")




if __name__ == "__main__":
    # Exécuter tous les contrôles et collecter les résultats
    results = [check() for check in checks]

    # Générer le rapport HTML
    generate_html_report(results)

print("Le programme est terminé.")
input("Appuyez sur Entrée pour fermer...")
