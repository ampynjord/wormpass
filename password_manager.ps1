# ===========================================================
# WORMPASS - GESTIONNAIRE DE MOTS DE PASSE SECURISE
# ===========================================================
# Auteur: Assistant IA
# Version: 1.0
# Date: 27/06/2025
# Description: WormPass - Gestionnaire de mots de passe securise avec interface moderne
# Theme: Rouge et Noir
# ===========================================================

# Chargement des assemblies Windows Forms
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Security

# Variables globales
$global:PasswordDB = @{}
$global:MasterPassword = ""
$global:DatabaseFile = "$PSScriptRoot\wormpass.dat"
$global:IsAuthenticated = $false
$global:MainForm = $null
$global:PasswordListView = $null

# Theme WormPass - Couleurs
$global:WormPassTheme = @{
    PrimaryDark = [System.Drawing.Color]::FromArgb(25, 25, 25)      # Noir principal
    SecondaryDark = [System.Drawing.Color]::FromArgb(45, 45, 45)    # Gris fonce
    AccentRed = [System.Drawing.Color]::FromArgb(220, 53, 69)       # Rouge principal
    DarkRed = [System.Drawing.Color]::FromArgb(178, 34, 52)         # Rouge fonce
    LightRed = [System.Drawing.Color]::FromArgb(248, 81, 73)        # Rouge clair
    TextWhite = [System.Drawing.Color]::White                       # Texte blanc
    TextGray = [System.Drawing.Color]::FromArgb(200, 200, 200)      # Texte gris clair
    BorderGray = [System.Drawing.Color]::FromArgb(70, 70, 70)       # Bordures
    HoverRed = [System.Drawing.Color]::FromArgb(255, 69, 58)        # Rouge survol
}

# ===========================================================
# FONCTIONS UTILITAIRES ET DE MESSAGE
# ===========================================================

function Show-MessageBox {
    param(
        [string]$Message,
        [string]$Title = "WormPass - Gestionnaire de Mots de Passe",
        [System.Windows.Forms.MessageBoxButtons]$Buttons = [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::Information
    )
    return [System.Windows.Forms.MessageBox]::Show($Message, $Title, $Buttons, $Icon)
}

function Show-InputBox {
    param(
        [string]$Prompt,
        [string]$Title = "Saisie",
        [string]$DefaultValue = "",
        [bool]$IsPassword = $false
    )
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Size = New-Object System.Drawing.Size(400, 150)
    $form.StartPosition = "CenterParent"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10, 15)
    $label.Size = New-Object System.Drawing.Size(370, 20)
    $label.Text = $Prompt
    $form.Controls.Add($label)
    
    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(10, 40)
    $textBox.Size = New-Object System.Drawing.Size(360, 23)
    $textBox.Text = $DefaultValue
    if ($IsPassword) {
        $textBox.PasswordChar = '*'
    }
    $form.Controls.Add($textBox)
    
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(215, 75)
    $okButton.Size = New-Object System.Drawing.Size(75, 23)
    $okButton.Text = "OK"
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($okButton)
    $form.AcceptButton = $okButton
    
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(295, 75)
    $cancelButton.Size = New-Object System.Drawing.Size(75, 23)
    $cancelButton.Text = "Annuler"
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($cancelButton)
    $form.CancelButton = $cancelButton
    
    $textBox.Select()
    $result = $form.ShowDialog()
    
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $textBox.Text
    }
    return $null
}

# ===========================================================
# FONCTIONS DE SÉCURITÉ ET CHIFFREMENT
# ===========================================================

function Get-StringHash {
    param([string]$InputString)
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($InputString))
    return [Convert]::ToBase64String($hashBytes)
}

function Encrypt-String {
    param(
        [string]$PlainText,
        [string]$Key
    )
    try {
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = [System.Text.Encoding]::UTF8.GetBytes((Get-StringHash $Key).Substring(0, 32))
        $aes.IV = [System.Text.Encoding]::UTF8.GetBytes((Get-StringHash $Key).Substring(0, 16))
        
        $encryptor = $aes.CreateEncryptor()
        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
        $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
        
        return [Convert]::ToBase64String($encryptedBytes)
    }
    catch {
        throw "Erreur lors du chiffrement: $($_.Exception.Message)"
    }
}

function Decrypt-String {
    param(
        [string]$EncryptedText,
        [string]$Key
    )
    try {
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = [System.Text.Encoding]::UTF8.GetBytes((Get-StringHash $Key).Substring(0, 32))
        $aes.IV = [System.Text.Encoding]::UTF8.GetBytes((Get-StringHash $Key).Substring(0, 16))
        
        $decryptor = $aes.CreateDecryptor()
        $encryptedBytes = [Convert]::FromBase64String($EncryptedText)
        $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
        
        return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
    }
    catch {
        throw "Erreur lors du déchiffrement: $($_.Exception.Message)"
    }
}

# ===========================================================
# FONCTIONS DE GESTION DES MOTS DE PASSE
# ===========================================================

function New-SecurePassword {
    param(
        [int]$Length = 12,
        [bool]$IncludeUppercase = $true,
        [bool]$IncludeLowercase = $true,
        [bool]$IncludeNumbers = $true,
        [bool]$IncludeSpecialChars = $true
    )
    
    $charset = ""
    if ($IncludeLowercase) { $charset += "abcdefghijklmnopqrstuvwxyz" }
    if ($IncludeUppercase) { $charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ" }
    if ($IncludeNumbers) { $charset += "0123456789" }
    if ($IncludeSpecialChars) { $charset += "!@#$%^&*()_+-=[]{}|;:,.<>?" }
    
    if ($charset.Length -eq 0) {
        throw "Au moins un type de caractere doit etre selectionne"
    }
    
    $password = ""
    $random = New-Object System.Random
    
    for ($i = 0; $i -lt $Length; $i++) {
        $password += $charset[$random.Next(0, $charset.Length)]
    }
    
    return $password
}

function Add-PasswordEntry {
    param(
        [string]$Site,
        [string]$Username,
        [string]$Password,
        [string]$Notes = ""
    )
    
    $entry = @{
        Site = $Site
        Username = $Username
        Password = $Password
        Notes = $Notes
        CreatedDate = Get-Date
        ModifiedDate = Get-Date
    }
    
    $global:PasswordDB[$Site] = $entry
    Refresh-PasswordList
    Show-MessageBox "[SUCCESS] Mot de passe ajoute avec succes pour $Site dans WormPass !" "Succes" -Icon Information
}

function Get-PasswordEntry {
    param([string]$Site)
    
    if ($global:PasswordDB.ContainsKey($Site)) {
        return $global:PasswordDB[$Site]
    }
    return $null
}

function Update-PasswordEntry {
    param(
        [string]$Site,
        [string]$Username,
        [string]$Password,
        [string]$Notes = ""
    )
    
    if ($global:PasswordDB.ContainsKey($Site)) {
        $global:PasswordDB[$Site].Username = $Username
        $global:PasswordDB[$Site].Password = $Password
        $global:PasswordDB[$Site].Notes = $Notes
        $global:PasswordDB[$Site].ModifiedDate = Get-Date
        Refresh-PasswordList
        Show-MessageBox "[SUCCESS] Mot de passe mis a jour avec succes pour $Site !" "Succes" -Icon Information
        return $true
    }
    return $false
}

function Remove-PasswordEntry {
    param([string]$Site)
    
    if ($global:PasswordDB.ContainsKey($Site)) {
        $global:PasswordDB.Remove($Site)
        Refresh-PasswordList
        Show-MessageBox "[DELETE] Mot de passe supprime avec succes pour $Site !" "Succes" -Icon Information
        return $true
    }
    return $false
}

function Search-PasswordEntries {
    param([string]$SearchTerm)
    
    $results = @()
    foreach ($site in $global:PasswordDB.Keys) {
        $entry = $global:PasswordDB[$site]
        if ($site -like "*$SearchTerm*" -or 
            $entry.Username -like "*$SearchTerm*" -or 
            $entry.Notes -like "*$SearchTerm*") {
            $results += $entry
        }
    }
    return $results
}

# ===========================================================
# FONCTIONS DE SAUVEGARDE ET CHARGEMENT
# ===========================================================

function Save-PasswordDatabase {
    try {
        if (-not $global:IsAuthenticated) {
            Show-MessageBox "Vous devez être authentifié pour sauvegarder" "Erreur" -Icon Error
            return $false
        }
        
        $jsonData = $global:PasswordDB | ConvertTo-Json -Depth 10
        $encryptedData = Encrypt-String -PlainText $jsonData -Key $global:MasterPassword
        
        $encryptedData | Out-File -FilePath $global:DatabaseFile -Encoding UTF8
        
        Show-MessageBox "[SAVED] Base de donnees WormPass sauvegardee avec succes !" "Succes" -Icon Information
        return $true
    }
    catch {
        Show-MessageBox "Erreur lors de la sauvegarde: $($_.Exception.Message)" "Erreur" -Icon Error
        return $false
    }
}

function Load-PasswordDatabase {
    try {
        if (-not (Test-Path $global:DatabaseFile)) {
            $global:PasswordDB = @{}
            return $true
        }
        
        $encryptedData = Get-Content -Path $global:DatabaseFile -Raw
        $decryptedData = Decrypt-String -EncryptedText $encryptedData -Key $global:MasterPassword
        $global:PasswordDB = $decryptedData | ConvertFrom-Json -AsHashtable
        
        return $true
    }
    catch {
        Show-MessageBox "Erreur lors du chargement: Mot de passe maitre incorrect ou fichier corrompu" "Erreur" -Icon Error
        return $false
    }
}

# ===========================================================
# FONCTIONS D'AUTHENTIFICATION
# ===========================================================

function Show-AuthenticationDialog {
    $authForm = New-Object System.Windows.Forms.Form
    $authForm.Text = "WormPass - Authentification Securisee"
    $authForm.Size = New-Object System.Drawing.Size(500, 350)
    $authForm.StartPosition = "CenterScreen"
    $authForm.FormBorderStyle = "FixedDialog"
    $authForm.MaximizeBox = $false
    $authForm.MinimizeBox = $false
    $authForm.BackColor = $global:WormPassTheme.PrimaryDark
    $authForm.ForeColor = $global:WormPassTheme.TextWhite
    $authForm.Icon = [System.Drawing.SystemIcons]::Shield
    
    # Logo/Titre principal
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Location = New-Object System.Drawing.Point(20, 20)
    $titleLabel.Size = New-Object System.Drawing.Size(450, 40)
    $titleLabel.Text = "[WORM] WORMPASS"
    $titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
    $titleLabel.ForeColor = $global:WormPassTheme.AccentRed
    $titleLabel.TextAlign = "MiddleCenter"
    $authForm.Controls.Add($titleLabel)
    
    # Sous-titre
    $subtitleLabel = New-Object System.Windows.Forms.Label
    $subtitleLabel.Location = New-Object System.Drawing.Point(20, 65)
    $subtitleLabel.Size = New-Object System.Drawing.Size(450, 25)
    $subtitleLabel.Text = "Gestionnaire de Mots de Passe Securise v1.0"
    $subtitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Italic)
    $subtitleLabel.ForeColor = $global:WormPassTheme.TextGray
    $subtitleLabel.TextAlign = "MiddleCenter"
    $authForm.Controls.Add($subtitleLabel)
    
    # Message
    $messageLabel = New-Object System.Windows.Forms.Label
    $messageLabel.Location = New-Object System.Drawing.Point(20, 110)
    $messageLabel.Size = New-Object System.Drawing.Size(450, 40)
    $messageLabel.TextAlign = "MiddleCenter"
    $messageLabel.ForeColor = $global:WormPassTheme.TextWhite
    $messageLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    
    if (Test-Path $global:DatabaseFile) {
        $messageLabel.Text = "Base de donnees WormPass detectee.`nEntrez votre mot de passe maitre :"
    } else {
        $messageLabel.Text = "Bienvenue dans WormPass !`nCreez votre mot de passe maitre pour commencer :"
    }
    $authForm.Controls.Add($messageLabel)
    
    # Panneau pour le mot de passe
    $passwordPanel = New-Object System.Windows.Forms.Panel
    $passwordPanel.Location = New-Object System.Drawing.Point(30, 165)
    $passwordPanel.Size = New-Object System.Drawing.Size(430, 60)
    $passwordPanel.BackColor = $global:WormPassTheme.SecondaryDark
    $authForm.Controls.Add($passwordPanel)
    
    # Mot de passe
    $passwordLabel = New-Object System.Windows.Forms.Label
    $passwordLabel.Location = New-Object System.Drawing.Point(15, 8)
    $passwordLabel.Size = New-Object System.Drawing.Size(150, 20)
    $passwordLabel.Text = "Mot de passe maitre :"
    $passwordLabel.ForeColor = $global:WormPassTheme.TextGray
    $passwordLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $passwordPanel.Controls.Add($passwordLabel)
    
    $passwordTextBox = New-Object System.Windows.Forms.TextBox
    $passwordTextBox.Location = New-Object System.Drawing.Point(15, 30)
    $passwordTextBox.Size = New-Object System.Drawing.Size(400, 25)
    $passwordTextBox.PasswordChar = '*'
    $passwordTextBox.BackColor = $global:WormPassTheme.PrimaryDark
    $passwordTextBox.ForeColor = $global:WormPassTheme.TextWhite
    $passwordTextBox.BorderStyle = "FixedSingle"
    $passwordTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $passwordPanel.Controls.Add($passwordTextBox)
    
    # Confirmation pour nouveau mot de passe
    $confirmPanel = New-Object System.Windows.Forms.Panel
    $confirmPanel.Location = New-Object System.Drawing.Point(30, 235)
    $confirmPanel.Size = New-Object System.Drawing.Size(430, 60)
    $confirmPanel.BackColor = $global:WormPassTheme.SecondaryDark
    $confirmPanel.Visible = $false
    
    $confirmLabel = New-Object System.Windows.Forms.Label
    $confirmLabel.Location = New-Object System.Drawing.Point(15, 8)
    $confirmLabel.Size = New-Object System.Drawing.Size(180, 20)
    $confirmLabel.Text = "Confirmez le mot de passe :"
    $confirmLabel.ForeColor = $global:WormPassTheme.TextGray
    $confirmLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $confirmPanel.Controls.Add($confirmLabel)
    
    $confirmTextBox = New-Object System.Windows.Forms.TextBox
    $confirmTextBox.Location = New-Object System.Drawing.Point(15, 30)
    $confirmTextBox.Size = New-Object System.Drawing.Size(400, 25)
    $confirmTextBox.PasswordChar = '*'
    $confirmTextBox.BackColor = $global:WormPassTheme.PrimaryDark
    $confirmTextBox.ForeColor = $global:WormPassTheme.TextWhite
    $confirmTextBox.BorderStyle = "FixedSingle"
    $confirmTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $confirmPanel.Controls.Add($confirmTextBox)
    $authForm.Controls.Add($confirmPanel)
    
    if (-not (Test-Path $global:DatabaseFile)) {
        $confirmPanel.Visible = $true
        $authForm.Size = New-Object System.Drawing.Size(500, 400)
    }
    
    # Panneau des boutons
    $buttonPanel = New-Object System.Windows.Forms.Panel
    $buttonPanel.Location = New-Object System.Drawing.Point(0, 310)
    if (-not (Test-Path $global:DatabaseFile)) {
        $buttonPanel.Location = New-Object System.Drawing.Point(0, 360)
    }
    $buttonPanel.Size = New-Object System.Drawing.Size(500, 60)
    $buttonPanel.BackColor = $global:WormPassTheme.SecondaryDark
    $authForm.Controls.Add($buttonPanel)
    
    # Boutons
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(250, 15)
    $okButton.Size = New-Object System.Drawing.Size(100, 35)
    $okButton.Text = "ENTRER"
    $okButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $okButton.BackColor = $global:WormPassTheme.AccentRed
    $okButton.ForeColor = $global:WormPassTheme.TextWhite
    $okButton.FlatStyle = "Flat"
    $okButton.FlatAppearance.BorderSize = 0
    $buttonPanel.Controls.Add($okButton)
    $authForm.AcceptButton = $okButton
    
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(360, 15)
    $cancelButton.Size = New-Object System.Drawing.Size(100, 35)
    $cancelButton.Text = "ANNULER"
    $cancelButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $cancelButton.BackColor = $global:WormPassTheme.BorderGray
    $cancelButton.ForeColor = $global:WormPassTheme.TextWhite
    $cancelButton.FlatStyle = "Flat"
    $cancelButton.FlatAppearance.BorderSize = 0
    $buttonPanel.Controls.Add($cancelButton)
    $authForm.CancelButton = $cancelButton
    
    # Événements
    $okButton.Add_Click({
        $password = $passwordTextBox.Text
        
        if ([string]::IsNullOrWhiteSpace($password)) {
            Show-MessageBox "Le mot de passe ne peut pas être vide" "Erreur" -Icon Error
            return
        }
        
        if (-not (Test-Path $global:DatabaseFile)) {
            # Nouveau mot de passe
            $confirmPassword = $confirmTextBox.Text
            
            if ($password -ne $confirmPassword) {
                Show-MessageBox "Les mots de passe ne correspondent pas" "Erreur" -Icon Error
                return
            }
            
            if ($password.Length -lt 6) {
            Show-MessageBox "Le mot de passe maitre doit contenir au moins 6 caracteres" "Erreur" -Icon Error
                return
            }
        }
        
        $global:MasterPassword = $password
        
        if (Load-PasswordDatabase) {
            $global:IsAuthenticated = $true
            $authForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $authForm.Close()
        } else {
            $global:IsAuthenticated = $false
            $global:MasterPassword = ""
        }
    })
    
    $cancelButton.Add_Click({
        $authForm.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $authForm.Close()
    })
    
    $passwordTextBox.Select()
    return $authForm.ShowDialog()
}

# ===========================================================
# INTERFACES GRAPHIQUES SPÉCIALISÉES
# ===========================================================

function Show-AddPasswordDialog {
    $addForm = New-Object System.Windows.Forms.Form
    $addForm.Text = "Ajouter un mot de passe"
    $addForm.Size = New-Object System.Drawing.Size(500, 400)
    $addForm.StartPosition = "CenterParent"
    $addForm.FormBorderStyle = "FixedDialog"
    $addForm.MaximizeBox = $false
    $addForm.MinimizeBox = $false
    
    # Site
    $siteLabel = New-Object System.Windows.Forms.Label
    $siteLabel.Location = New-Object System.Drawing.Point(20, 20)
    $siteLabel.Size = New-Object System.Drawing.Size(100, 20)
    $siteLabel.Text = "Site/Service :"
    $addForm.Controls.Add($siteLabel)
    
    $siteTextBox = New-Object System.Windows.Forms.TextBox
    $siteTextBox.Location = New-Object System.Drawing.Point(130, 20)
    $siteTextBox.Size = New-Object System.Drawing.Size(320, 23)
    $addForm.Controls.Add($siteTextBox)
    
    # Utilisateur
    $userLabel = New-Object System.Windows.Forms.Label
    $userLabel.Location = New-Object System.Drawing.Point(20, 60)
    $userLabel.Size = New-Object System.Drawing.Size(100, 20)
    $userLabel.Text = "Utilisateur :"
    $addForm.Controls.Add($userLabel)
    
    $userTextBox = New-Object System.Windows.Forms.TextBox
    $userTextBox.Location = New-Object System.Drawing.Point(130, 60)
    $userTextBox.Size = New-Object System.Drawing.Size(320, 23)
    $addForm.Controls.Add($userTextBox)
    
    # Mot de passe
    $passwordLabel = New-Object System.Windows.Forms.Label
    $passwordLabel.Location = New-Object System.Drawing.Point(20, 100)
    $passwordLabel.Size = New-Object System.Drawing.Size(100, 20)
    $passwordLabel.Text = "Mot de passe :"
    $addForm.Controls.Add($passwordLabel)
    
    $passwordTextBox = New-Object System.Windows.Forms.TextBox
    $passwordTextBox.Location = New-Object System.Drawing.Point(130, 100)
    $passwordTextBox.Size = New-Object System.Drawing.Size(250, 23)
    $passwordTextBox.PasswordChar = '*'
    $addForm.Controls.Add($passwordTextBox)
    
    $showPasswordCheckBox = New-Object System.Windows.Forms.CheckBox
    $showPasswordCheckBox.Location = New-Object System.Drawing.Point(390, 100)
    $showPasswordCheckBox.Size = New-Object System.Drawing.Size(60, 23)
    $showPasswordCheckBox.Text = "Voir"
    $addForm.Controls.Add($showPasswordCheckBox)
    
    $showPasswordCheckBox.Add_CheckedChanged({
        if ($showPasswordCheckBox.Checked) {
            $passwordTextBox.PasswordChar = ''
        } else {
            $passwordTextBox.PasswordChar = '*'
        }
    })
    
    $generateButton = New-Object System.Windows.Forms.Button
    $generateButton.Location = New-Object System.Drawing.Point(130, 130)
    $generateButton.Size = New-Object System.Drawing.Size(120, 30)
    $generateButton.Text = "Generer"
    $generateButton.BackColor = [System.Drawing.Color]::LightBlue
    $addForm.Controls.Add($generateButton)
    
    $generateButton.Add_Click({
        $generatedPassword = Show-PasswordGeneratorDialog
        if ($generatedPassword) {
            $passwordTextBox.Text = $generatedPassword
        }
    })
    
    # Notes
    $notesLabel = New-Object System.Windows.Forms.Label
    $notesLabel.Location = New-Object System.Drawing.Point(20, 180)
    $notesLabel.Size = New-Object System.Drawing.Size(100, 20)
    $notesLabel.Text = "Notes :"
    $addForm.Controls.Add($notesLabel)
    
    $notesTextBox = New-Object System.Windows.Forms.TextBox
    $notesTextBox.Location = New-Object System.Drawing.Point(130, 180)
    $notesTextBox.Size = New-Object System.Drawing.Size(320, 80)
    $notesTextBox.Multiline = $true
    $notesTextBox.ScrollBars = "Vertical"
    $addForm.Controls.Add($notesTextBox)
    
    # Boutons
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(280, 320)
    $okButton.Size = New-Object System.Drawing.Size(80, 30)
    $okButton.Text = "Ajouter"
    $okButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $okButton.BackColor = [System.Drawing.Color]::LightGreen
    $addForm.Controls.Add($okButton)
    
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(370, 320)
    $cancelButton.Size = New-Object System.Drawing.Size(80, 30)
    $cancelButton.Text = "Annuler"
    $cancelButton.BackColor = [System.Drawing.Color]::LightCoral
    $addForm.Controls.Add($cancelButton)
    
    # Événements
    $okButton.Add_Click({
        $site = $siteTextBox.Text.Trim()
        $username = $userTextBox.Text.Trim()
        $password = $passwordTextBox.Text
        $notes = $notesTextBox.Text.Trim()
        
        if ([string]::IsNullOrWhiteSpace($site)) {
            Show-MessageBox "Le nom du site est obligatoire" "Erreur" -Icon Error
            return
        }
        
        if ($global:PasswordDB.ContainsKey($site)) {
        Show-MessageBox "Une entree existe deja pour ce site" "Erreur" -Icon Error
            return
        }
        
        if ([string]::IsNullOrWhiteSpace($password)) {
            Show-MessageBox "Le mot de passe ne peut pas être vide" "Erreur" -Icon Error
            return
        }
        
        Add-PasswordEntry -Site $site -Username $username -Password $password -Notes $notes
        $addForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $addForm.Close()
    })
    
    $cancelButton.Add_Click({
        $addForm.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $addForm.Close()
    })
    
    $siteTextBox.Select()
    return $addForm.ShowDialog()
}

function Show-PasswordGeneratorDialog {
    $genForm = New-Object System.Windows.Forms.Form
    $genForm.Text = "Generateur de mot de passe"
    $genForm.Size = New-Object System.Drawing.Size(450, 350)
    $genForm.StartPosition = "CenterParent"
    $genForm.FormBorderStyle = "FixedDialog"
    $genForm.MaximizeBox = $false
    $genForm.MinimizeBox = $false
    
    # Longueur
    $lengthLabel = New-Object System.Windows.Forms.Label
    $lengthLabel.Location = New-Object System.Drawing.Point(20, 20)
    $lengthLabel.Size = New-Object System.Drawing.Size(150, 20)
    $lengthLabel.Text = "Longueur du mot de passe :"
    $genForm.Controls.Add($lengthLabel)
    
    $lengthNumeric = New-Object System.Windows.Forms.NumericUpDown
    $lengthNumeric.Location = New-Object System.Drawing.Point(180, 20)
    $lengthNumeric.Size = New-Object System.Drawing.Size(80, 23)
    $lengthNumeric.Minimum = 4
    $lengthNumeric.Maximum = 50
    $lengthNumeric.Value = 12
    $genForm.Controls.Add($lengthNumeric)
    
    # Options
    $optionsGroup = New-Object System.Windows.Forms.GroupBox
    $optionsGroup.Location = New-Object System.Drawing.Point(20, 60)
    $optionsGroup.Size = New-Object System.Drawing.Size(390, 120)
    $optionsGroup.Text = "Types de caractères"
    $genForm.Controls.Add($optionsGroup)
    
    $upperCheckBox = New-Object System.Windows.Forms.CheckBox
    $upperCheckBox.Location = New-Object System.Drawing.Point(20, 25)
    $upperCheckBox.Size = New-Object System.Drawing.Size(150, 20)
    $upperCheckBox.Text = "Majuscules (A-Z)"
    $upperCheckBox.Checked = $true
    $optionsGroup.Controls.Add($upperCheckBox)
    
    $lowerCheckBox = New-Object System.Windows.Forms.CheckBox
    $lowerCheckBox.Location = New-Object System.Drawing.Point(20, 50)
    $lowerCheckBox.Size = New-Object System.Drawing.Size(150, 20)
    $lowerCheckBox.Text = "Minuscules (a-z)"
    $lowerCheckBox.Checked = $true
    $optionsGroup.Controls.Add($lowerCheckBox)
    
    $numbersCheckBox = New-Object System.Windows.Forms.CheckBox
    $numbersCheckBox.Location = New-Object System.Drawing.Point(20, 75)
    $numbersCheckBox.Size = New-Object System.Drawing.Size(150, 20)
    $numbersCheckBox.Text = "Chiffres (0-9)"
    $numbersCheckBox.Checked = $true
    $optionsGroup.Controls.Add($numbersCheckBox)
    
    $specialCheckBox = New-Object System.Windows.Forms.CheckBox
    $specialCheckBox.Location = New-Object System.Drawing.Point(180, 25)
    $specialCheckBox.Size = New-Object System.Drawing.Size(200, 20)
    $specialCheckBox.Text = "Caracteres speciaux"
    $specialCheckBox.Checked = $true
    $optionsGroup.Controls.Add($specialCheckBox)
    
    # Résultat
    $resultLabel = New-Object System.Windows.Forms.Label
    $resultLabel.Location = New-Object System.Drawing.Point(20, 200)
    $resultLabel.Size = New-Object System.Drawing.Size(150, 20)
    $resultLabel.Text = "Mot de passe genere :"
    $genForm.Controls.Add($resultLabel)
    
    $resultTextBox = New-Object System.Windows.Forms.TextBox
    $resultTextBox.Location = New-Object System.Drawing.Point(20, 225)
    $resultTextBox.Size = New-Object System.Drawing.Size(320, 23)
    $resultTextBox.ReadOnly = $true
    $resultTextBox.Font = New-Object System.Drawing.Font("Consolas", 10)
    $genForm.Controls.Add($resultTextBox)
    
    $copyButton = New-Object System.Windows.Forms.Button
    $copyButton.Location = New-Object System.Drawing.Point(350, 225)
    $copyButton.Size = New-Object System.Drawing.Size(60, 23)
    $copyButton.Text = "Copier"
    $copyButton.Enabled = $false
    $genForm.Controls.Add($copyButton)
    
    $generateButton = New-Object System.Windows.Forms.Button
    $generateButton.Location = New-Object System.Drawing.Point(20, 260)
    $generateButton.Size = New-Object System.Drawing.Size(100, 30)
    $generateButton.Text = "Generer"
    $generateButton.BackColor = [System.Drawing.Color]::LightBlue
    $genForm.Controls.Add($generateButton)
    
    # Boutons
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(260, 260)
    $okButton.Size = New-Object System.Drawing.Size(80, 30)
    $okButton.Text = "OK"
    $okButton.Enabled = $false
    $okButton.BackColor = [System.Drawing.Color]::LightGreen
    $genForm.Controls.Add($okButton)
    
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(350, 260)
    $cancelButton.Size = New-Object System.Drawing.Size(80, 30)
    $cancelButton.Text = "Annuler"
    $cancelButton.BackColor = [System.Drawing.Color]::LightCoral
    $genForm.Controls.Add($cancelButton)
    
    # Variables
    $script:generatedPassword = ""
    
    # Événements
    $generateButton.Add_Click({
        try {
            $length = [int]$lengthNumeric.Value
            $includeUpper = $upperCheckBox.Checked
            $includeLower = $lowerCheckBox.Checked
            $includeNumbers = $numbersCheckBox.Checked
            $includeSpecial = $specialCheckBox.Checked
            
            if (-not ($includeUpper -or $includeLower -or $includeNumbers -or $includeSpecial)) {
            Show-MessageBox "Au moins un type de caractere doit etre selectionne" "Erreur" -Icon Error
                return
            }
            
            $script:generatedPassword = New-SecurePassword -Length $length -IncludeUppercase $includeUpper -IncludeLowercase $includeLower -IncludeNumbers $includeNumbers -IncludeSpecialChars $includeSpecial
            $resultTextBox.Text = $script:generatedPassword
            $copyButton.Enabled = $true
            $okButton.Enabled = $true
        }
        catch {
            Show-MessageBox "Erreur lors de la generation: $($_.Exception.Message)" "Erreur" -Icon Error
        }
    })
    
    $copyButton.Add_Click({
        if ($script:generatedPassword) {
            [System.Windows.Forms.Clipboard]::SetText($script:generatedPassword)
            Show-MessageBox "Mot de passe copie dans le presse-papiers" "Information" -Icon Information
        }
    })
    
    $okButton.Add_Click({
        $genForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $genForm.Close()
    })
    
    $cancelButton.Add_Click({
        $genForm.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $genForm.Close()
    })
    
    $result = $genForm.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $script:generatedPassword
    }
    return $null
}

function Refresh-PasswordList {
    if ($global:PasswordListView) {
        $global:PasswordListView.Items.Clear()
        
        foreach ($site in $global:PasswordDB.Keys | Sort-Object) {
            $entry = $global:PasswordDB[$site]
            $listItem = New-Object System.Windows.Forms.ListViewItem($site)
            $listItem.SubItems.Add($entry.Username)
            $listItem.SubItems.Add('*' * $entry.Password.Length)
            $listItem.SubItems.Add($entry.CreatedDate.ToString('dd/MM/yyyy'))
            $listItem.SubItems.Add($entry.Notes)
            $listItem.Tag = $entry
            $global:PasswordListView.Items.Add($listItem)
        }
        
        # Mise à jour du statut
        if ($global:StatusLabel) {
            $global:StatusLabel.Text = "[OK] $($global:PasswordDB.Count) mot(s) de passe charge(s)"
        }
    }
}

# ===========================================================
# INTERFACE PRINCIPALE
# ===========================================================

function New-MainForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "WormPass v1.0 - Gestionnaire de Mots de Passe Securise"
    $form.Size = New-Object System.Drawing.Size(1000, 650)
    $form.StartPosition = "CenterScreen"
    $form.MinimumSize = New-Object System.Drawing.Size(900, 600)
    $form.BackColor = $global:WormPassTheme.PrimaryDark
    $form.ForeColor = $global:WormPassTheme.TextWhite
    $form.Icon = [System.Drawing.SystemIcons]::Shield
    
    # Header avec logo (utilise Dock pour un meilleur placement)
    $headerPanel = New-Object System.Windows.Forms.Panel
    $headerPanel.Dock = [System.Windows.Forms.DockStyle]::Top
    $headerPanel.Height = 70
    $headerPanel.BackColor = $global:WormPassTheme.SecondaryDark
    $form.Controls.Add($headerPanel)
    
    $logoLabel = New-Object System.Windows.Forms.Label
    $logoLabel.Location = New-Object System.Drawing.Point(20, 10)
    $logoLabel.Size = New-Object System.Drawing.Size(200, 50)
    $logoLabel.Text = "[WORM] WormPass"
    $logoLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $logoLabel.ForeColor = $global:WormPassTheme.AccentRed
    $logoLabel.TextAlign = "MiddleLeft"
    $headerPanel.Controls.Add($logoLabel)
    
    $versionLabel = New-Object System.Windows.Forms.Label
    $versionLabel.Location = New-Object System.Drawing.Point(850, 25)
    $versionLabel.Size = New-Object System.Drawing.Size(100, 20)
    $versionLabel.Text = "Version 1.0"
    $versionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)
    $versionLabel.ForeColor = $global:WormPassTheme.TextGray
    $versionLabel.TextAlign = "MiddleRight"
    $headerPanel.Controls.Add($versionLabel)
    
    # Menu principal
    $menuStrip = New-Object System.Windows.Forms.MenuStrip
    $menuStrip.Dock = [System.Windows.Forms.DockStyle]::Top
    $menuStrip.BackColor = $global:WormPassTheme.SecondaryDark
    $menuStrip.ForeColor = $global:WormPassTheme.TextWhite
    
    # Menu Fichier
    $fileMenu = New-Object System.Windows.Forms.ToolStripMenuItem
    $fileMenu.Text = "Fichier"
    $fileMenu.BackColor = $global:WormPassTheme.SecondaryDark
    $fileMenu.ForeColor = $global:WormPassTheme.TextWhite
    
    $newItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $newItem.Text = "Nouveau mot de passe"
    $newItem.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::N
    $newItem.BackColor = $global:WormPassTheme.SecondaryDark
    $newItem.ForeColor = $global:WormPassTheme.TextWhite
    $newItem.Add_Click({ Show-AddPasswordDialog })
    $fileMenu.DropDownItems.Add($newItem) | Out-Null
    
    $saveItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $saveItem.Text = "Sauvegarder"
    $saveItem.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::S
    $saveItem.BackColor = $global:WormPassTheme.SecondaryDark
    $saveItem.ForeColor = $global:WormPassTheme.TextWhite
    $saveItem.Add_Click({ Save-PasswordDatabase })
    $fileMenu.DropDownItems.Add($saveItem) | Out-Null
    
    $fileMenu.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
    
    $exitItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $exitItem.Text = "Quitter"
    $exitItem.ShortcutKeys = [System.Windows.Forms.Keys]::Alt -bor [System.Windows.Forms.Keys]::F4
    $exitItem.BackColor = $global:WormPassTheme.SecondaryDark
    $exitItem.ForeColor = $global:WormPassTheme.TextWhite
    $exitItem.Add_Click({ $form.Close() })
    $fileMenu.DropDownItems.Add($exitItem) | Out-Null
    
    # Menu Outils
    $toolsMenu = New-Object System.Windows.Forms.ToolStripMenuItem
    $toolsMenu.Text = "Outils"
    $toolsMenu.BackColor = $global:WormPassTheme.SecondaryDark
    $toolsMenu.ForeColor = $global:WormPassTheme.TextWhite
    
    $generateItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $generateItem.Text = "Generateur de mot de passe"
    $generateItem.BackColor = $global:WormPassTheme.SecondaryDark
    $generateItem.ForeColor = $global:WormPassTheme.TextWhite
    $generateItem.Add_Click({ Show-PasswordGeneratorDialog })
    $toolsMenu.DropDownItems.Add($generateItem) | Out-Null
    
    $statsItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $statsItem.Text = "Statistiques"
    $statsItem.BackColor = $global:WormPassTheme.SecondaryDark
    $statsItem.ForeColor = $global:WormPassTheme.TextWhite
    $statsItem.Add_Click({ Show-StatsDialog })
    $toolsMenu.DropDownItems.Add($statsItem) | Out-Null
    
    # Menu Aide
    $helpMenu = New-Object System.Windows.Forms.ToolStripMenuItem
    $helpMenu.Text = "Aide"
    $helpMenu.BackColor = $global:WormPassTheme.SecondaryDark
    $helpMenu.ForeColor = $global:WormPassTheme.TextWhite
    
    $aboutItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $aboutItem.Text = "A propos"
    $aboutItem.BackColor = $global:WormPassTheme.SecondaryDark
    $aboutItem.ForeColor = $global:WormPassTheme.TextWhite
    $aboutItem.Add_Click({ Show-AboutDialog })
    $helpMenu.DropDownItems.Add($aboutItem) | Out-Null
    
    $menuStrip.Items.Add($fileMenu) | Out-Null
    $menuStrip.Items.Add($toolsMenu) | Out-Null
    $menuStrip.Items.Add($helpMenu) | Out-Null
    $form.Controls.Add($menuStrip) | Out-Null
    
    # Barre d'outils moderne
    $toolStrip = New-Object System.Windows.Forms.ToolStrip
    $toolStrip.Dock = [System.Windows.Forms.DockStyle]::Top
    $toolStrip.BackColor = $global:WormPassTheme.SecondaryDark
    $toolStrip.ForeColor = $global:WormPassTheme.TextWhite
    $toolStrip.Height = 50
    $toolStrip.RenderMode = [System.Windows.Forms.ToolStripRenderMode]::Professional
    $toolStrip.GripStyle = [System.Windows.Forms.ToolStripGripStyle]::Hidden
    
    $addButton = New-Object System.Windows.Forms.ToolStripButton
    $addButton.Text = "AJOUTER"
    $addButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $addButton.BackColor = $global:WormPassTheme.AccentRed
    $addButton.ForeColor = $global:WormPassTheme.TextWhite
    $addButton.Add_Click({ Show-AddPasswordDialog })
    $toolStrip.Items.Add($addButton) | Out-Null
    
    $editButton = New-Object System.Windows.Forms.ToolStripButton
    $editButton.Text = "MODIFIER"
    $editButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $editButton.BackColor = $global:WormPassTheme.BorderGray
    $editButton.ForeColor = $global:WormPassTheme.TextWhite
    $editButton.Add_Click({ Edit-SelectedPassword })
    $toolStrip.Items.Add($editButton) | Out-Null
    
    $deleteButton = New-Object System.Windows.Forms.ToolStripButton
    $deleteButton.Text = "SUPPRIMER"
    $deleteButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $deleteButton.BackColor = $global:WormPassTheme.DarkRed
    $deleteButton.ForeColor = $global:WormPassTheme.TextWhite
    $deleteButton.Add_Click({ Delete-SelectedPassword })
    $toolStrip.Items.Add($deleteButton) | Out-Null
    
    $toolStrip.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
    
    $generateButton = New-Object System.Windows.Forms.ToolStripButton
    $generateButton.Text = "GENERER"
    $generateButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $generateButton.BackColor = $global:WormPassTheme.BorderGray
    $generateButton.ForeColor = $global:WormPassTheme.TextWhite
    $generateButton.Add_Click({ Show-PasswordGeneratorDialog })
    $toolStrip.Items.Add($generateButton) | Out-Null
    
    $saveButton = New-Object System.Windows.Forms.ToolStripButton
    $saveButton.Text = "SAUVEGARDER"
    $saveButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $saveButton.BackColor = $global:WormPassTheme.BorderGray
    $saveButton.ForeColor = $global:WormPassTheme.TextWhite
    $saveButton.Add_Click({ Save-PasswordDatabase })
    $toolStrip.Items.Add($saveButton) | Out-Null
    
    $form.Controls.Add($toolStrip) | Out-Null
    
    # Zone de recherche moderne
    $searchPanel = New-Object System.Windows.Forms.Panel
    $searchPanel.Dock = [System.Windows.Forms.DockStyle]::Top
    $searchPanel.Height = 60
    $searchPanel.BackColor = $global:WormPassTheme.SecondaryDark
    
    $searchTitleLabel = New-Object System.Windows.Forms.Label
    $searchTitleLabel.Location = New-Object System.Drawing.Point(20, 8)
    $searchTitleLabel.Size = New-Object System.Drawing.Size(150, 20)
    $searchTitleLabel.Text = "[SEARCH] RECHERCHE"
    $searchTitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $searchTitleLabel.ForeColor = $global:WormPassTheme.AccentRed
    $searchPanel.Controls.Add($searchTitleLabel)
    
    $searchTextBox = New-Object System.Windows.Forms.TextBox
    $searchTextBox.Location = New-Object System.Drawing.Point(20, 30)
    $searchTextBox.Size = New-Object System.Drawing.Size(350, 25)
    $searchTextBox.BackColor = $global:WormPassTheme.PrimaryDark
    $searchTextBox.ForeColor = $global:WormPassTheme.TextWhite
    $searchTextBox.BorderStyle = "FixedSingle"
    $searchTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $searchPanel.Controls.Add($searchTextBox)
    
    $searchButton = New-Object System.Windows.Forms.Button
    $searchButton.Location = New-Object System.Drawing.Point(380, 29)
    $searchButton.Size = New-Object System.Drawing.Size(100, 27)
    $searchButton.Text = "RECHERCHER"
    $searchButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $searchButton.BackColor = $global:WormPassTheme.AccentRed
    $searchButton.ForeColor = $global:WormPassTheme.TextWhite
    $searchButton.FlatStyle = "Flat"
    $searchButton.FlatAppearance.BorderSize = 0
    $searchPanel.Controls.Add($searchButton)
    
    $clearButton = New-Object System.Windows.Forms.Button
    $clearButton.Location = New-Object System.Drawing.Point(490, 29)
    $clearButton.Size = New-Object System.Drawing.Size(80, 27)
    $clearButton.Text = "EFFACER"
    $clearButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $clearButton.BackColor = $global:WormPassTheme.BorderGray
    $clearButton.ForeColor = $global:WormPassTheme.TextWhite
    $clearButton.FlatStyle = "Flat"
    $clearButton.FlatAppearance.BorderSize = 0
    $searchPanel.Controls.Add($clearButton)
    
    # Ajouter la zone de recherche APRÈS la barre d'outils
    $form.Controls.Add($searchPanel)
    
    # Liste des mots de passe moderne
    $listPanel = New-Object System.Windows.Forms.Panel
    $listPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $listPanel.Padding = New-Object System.Windows.Forms.Padding(10)
    $listPanel.BackColor = $global:WormPassTheme.PrimaryDark
    
    $global:PasswordListView = New-Object System.Windows.Forms.ListView
    $global:PasswordListView.Dock = [System.Windows.Forms.DockStyle]::Fill
    $global:PasswordListView.View = [System.Windows.Forms.View]::Details
    $global:PasswordListView.FullRowSelect = $true
    $global:PasswordListView.GridLines = $true
    $global:PasswordListView.MultiSelect = $false
    $global:PasswordListView.BackColor = $global:WormPassTheme.PrimaryDark
    $global:PasswordListView.ForeColor = $global:WormPassTheme.TextWhite
    $global:PasswordListView.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $global:PasswordListView.BorderStyle = "FixedSingle"
    
    # Colonnes avec largeurs ajustees et proportionnelles
    $global:PasswordListView.Columns.Add("Site/Service", 200) | Out-Null
    $global:PasswordListView.Columns.Add("Utilisateur", 180) | Out-Null
    $global:PasswordListView.Columns.Add("Mot de passe", 120) | Out-Null
    $global:PasswordListView.Columns.Add("Date creation", 120) | Out-Null
    $global:PasswordListView.Columns.Add("Notes", 300) | Out-Null
    
    $listPanel.Controls.Add($global:PasswordListView)
    $form.Controls.Add($listPanel)
    
    # Menu contextuel moderne
    $contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $contextMenu.BackColor = $global:WormPassTheme.SecondaryDark
    $contextMenu.ForeColor = $global:WormPassTheme.TextWhite
    
    $viewItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $viewItem.Text = "[VIEW] Reveler le mot de passe"
    $viewItem.BackColor = $global:WormPassTheme.SecondaryDark
    $viewItem.ForeColor = $global:WormPassTheme.TextWhite
    $viewItem.Add_Click({ Reveal-SelectedPassword })
    $contextMenu.Items.Add($viewItem) | Out-Null
    
    $copyUserItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $copyUserItem.Text = "[COPY] Copier l'utilisateur"
    $copyUserItem.BackColor = $global:WormPassTheme.SecondaryDark
    $copyUserItem.ForeColor = $global:WormPassTheme.TextWhite
    $copyUserItem.Add_Click({ Copy-SelectedUsername })
    $contextMenu.Items.Add($copyUserItem) | Out-Null
    
    $copyPassItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $copyPassItem.Text = "[COPY] Copier le mot de passe"
    $copyPassItem.BackColor = $global:WormPassTheme.SecondaryDark
    $copyPassItem.ForeColor = $global:WormPassTheme.TextWhite
    $copyPassItem.Add_Click({ Copy-SelectedPassword })
    $contextMenu.Items.Add($copyPassItem) | Out-Null
    
    $contextMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
    
    $editContextItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $editContextItem.Text = "[EDIT] Modifier"
    $editContextItem.BackColor = $global:WormPassTheme.SecondaryDark
    $editContextItem.ForeColor = $global:WormPassTheme.TextWhite
    $editContextItem.Add_Click({ Edit-SelectedPassword })
    $contextMenu.Items.Add($editContextItem) | Out-Null
    
    $deleteContextItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $deleteContextItem.Text = "[DELETE] Supprimer"
    $deleteContextItem.BackColor = $global:WormPassTheme.SecondaryDark
    $deleteContextItem.ForeColor = $global:WormPassTheme.AccentRed
    $deleteContextItem.Add_Click({ Delete-SelectedPassword })
    $contextMenu.Items.Add($deleteContextItem) | Out-Null
    
    $global:PasswordListView.ContextMenuStrip = $contextMenu
    
    # Barre de statut moderne
    $statusStrip = New-Object System.Windows.Forms.StatusStrip
    $statusStrip.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $statusStrip.BackColor = $global:WormPassTheme.SecondaryDark
    $statusStrip.ForeColor = $global:WormPassTheme.TextWhite
    
    $statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $statusLabel.Text = "[OK] WormPass pret"
    $statusLabel.ForeColor = $global:WormPassTheme.TextWhite
    $statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $statusStrip.Items.Add($statusLabel) | Out-Null
    
    # Indicateur de securite
    $securityLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $securityLabel.Text = "[SECURE] Chiffrement AES actif"
    $securityLabel.ForeColor = $global:WormPassTheme.AccentRed
    $securityLabel.Spring = $true
    $securityLabel.TextAlign = "MiddleRight"
    $statusStrip.Items.Add($securityLabel) | Out-Null
    
    $form.Controls.Add($statusStrip) | Out-Null
    
    # Variables globales pour les contrôles
    $global:SearchTextBox = $searchTextBox
    $global:StatusLabel = $statusLabel
    
    # Événements de recherche
    $searchButton.Add_Click({
        $searchTerm = $searchTextBox.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($searchTerm)) {
            Refresh-PasswordList
        } else {
            Search-AndDisplayPasswords $searchTerm
        }
    })
    
    $clearButton.Add_Click({
        $searchTextBox.Clear()
        Refresh-PasswordList
    })
    
    $searchTextBox.Add_KeyDown({
        if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            $searchButton.PerformClick()
        }
    })
    
    # Événement de fermeture
    $form.Add_FormClosing({
        if ($global:IsAuthenticated) {
            $result = Show-MessageBox "Voulez-vous sauvegarder avant de quitter ?" "Sauvegarde" -Buttons YesNoCancel -Icon Question
            if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                Save-PasswordDatabase
            } elseif ($result -eq [System.Windows.Forms.DialogResult]::Cancel) {
                $_.Cancel = $true
            }
        }
    })
    
    return $form
}

function Search-AndDisplayPasswords {
    param([string]$SearchTerm)
    
    $global:PasswordListView.Items.Clear()
    $results = Search-PasswordEntries -SearchTerm $SearchTerm
    
    foreach ($result in $results) {
        $listItem = New-Object System.Windows.Forms.ListViewItem($result.Site)
        $listItem.SubItems.Add($result.Username)
        $listItem.SubItems.Add('*' * $result.Password.Length)
        $listItem.SubItems.Add($result.CreatedDate.ToString('dd/MM/yyyy'))
        $listItem.SubItems.Add($result.Notes)
        $listItem.Tag = $result
        $global:PasswordListView.Items.Add($listItem)
    }
    
    $global:StatusLabel.Text = "[SEARCH] Recherche WormPass: $($results.Count) resultat(s) trouve(s)"
}

function Reveal-SelectedPassword {
    if ($global:PasswordListView.SelectedItems.Count -eq 0) {
        Show-MessageBox "Veuillez selectionner une entree" "Information" -Icon Information
        return
    }
    
    $selectedItem = $global:PasswordListView.SelectedItems[0]
    $entry = $selectedItem.Tag
    
    $result = Show-MessageBox "Voulez-vous reveler le mot de passe pour $($entry.Site) ?" "Confirmation" -Buttons YesNo -Icon Question
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        Show-MessageBox "Mot de passe pour $($entry.Site):`n`n$($entry.Password)" "Mot de passe revele" -Icon Information
    }
}

function Copy-SelectedUsername {
    if ($global:PasswordListView.SelectedItems.Count -eq 0) {
        Show-MessageBox "Veuillez selectionner une entree" "Information" -Icon Information
        return
    }
    
    $selectedItem = $global:PasswordListView.SelectedItems[0]
    $entry = $selectedItem.Tag
    
    [System.Windows.Forms.Clipboard]::SetText($entry.Username)
    $global:StatusLabel.Text = "[COPY] Nom d'utilisateur copie dans le presse-papiers"
}

function Copy-SelectedPassword {
    if ($global:PasswordListView.SelectedItems.Count -eq 0) {
        Show-MessageBox "Veuillez selectionner une entree" "Information" -Icon Information
        return
    }
    
    $selectedItem = $global:PasswordListView.SelectedItems[0]
    $entry = $selectedItem.Tag
    
    [System.Windows.Forms.Clipboard]::SetText($entry.Password)
    $global:StatusLabel.Text = "[COPY] Mot de passe copie dans le presse-papiers"
}

function Edit-SelectedPassword {
    if ($global:PasswordListView.SelectedItems.Count -eq 0) {
        Show-MessageBox "Veuillez selectionner une entree a modifier" "Information" -Icon Information
        return
    }
    
    $selectedItem = $global:PasswordListView.SelectedItems[0]
    $entry = $selectedItem.Tag
    
    Show-EditPasswordDialog $entry
}

function Delete-SelectedPassword {
    if ($global:PasswordListView.SelectedItems.Count -eq 0) {
        Show-MessageBox "Veuillez selectionner une entree a supprimer" "Information" -Icon Information
        return
    }
    
    $selectedItem = $global:PasswordListView.SelectedItems[0]
    $entry = $selectedItem.Tag
    
    $result = Show-MessageBox "Etes-vous sur de vouloir supprimer l'entree pour $($entry.Site) ?" "Confirmation de suppression" -Buttons YesNo -Icon Warning
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        Remove-PasswordEntry -Site $entry.Site
    }
}

function Show-EditPasswordDialog {
    param($Entry)
    
    $editForm = New-Object System.Windows.Forms.Form
    $editForm.Text = "Modifier - $($Entry.Site)"
    $editForm.Size = New-Object System.Drawing.Size(500, 400)
    $editForm.StartPosition = "CenterParent"
    $editForm.FormBorderStyle = "FixedDialog"
    $editForm.MaximizeBox = $false
    $editForm.MinimizeBox = $false
    
    # Site (lecture seule)
    $siteLabel = New-Object System.Windows.Forms.Label
    $siteLabel.Location = New-Object System.Drawing.Point(20, 20)
    $siteLabel.Size = New-Object System.Drawing.Size(100, 20)
    $siteLabel.Text = "Site/Service :"
    $editForm.Controls.Add($siteLabel)
    
    $siteTextBox = New-Object System.Windows.Forms.TextBox
    $siteTextBox.Location = New-Object System.Drawing.Point(130, 20)
    $siteTextBox.Size = New-Object System.Drawing.Size(320, 23)
    $siteTextBox.Text = $Entry.Site
    $siteTextBox.ReadOnly = $true
    $siteTextBox.BackColor = [System.Drawing.Color]::LightGray
    $editForm.Controls.Add($siteTextBox)
    
    # Utilisateur
    $userLabel = New-Object System.Windows.Forms.Label
    $userLabel.Location = New-Object System.Drawing.Point(20, 60)
    $userLabel.Size = New-Object System.Drawing.Size(100, 20)
    $userLabel.Text = "Utilisateur :"
    $editForm.Controls.Add($userLabel)
    
    $userTextBox = New-Object System.Windows.Forms.TextBox
    $userTextBox.Location = New-Object System.Drawing.Point(130, 60)
    $userTextBox.Size = New-Object System.Drawing.Size(320, 23)
    $userTextBox.Text = $Entry.Username
    $editForm.Controls.Add($userTextBox)
    
    # Mot de passe
    $passwordLabel = New-Object System.Windows.Forms.Label
    $passwordLabel.Location = New-Object System.Drawing.Point(20, 100)
    $passwordLabel.Size = New-Object System.Drawing.Size(100, 20)
    $passwordLabel.Text = "Mot de passe :"
    $editForm.Controls.Add($passwordLabel)
    
    $passwordTextBox = New-Object System.Windows.Forms.TextBox
    $passwordTextBox.Location = New-Object System.Drawing.Point(130, 100)
    $passwordTextBox.Size = New-Object System.Drawing.Size(250, 23)
    $passwordTextBox.Text = $Entry.Password
    $passwordTextBox.PasswordChar = '*'
    $editForm.Controls.Add($passwordTextBox)
    
    $showPasswordCheckBox = New-Object System.Windows.Forms.CheckBox
    $showPasswordCheckBox.Location = New-Object System.Drawing.Point(390, 100)
    $showPasswordCheckBox.Size = New-Object System.Drawing.Size(60, 23)
    $showPasswordCheckBox.Text = "Voir"
    $editForm.Controls.Add($showPasswordCheckBox)
    
    $showPasswordCheckBox.Add_CheckedChanged({
        if ($showPasswordCheckBox.Checked) {
            $passwordTextBox.PasswordChar = ''
        } else {
            $passwordTextBox.PasswordChar = '*'
        }
    })
    
    $generateButton = New-Object System.Windows.Forms.Button
    $generateButton.Location = New-Object System.Drawing.Point(130, 130)
    $generateButton.Size = New-Object System.Drawing.Size(120, 30)
    $generateButton.Text = "Generer"
    $generateButton.BackColor = [System.Drawing.Color]::LightBlue
    $editForm.Controls.Add($generateButton)
    
    $generateButton.Add_Click({
        $generatedPassword = Show-PasswordGeneratorDialog
        if ($generatedPassword) {
            $passwordTextBox.Text = $generatedPassword
        }
    })
    
    # Notes
    $notesLabel = New-Object System.Windows.Forms.Label
    $notesLabel.Location = New-Object System.Drawing.Point(20, 180)
    $notesLabel.Size = New-Object System.Drawing.Size(100, 20)
    $notesLabel.Text = "Notes :"
    $editForm.Controls.Add($notesLabel)
    
    $notesTextBox = New-Object System.Windows.Forms.TextBox
    $notesTextBox.Location = New-Object System.Drawing.Point(130, 180)
    $notesTextBox.Size = New-Object System.Drawing.Size(320, 80)
    $notesTextBox.Text = $Entry.Notes
    $notesTextBox.Multiline = $true
    $notesTextBox.ScrollBars = "Vertical"
    $editForm.Controls.Add($notesTextBox)
    
    # Boutons
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(280, 320)
    $okButton.Size = New-Object System.Drawing.Size(80, 30)
    $okButton.Text = "Modifier"
    $okButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $okButton.BackColor = [System.Drawing.Color]::LightGreen
    $editForm.Controls.Add($okButton)
    
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(370, 320)
    $cancelButton.Size = New-Object System.Drawing.Size(80, 30)
    $cancelButton.Text = "Annuler"
    $cancelButton.BackColor = [System.Drawing.Color]::LightCoral
    $editForm.Controls.Add($cancelButton)
    
    # Événements
    $okButton.Add_Click({
        $username = $userTextBox.Text.Trim()
        $password = $passwordTextBox.Text
        $notes = $notesTextBox.Text.Trim()
        
        if ([string]::IsNullOrWhiteSpace($password)) {
            Show-MessageBox "Le mot de passe ne peut pas être vide" "Erreur" -Icon Error
            return
        }
        
        Update-PasswordEntry -Site $Entry.Site -Username $username -Password $password -Notes $notes
        $editForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $editForm.Close()
    })
    
    $cancelButton.Add_Click({
        $editForm.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $editForm.Close()
    })
    
    return $editForm.ShowDialog()
}

function Show-StatsDialog {
    if ($global:PasswordDB.Count -eq 0) {
        Show-MessageBox "Aucune donnee a analyser" "Information" -Icon Information
        return
    }
    
    # Calcul des statistiques
    $totalEntries = $global:PasswordDB.Count
    $passwordLengths = @()
    $oldestEntry = $null
    $newestEntry = $null
    $sitesWithNotes = 0
    $weakPasswords = 0
    $strongPasswords = 0
    
    foreach ($entry in $global:PasswordDB.Values) {
        $passwordLengths += $entry.Password.Length
        
        if ($null -eq $oldestEntry -or $entry.CreatedDate -lt $oldestEntry.CreatedDate) {
            $oldestEntry = $entry
        }
        
        if ($null -eq $newestEntry -or $entry.CreatedDate -gt $newestEntry.CreatedDate) {
            $newestEntry = $entry
        }
        
        if (-not [string]::IsNullOrWhiteSpace($entry.Notes)) {
            $sitesWithNotes++
        }
        
        if ($entry.Password.Length -lt 8) {
            $weakPasswords++
        } elseif ($entry.Password.Length -ge 12) {
            $strongPasswords++
        }
    }
    
    $avgPasswordLength = ($passwordLengths | Measure-Object -Average).Average
    $minPasswordLength = ($passwordLengths | Measure-Object -Minimum).Minimum
    $maxPasswordLength = ($passwordLengths | Measure-Object -Maximum).Maximum
    
    $statsText = @"
STATISTIQUES GENERALES

Nombre total d'entrees: $totalEntries
Entrees avec notes: $sitesWithNotes

ANALYSE DES MOTS DE PASSE:
   • Longueur moyenne: $([math]::Round($avgPasswordLength, 1)) caracteres
   • Longueur minimale: $minPasswordLength caracteres
   • Longueur maximale: $maxPasswordLength caracteres

CHRONOLOGIE:
   • Premiere entree: $($oldestEntry.Site) - $($oldestEntry.CreatedDate.ToString('dd/MM/yyyy HH:mm'))
   • Derniere entree: $($newestEntry.Site) - $($newestEntry.CreatedDate.ToString('dd/MM/yyyy HH:mm'))

ANALYSE DE SECURITE:
   • Mots de passe faibles (<8 caracteres): $weakPasswords
   • Mots de passe forts (>=12 caracteres): $strongPasswords
"@
    
    if ($weakPasswords -gt 0) {
        $statsText += "`n`nRecommandation: Renforcez vos mots de passe faibles!"
    }
    
    Show-MessageBox $statsText "Statistiques" -Icon Information
}

function Show-AboutDialog {
    $aboutText = @"
[WORM] WormPass - Gestionnaire de Mots de Passe
Version 1.0 - Interface Moderne Rouge & Noir

Developpe avec PowerShell et Windows Forms

[FEATURES] Fonctionnalites principales:
• Stockage securise avec chiffrement AES-256
• Interface moderne et ergonomique
• Generateur de mots de passe robuste
• Recherche et filtrage avance
• Statistiques detaillees de securite
• Sauvegarde automatique chiffree
• Menu contextuel complet
• Theme sombre rouge et noir

[SECURITY] Securite:
• Chiffrement AES-256 des donnees
• Authentification par mot de passe maitre
• Hashage SHA-256 des cles
• Protection contre les fuites memoire

[DESIGN] Design:
• Theme moderne rouge et noir
• Interface ergonomique et intuitive
• Icones et symboles pour la navigation
• Couleurs contrastees pour l'accessibilite

(c) 2025 - WormPass v1.0
Developpe par Assistant IA
"@
    
    Show-MessageBox $aboutText "A propos de WormPass" -Icon Information
}

# ===========================================================
# FONCTION PRINCIPALE
# ===========================================================

function Start-PasswordManager {
    # Vérification des prérequis
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Show-MessageBox "Ce script necessite PowerShell 5.0 ou superieur" "Erreur" -Icon Error
        return
    }
    
    # Authentification au démarrage
    $authResult = Show-AuthenticationDialog
    
    if ($authResult -ne [System.Windows.Forms.DialogResult]::OK -or -not $global:IsAuthenticated) {
        Show-MessageBox "Authentification annulee ou echouee" "Information" -Icon Information
        return
    }
    
    # Création et affichage de l'interface principale
    $global:MainForm = New-MainForm
    Refresh-PasswordList
    
    $global:StatusLabel.Text = "[OK] WormPass connecte - $($global:PasswordDB.Count) entree(s) chargee(s)"
    
    # Affichage de la fenêtre principale
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $global:MainForm.ShowDialog() | Out-Null
}

# ===========================================================
# LANCEMENT DU PROGRAMME
# ===========================================================

# Lancement de l'application
Start-PasswordManager