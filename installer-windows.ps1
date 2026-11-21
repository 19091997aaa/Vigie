# Installateur Vigie pour Windows.
# Clic droit sur ce fichier -> "Exécuter avec PowerShell".
# Il installe Python (si besoin), les outils passifs, les outils de scan, puis Vigie.
# Il ne touche à aucune machine distante : il prépare seulement ton PC.

$ErrorActionPreference = "Stop"
$racine   = Split-Path -Parent $MyInvocation.MyCommand.Path
$dossierOutils = Join-Path $env:USERPROFILE "vigie-outils"
$resume = @()

function Titre($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Ok($t)    { Write-Host "  [ok] $t"   -ForegroundColor Green; $script:resume += "ok   : $t" }
function Rate($t)  { Write-Host "  [!]  $t"   -ForegroundColor Yellow; $script:resume += "manque : $t" }

# 1. Python ------------------------------------------------------------------
Titre "Python"
if (Get-Command python -ErrorAction SilentlyContinue) {
    Ok ("Python présent : " + (python --version))
} else {
    Write-Host "  Installation de Python via winget..."
    try { winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements; Ok "Python installé" }
    catch { Rate "Python : installe-le depuis https://www.python.org/downloads/ puis relance ce script" ; return }
}
python -m pip install --user --upgrade pip pipx | Out-Null
python -m pipx ensurepath | Out-Null
$env:Path += ";$env:USERPROFILE\.local\bin"

# 2. Outils passifs (Python) -------------------------------------------------
Titre "Outils passifs (sans action sur les machines)"
# dnstwist[full] : sans son module DNS, dnstwist refuse de demarrer avec des resolveurs publics.
foreach ($p in @("sherlock-project", "dnstwist[full]", "checkdmarc")) {
    try { python -m pipx install $p 2>$null; Ok $p } catch { Rate $p }
}

# 3. Outils de scan (téléchargés depuis GitHub) ------------------------------
Titre "Outils de scan (sur autorisation signée seulement)"
New-Item -ItemType Directory -Force -Path $dossierOutils | Out-Null
function InstallerPD($depot, $exe) {
    try {
        $api = "https://api.github.com/repos/$depot/releases/latest"
        $rel = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "Vigie" }
        $asset = $rel.assets | Where-Object { $_.name -match "windows_amd64\.zip$" } | Select-Object -First 1
        if (-not $asset) { Rate "$exe : pas de version Windows trouvée"; return }
        $zip = Join-Path $env:TEMP $asset.name
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -Headers @{ "User-Agent" = "Vigie" }
        Expand-Archive -Path $zip -DestinationPath $dossierOutils -Force
        Remove-Item $zip -Force
        Ok "$exe"
    } catch { Rate "$exe : $($_.Exception.Message)" }
}
InstallerPD "projectdiscovery/subfinder" "subfinder"
InstallerPD "projectdiscovery/httpx"     "httpx"
InstallerPD "projectdiscovery/nuclei"    "nuclei"
# Ajoute le dossier des outils au PATH de l'utilisateur, une fois pour toutes.
$pathUser = [Environment]::GetEnvironmentVariable("Path", "User")
if ($pathUser -notlike "*$dossierOutils*") {
    [Environment]::SetEnvironmentVariable("Path", "$pathUser;$dossierOutils", "User")
    Ok "Outils ajoutés au PATH (rouvre le terminal pour en profiter)"
}

# 4. Vigie -------------------------------------------------------------------
Titre "Vigie"
$zipVigie = Join-Path $racine "vigie.zip"
if (Test-Path $zipVigie) {
    Expand-Archive -Path $zipVigie -DestinationPath $racine -Force
    Ok "Vigie décompressé dans $racine\vigie"
} elseif (Test-Path (Join-Path $racine "vigie")) {
    Ok "Vigie déjà présent"
} else {
    Rate "vigie.zip introuvable : mets-le dans le même dossier que ce script"
}

# 5. Bilan -------------------------------------------------------------------
Titre "Bilan"
$resume | ForEach-Object { Write-Host "  $_" }
Write-Host "`nOutils d'attaque (Nmap, Metasploit, sqlmap, Hydra, Responder) : à installer à la main,"
Write-Host "et à n'utiliser qu'avec une autorisation signée. Ils ne sont jamais lancés tout seuls."
Write-Host "`nPour lancer Vigie :" -ForegroundColor Cyan
Write-Host "  cd `"$racine\vigie`""
Write-Host "  python -m vigie interface"
Write-Host "`nTerminé. Rouvre ton terminal avant le premier lancement." -ForegroundColor Green
