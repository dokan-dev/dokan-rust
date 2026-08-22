[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$failures = [System.Collections.Generic.List[string]]::new()
$rootLicense = (Get-Content -LiteralPath (Join-Path $repositoryRoot "LICENSE") -Raw) -replace "`r`n", "`n"

Push-Location $repositoryRoot
try {
	$metadataOutput = & cargo metadata --no-deps --format-version 1 --locked
	if ($LASTEXITCODE -ne 0) {
		throw "cargo metadata failed with exit code $LASTEXITCODE"
	}
	$metadata = ($metadataOutput -join [Environment]::NewLine) | ConvertFrom-Json
}
finally {
	Pop-Location
}

$workspaceMembers = @{}
foreach ($member in $metadata.workspace_members) {
	$workspaceMembers[[string]$member] = $true
}

$dependencyMapPattern = "^(?:target\..+\.)?(?:build-|dev-)?dependencies$"
$dependencyTablePattern = "^(?:target\..+\.)?(?:build-|dev-)?dependencies\..+$"

foreach ($package in $metadata.packages) {
	if (-not $workspaceMembers.ContainsKey([string]$package.id)) {
		continue
	}

	$manifestPath = [string]$package.manifest_path
	$relativePath = $manifestPath.Substring($repositoryRoot.Length).TrimStart(
		[IO.Path]::DirectorySeparatorChar,
		[IO.Path]::AltDirectorySeparatorChar
	)
	$lines = Get-Content -LiteralPath $manifestPath
	$section = ""
	$inheritsWorkspaceLints = $false

	for ($lineIndex = 0; $lineIndex -lt $lines.Count; $lineIndex++) {
		$line = $lines[$lineIndex]
		if ($line -match "^\s*\[(?<section>.+)\]\s*(?:#.*)?$") {
			$section = $Matches.section.Trim()
			if ($section -match $dependencyTablePattern) {
				$failures.Add(
					"${relativePath}:$($lineIndex + 1): dependency subtables must be replaced with an entry using ``workspace = true``"
				)
			}
			continue
		}

		$trimmed = $line.Trim()
		if ($trimmed.Length -eq 0 -or $trimmed.StartsWith("#")) {
			continue
		}

		if ($section -eq "lints" -and $trimmed -match "^workspace\s*=\s*true(?:\s*#.*)?$") {
			$inheritsWorkspaceLints = $true
		}

		if ($section -notmatch $dependencyMapPattern) {
			continue
		}

		if ($trimmed -notmatch "^(?<name>['`"]?[A-Za-z0-9_.-]+['`"]?)\s*=") {
			continue
		}

		$dependencyName = $Matches.name
		$dependencyLine = $lineIndex + 1
		$statement = $trimmed
		$braceDepth =
			([regex]::Matches($statement, "\{").Count - [regex]::Matches($statement, "\}").Count)
		while ($braceDepth -gt 0 -and $lineIndex + 1 -lt $lines.Count) {
			$lineIndex++
			$continuation = $lines[$lineIndex].Trim()
			$statement += " $continuation"
			$braceDepth +=
				([regex]::Matches($continuation, "\{").Count - [regex]::Matches($continuation, "\}").Count)
		}

		$dottedWorkspaceEntry =
			$statement -match "^[A-Za-z0-9_.-]+\.workspace\s*=\s*true(?:\s*#.*)?$"
		$inlineWorkspaceEntry = $statement -match "\bworkspace\s*=\s*true\b"
		if (-not $dottedWorkspaceEntry -and -not $inlineWorkspaceEntry) {
			$failures.Add(
				"${relativePath}:${dependencyLine}: dependency '$dependencyName' must inherit from ``[workspace.dependencies]``"
			)
		}
	}

	if (-not $inheritsWorkspaceLints) {
		$failures.Add("${relativePath}: missing ``[lints] workspace = true``")
	}

	if ($null -eq $package.publish) {
		$packageRoot = Split-Path -Parent $manifestPath
		$licensePath = Join-Path $packageRoot "LICENSE"
		if (-not (Test-Path -LiteralPath $licensePath -PathType Leaf)) {
			$failures.Add("${relativePath}: publishable packages must include LICENSE")
		}
		else {
			$packageLicense = (Get-Content -LiteralPath $licensePath -Raw) -replace "`r`n", "`n"
			if ($packageLicense -ne $rootLicense) {
				$failures.Add("${relativePath}: packaged LICENSE differs from the repository license")
			}
		}

		$readmePath = Join-Path $packageRoot ([string]$package.readme)
		if (-not (Test-Path -LiteralPath $readmePath -PathType Leaf)) {
			$failures.Add("${relativePath}: publishable package README is missing")
		}
		elseif ((Get-Item -LiteralPath $readmePath).Length -lt 100) {
			$failures.Add("${relativePath}: publishable package README is unexpectedly small")
		}
	}
}

if ($failures.Count -ne 0) {
	$failures | ForEach-Object { Write-Error $_ }
	exit 1
}

Write-Host "Workspace dependency and lint inheritance policy passed for $($workspaceMembers.Count) packages."
