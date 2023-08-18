# This script is run automatically after the TimePRO certificate is renewed. It utilises the Octopus API to update the thumbprint variable.
# The script is the same for production and staging, but the config files are different.

param ($thumbprint)

$ErrorActionPreference = "Stop";

# Importing the configuration file
$config = Import-PowerShellDataFile $PSScriptRoot\octopusConfig.PSD1

# Creating variables to determine magic strings and getting them from the configuration file
$octopusURL = $config.octopusURL
$header = $config.header
$spaceName = $config.spaceName
$projectName = $config.projectName
$variable = @{
    Id = $config.variableId
    Value = $thumbprint
    Type = $config.variableType
    Scope = $config.variableScope
    IsSensitive = $config.variableIsSensitive
}

# Get space
$space = (Invoke-RestMethod -Method Get -Uri "$octopusURL/api/spaces/all" -Headers $header) | Where-Object {$_.Name -eq $spaceName}

# Get project
$project = (Invoke-RestMethod -Method Get -Uri "$octopusURL/api/$($space.Id)/projects/all" -Headers $header) | Where-Object {$_.Name -eq $projectName}

# Get project variables
$projectVariables = Invoke-RestMethod -Method Get -Uri "$octopusURL/api/$($space.Id)/variables/$($project.VariableSetId)" -Headers $header

# Check to see if variable is already present
$variableToUpdate = $projectVariables.Variables | Where-Object {$_.Id -eq $variable.Id}
if ($null -eq $variableToUpdate)
{
    # Create new object
    $variableToUpdate = New-Object -TypeName PSObject
    $variableToUpdate | Add-Member -MemberType NoteProperty -Name "Id" -Value $variable.Id
    $variableToUpdate | Add-Member -MemberType NoteProperty -Name "Value" -Value $variable.Value
    $variableToUpdate | Add-Member -MemberType NoteProperty -Name "Type" -Value $variable.Type
    $variableToUpdate | Add-Member -MemberType NoteProperty -Name "Scope" -Value $variable.Scope
    $variableToUpdate | Add-Member -MemberType NoteProperty -Name "IsSensitive" -Value $variable.IsSensitive

    # Add to collection
    $projectVariables.Variables += $variableToUpdate

    $projectVariables.Variables
}

# Update the value
$variableToUpdate.Value = $variable.Value

# Update the collection
Invoke-RestMethod -Method Put -Uri "$octopusURL/api/$($space.Id)/variables/$($project.VariableSetId)" -Headers $header -Body ($projectVariables | ConvertTo-Json -Depth 10)