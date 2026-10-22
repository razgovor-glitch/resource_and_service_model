<#
  Выгрузка ВМ из vCenter в формат RSM (data/raw/vcenter/<server>.json).

  Требуется VMware PowerCLI (Install-Module VMware.PowerCLI -Scope CurrentUser) и read-only
  учётка vCenter. Пароль не передаётся в командной строке: сохраните его один раз
    New-VICredentialStoreItem -Host vc01.corp.example.com -User svc-rsm@vsphere.local -Password '...'
  (или отвечайте на запрос Connect-VIServer).

  pwsh deploy/vcenter/export_vcenter.ps1 -Server vc01.corp.example.com
#>
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [string]$Out = "data/raw/vcenter/$Server.json"
)
$ErrorActionPreference = "Stop"
Import-Module VMware.VimAutomation.Core
Set-PowerCLIConfiguration -Scope Session -InvalidCertificateAction Warn -Confirm:$false | Out-Null
Connect-VIServer -Server $Server | Out-Null

# Теги: категория → значение (категория «owner», «service», «env» и т.п.)
$tagIndex = @{}
$allVms = Get-VM
Get-TagAssignment -Entity $allVms -ErrorAction SilentlyContinue | ForEach-Object {
    $id = $_.Entity.Id
    if (-not $tagIndex.ContainsKey($id)) { $tagIndex[$id] = @{} }
    $tagIndex[$id][$_.Tag.Category.Name] = $_.Tag.Name
}

$vms = foreach ($vm in $allVms) {
    $view = $vm.ExtensionData
    $attrs = @{}
    foreach ($cv in $view.CustomValue) {           # Custom Attributes (часто там «Owner» в legacy)
        $field = $view.AvailableField | Where-Object { $_.Key -eq $cv.Key }
        if ($field) { $attrs[$field.Name] = $cv.Value }
    }
    [ordered]@{
        name              = $vm.Name
        uuid              = $view.Config.Uuid
        instance_uuid     = $view.Config.InstanceUuid
        guest_hostname    = $vm.Guest.HostName
        ip_addresses      = @($vm.Guest.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
        mac_addresses     = @(Get-NetworkAdapter -VM $vm | ForEach-Object { $_.MacAddress })
        guest_os          = $vm.Guest.OSFullName
        num_cpu           = $vm.NumCpu
        memory_mb         = [int]$vm.MemoryMB
        power_state       = "$($vm.PowerState)"
        cluster           = (Get-Cluster -VM $vm -ErrorAction SilentlyContinue).Name
        datacenter        = (Get-Datacenter -VM $vm -ErrorAction SilentlyContinue).Name
        folder            = $vm.Folder.Name
        esxi_host         = $vm.VMHost.Name
        tags              = $(if ($tagIndex.ContainsKey($vm.Id)) { $tagIndex[$vm.Id] } else { @{} })
        annotation        = $vm.Notes
        custom_attributes = $attrs
    }
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Out) | Out-Null
[ordered]@{
    exported_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    vcenter     = $Server
    vms         = @($vms)
} | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path $Out
Disconnect-VIServer -Server $Server -Confirm:$false
Write-Host "ВМ: $(@($vms).Count) → $Out"
