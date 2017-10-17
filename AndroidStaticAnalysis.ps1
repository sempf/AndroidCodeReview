foreach ($keyword in Get-Content C:\Tools\android.txt){
    Write-Host $keyword
    Get-ChildItem "C:\Android\Source\*.*" -Recurse | Select-String -Pattern $keyword -CaseSensitive
    Write-Host `r`n
}
