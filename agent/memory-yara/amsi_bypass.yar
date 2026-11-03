rule mem_amsi_bypass {
  meta:
    id = "mem.amsi_bypass"
    severity = "high"
    mitre = "T1562.001"
  strings:
    $a = "amsiutils" nocase
    $b = "AmsiScanBuffer" nocase
    $c = "amsiInitFailed" nocase
  condition:
    any of them
}
