rule mem_mimikatz {
  meta:
    id = "mem.mimikatz"
    severity = "critical"
    mitre = "T1003.001"
  strings:
    $a = "mimikatz" nocase
    $b = "sekurlsa::" nocase
    $c = "gentilkiwi" nocase
  condition:
    any of them
}
