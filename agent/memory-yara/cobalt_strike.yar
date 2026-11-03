rule mem_cobalt_beacon_strings {
  meta:
    id = "mem.cobalt_strike"
    severity = "critical"
    mitre = "T1071"
  strings:
    $a = "beacon" nocase
    $b = "IEX (New-Object Net.WebClient)" nocase
    $c = "powershell -nop -w hidden" nocase
  condition:
    2 of them
}
