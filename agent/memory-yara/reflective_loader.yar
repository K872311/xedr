rule mem_reflective_loader {
  meta:
    id = "mem.reflective_loader"
    severity = "high"
    mitre = "T1055.001"
  strings:
    $a = "ReflectiveLoader" nocase
    $b = "reflective dll" nocase
    $c = "This program cannot be run in DOS mode"
  condition:
    any of them
}
