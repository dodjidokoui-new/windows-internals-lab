# convert.ps1
# Reads a raw binary shellcode file and outputs a C byte array header.
# Usage : .\convert.ps1 shellcode.bin > sc_bytes.h

param(
    [Parameter(Mandatory=$true)]
    [string]$InputFile   # Path to the .bin shellcode file
)

# Read the binary file as raw bytes
$InputFile = (Resolve-Path $InputFile).Path
$bytes = [System.IO.File]::ReadAllBytes($InputFile)
$total = $bytes.length

# Start building the output lines
$lines = @()
$lines += "/* shellcode.bin - $total bytes */"
$lines += "unsigned char sc[] = {"

# Iterate over each byte and format it as 0xNN
# 12 bytes per line for readability
$line = "    "
for ($i = 0; $i -lt $total; $i++) {

    # Format current byte as uppercase hex : 0xNN
    $line += "0x{0:X2}" -f $bytes[$i]

    # Add comma after every byte except the last
    if ($i -lt $total - 1) { $line += ", " }

    # Every 12 bytes : flush the current line and start a new one
    if (($i + 1) % 12 -eq 0) {
        $lines += $line
        $line = "    "
    }
}

# Flush the last incomplete line if it has content
if ($line.Trim() -ne "") { $lines += $line }

$lines += "};"
$lines += "/* sizeof(sc) - $total */"

# Write all lines to stdout (redirect with > sc_bytes.h)
$lines | Out-File -Encoding ascii sc_bytes.h
Write-Host "[+] sc_bytes.h generated - $total bytes"