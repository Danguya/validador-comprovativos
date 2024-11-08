rule Detect_Specific_PDF
{
    meta:
        description = "Detect PDF file with specific magic number and size"
        author = "Exemplo de uso de YARA"
        date = "2024-11-07"

    strings:
        $pdf_magic = { 25 50 44 46 } 

    condition:
        $pdf_magic at 0 and filesize == 23851
}

