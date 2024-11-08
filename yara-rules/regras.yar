rule ATLANTICO {
        meta:
                author = "Joao Estulene"
                version = "0.1"
                description = "A yara rule to detect a fake MCX invoice"

        strings:
                $magic = {2550 4446 2d31 2e37 0a25}
                $pattern = "iText-5.5.13.3"
                $font = "Helvetica"
                $segundafont = "Helvetica-Bold"
                $byterange = "0 482 16868"

        condition:
                ($magic and $pattern) and ($font and $segundafont) and $byterange //and (filesize >= 25600 and filesize <= 28672)
}
