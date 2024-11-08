rule MCX_ATLANTICO {
        meta:
                author = "Joao Estulene | Wilmy Danguya"
                version = "0.1"
                description = "A yara rule to detect a fake MCX invoice"

        strings:
                $magic = {2550 4446 2d31 2e37 0a25}
                $pattern = "iText-5.5.13.3"
                $font = "Helvetica"
                $segundafont = "Helvetica-Bold"
                $terceirafont = "ZapfDingbats"
                $byterange = "0 482 16868"

        condition:
                ($magic and $pattern) and ($font and $segundafont and $terceirafont) and $byterange and (filesize >= 21000 and filesize <= 24000)
}

rule MCX_BCI {
        meta:
                author = "Joao Estulene | Wilmy Danguya"
                version = "0.1"
                description = "A yara rule to detect a fake MCX invoice"

        strings:
                $magic = {2550 4446 2d31 2e37 0a25}
                $pattern = "iText-5.5.13.3"
                $font = "Helvetica"
                $segundafont = "Helvetica-Bold"
                $terceirafont = "ZapfDingbats"
                $byterange = "0 482 16868"

        condition:
                ($magic and $pattern) and ($font and $segundafont and $terceirafont) and $byterange and (filesize >= 25000 and filesize <= 28000)
}


rule MCX_KEVE {
        meta:
                author = "Joao Estulene | Wilmy Danguya"
                version = "0.1"
                description = "A yara rule to detect a fake MCX invoice"

        strings:
                $magic = {2550 4446 2d31 2e37 0a25}
                $pattern = "iText-5.5.13.3"
                $font = "Helvetica"
                $segundafont = "Helvetica-Bold"
                $terceirafont = "ZapfDingbats"
                $byterange = "0 482 16868"

        condition:
                ($magic and $pattern) and ($font and $segundafont and $terceirafont) and $byterange and (filesize >= 55000 and filesize <= 59000)
}

rule MCX_BAI {
        meta:
                author = "Joao Estulene | Wilmy Danguya"
                version = "0.1"
                description = "A yara rule to detect a fake MCX invoice"

        strings:
                $magic = {2550 4446 2d31 2e37 0a25}
                $pattern = "iText-5.5.13.3"
                $font = "Helvetica"
                $segundafont = "Helvetica-Bold"
                $terceirafont = "ZapfDingbats"
                $byterange = "0 482 16868"

        condition:
                ($magic and $pattern) and ($font and $segundafont and $terceirafont) and $byterange and (filesize >= 25000 and filesize <= 28000)
}

rule MCX_BFA {
        meta:
                author = "Joao Estulene | Wilmy Danguya"
                version = "0.1"
                description = "A yara rule to detect a fake MCX invoice"

        strings:
                $magic = {2550 4446 2d31 2e37 0a25}
                $pattern = "iText-5.5.13.3"
                $font = "Helvetica"
                $segundafont = "Helvetica-Bold"
                $terceirafont = "ZapfDingbats"
                $byterange = "0 482 16868"

        condition:
                ($magic and $pattern) and ($font and $segundafont and $terceirafont) and $byterange and (filesize >= 23000 and filesize <= 26000)
}

rule MCX_STANDARD_BANK {
        meta:
                author = "Joao Estulene | Wilmy Danguya"
                version = "0.1"
                description = "A yara rule to detect a fake MCX invoice"

        strings:
                $magic = {2550 4446 2d31 2e37 0a25}
                $pattern = "iText-5.5.13.3"
                $font = "Helvetica"
                $segundafont = "Helvetica-Bold"
                $terceirafont = "ZapfDingbats"
                $byterange = "0 482 16868"

        condition:
                ($magic and $pattern) and ($font and $segundafont and $terceirafont) and $byterange and (filesize >= 27000 and filesize <= 30000)
}