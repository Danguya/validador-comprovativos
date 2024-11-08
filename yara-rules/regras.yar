rule ATLANTICO
{
   strings:
        $magic = {2550 4446 2d31 2e37 0a25}
        $pattern = "iText-5"
        $font = "Helvetica"
        $segundafont = "Helvetica-Bold"

    condition:
        ($magic and $pattern) and ($font and $segundafont) and (filesize >= 23000 and filesize <= 24000)
}