# Shellscan

A banner scanner that makes scanning the web great again.

## What?

What's the purpose of this project, you ask? I needed a quick way of getting all available SSH banners of a given networks under my terms. Nmap is too heavy, and Zmap needs Zgrab, which doens't even output in a format I want. And it requires a lot of manual work!

So, I said "fuck that" and created my own, which is also faster, albeit a little too fast. Depending on the input it can a) crash your computer and b) congest networks. So use with caution. It's not my fault if you do a mini DoS with this thing if you decide to scan `0.0.0.0/4` (Hint: DON'T FUCKING DO IT).

Heavily inspired from Google's gopacket [port scanning example](https://github.com/google/gopacket/blob/master/examples/synscan/main.go).
