# Minimal native-WineDbg discriminator.  Do not add parser/body inspection
# until this one breakpoint has demonstrably trapped in the live client.
break *0x14043cf98
info break
cont
