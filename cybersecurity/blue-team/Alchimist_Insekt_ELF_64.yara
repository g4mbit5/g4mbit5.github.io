import "elf"


rule Alchimist_Insekt_ELF_64
{
	meta:
    description = ""
	    author = "Yakov Goldberg"
	    date = "2022-11-07"
	    description = "Detect the Linux Alchimist Insekt Implants and Framework binaries"
	    hash1 = "4837be90842f915e146bf87723e38cc0533732ba1a243462417c13efdb732dcb" //Framework x64 - Cisco
	    hash2 = "d94fa98977a9f23b38d6956aa2bf293cf3f44d1d24fd13a8789ab5bf3e95f560" //Insekt x64 - Cisco
	    hash3 = "56ca5d07fa2e8004a008222a999a97a6c27054b510e8dd6bd22048b084079e37" //Insekt x64 - Cisco
	    hash4 = "818b80a08418f3bb4628edd4d766e4de138a58f409a89a5fdba527bab8808dd2" //Variant x64 - Cisco - UPX Packed 0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d
	    hash5 = "c016818f3ff7020ea748810bf4c3b8156607b12bb95d76d5a20dac1f7875b394" //Variant x64 - Threat Hunting
	    hash6 = "5416496c3d9635ec7a8926a4555f125960e24eaa60b109976cd8499885f0213b" //Variant x64 - Threat Hunting - Similar to 818b80a08418f3bb4628edd4d766e4de138a58f409a89a5fdba527bab8808dd2
	    os = "ELF 64-Bit"
	    reference = "https://blog.talosintelligence.com/alchimist-offensive-framework/" 

	    version="1.0"
	    OS = "ELF 64-bit LSB executable"
	strings:
		/* Go Build Signature */
        $x1 = "Go build" wide ascii nocase
        $x2 = "golang.org/x/sys" wide ascii nocase

        /*
			48 8B 54 24 58                          mov     rdx, [rsp+88h+var_30]
			48 8B 9A A8 00 00 00                    mov     rbx, [rdx+0A8h]
			48 8D 05 E8 CD 1F 00                    lea     rax, asc_7FD0E0 ; "\b"
			48 8D 0D EA 43 25 00                    lea     rcx, aAddSshKeyThrea ; "${add_ssh_key}-thread limit\n.WithDeadl"...
			BF 0E 00 00 00                          mov     edi, 0Eh
			E8 D7 0E E2 FF                          call    runtime_mapassign_faststr
			48 C7 40 08 3D 00 00 00                 mov     qword ptr [rax+8], 3Dh ; '='
			83 3D 48 C8 7D 00 00                    cmp     cs:dword_DDCB60, 0
			75 0C                                   jnz     short loc_600326
			48 8D 15 35 6A 26 00                    lea     rdx, aEncodingRuneNo+4A3Bh ; "mkdir -p $HOME/.ssh/;echo \"%s\" >> $HO"...
			48 89 10                                mov     [rax], rdx
			EB 0F  									jmp     short loc_600335 
        */
        $op1 = { 488b542458488b9aa8000000488d05e8cd1f00488d0dea432500bf0e000000e8d70ee2ff48c740083d000000833d48c87d0000750c488d15356a2600488910eb0f }

        /*
			48 8D 8C 24 60 02 00 00                 lea     rcx, [rsp+378h+var_118]
			44 0F 11 39                             movups  xmmword ptr [rcx], xmm15
			48 8D 94 24 70 02 00 00                 lea     rdx, [rsp+378h+var_108]
			44 0F 11 3A                             movups  xmmword ptr [rdx], xmm15
			48 8D 15 DC 9F 0D 00                    lea     rdx, unk_7E8B40
			48 89 94 24 60 02 00 00                 mov     [rsp+378h+var_118], rdx
			4C 8D 05 AD 6B 1B 00                    lea     r8, off_8C5720  ; "r3=reg"
			4C 89 84 24 68 02 00 00                 mov     [rsp+378h+var_110], r8
			48 89 94 24 70 02 00 00                 mov     [rsp+378h+var_108], rdx
			4C 8D 05 A6 6B 1B 00                    lea     r8, off_8C5730  ; "${DEAMON}%s %q: %s%s %"
			4C 89 84 24 78 02 00 00                 mov     [rsp+378h+var_100], r8
			48 8B 1D DF AE 69 00                    mov     rbx, cs:qword_DA9A78
			48 8D 05 60 AF 1B 00                    lea     rax, off_8C9B00
			BF 02 00 00 00                          mov     edi, 2
			48 89 FE                                mov     rsi, rdi
			E8 D3 6D DD FF							call    fmt_Fprint_0
        */

        $op2 = { 488d8c2460020000440f1139488d942470020000440f113a488d15dc9f0d0048899424600200004c8d05ad6b1b004c8984246802000048899424700200004c8d05a66b1b004c89842478020000488b1ddfae6900488d0560af1b00bf020000004889fee8d36dddff }

        /*
			66 41 0F FE FA                          paddd   xmm7, xmm10
			66 0F EF E7                             pxor    xmm4, xmm7
			66 44 0F 6F F4                          movdqa  xmm14, xmm4
			66 41 0F 72 F6 0C                       pslld   xmm14, 0Ch
			66 0F 72 D4 14                          psrld   xmm4, 14h
			66 41 0F EF E6                          pxor    xmm4, xmm14
			66 0F FE CC                             paddd   xmm1, xmm4
		 	66 44 0F EF D1                          pxor    xmm10, xmm1
			66 44 0F 38 00 15 2A 
        */
        $s0 = {66410ffefa660fefe766440f6ff466410f72f6 ?? 660f72d4 ?? 66410fefe6660ffecc66440fefd166440f3800152a}
        $s1 = "alchimist" wide ascii nocase
        $s2 = "Insekt" wide ascii nocase
        $s3 = {72 65 73 20 ?? ?? ?? ??} //res <word> for example, res binder or res master
        $s4 = {73 63 61 6E 20 65 6E 64} //scan end
        $s5 = {66 69 6C 65 20 75 6E 6C} // file unlinked while open: %s
        $s6 = {38 2A 66 75 6E 63 28 2A} //8*func(*big.Int, *big.Int, *big.Int) (*big.Int, *big.Int)
        $s7 = "scan end\nscavtracescpolint" wide ascii nocase
        $s8 = "websocket{user}111{user}123" wide ascii nocase

    condition:
        elf.machine == elf.EM_X86_64 and all of ($x*) and (any of ($op*) or 5 of ($s*))
}