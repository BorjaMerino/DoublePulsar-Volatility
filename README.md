# DoublePulsar-Volatility Plugin
<p align="justify">Volatility plugin to help identify DoublePulsar implant. The plugin is not based on Yara rules. It just dumps the array of functions pointers SrvTransaction2DispatchTable from the srv.sys driver and checks that all of them points to the binary address space (take a look at Zerosum0x0 analysis: https://zerosum0x0.blogspot.com.es/2017/04/doublepulsar-initial-smb-backdoor-ring.html). Note that although the plugin dumps the whole table it would really only be necessary to verify that the SrvTransactionNotImplemented symbol points to the correct place.

<p align="justify">The plugin resolves SrvTransaction2DispatchTable by getting the .pdb path from the debug directory section and downloads it from http://msdl.microsoft.com/download/symbols (or the server you provide with the SYMBOLS option). Once it gets the symbol offset it just dump the array of pointers. If SrvTransactionNotImplemented (entry14) points to an "unknown" location possibly your are dealing with DoublePulsar. It that case volshell and dis() will clear up any doubts.

To run the plugin be sure to have the following dependencies:

    construct:  pip install construct==2.5.5-reupload
    pdbparse:   pip install pdbparse
    pefile:	    pip install pefile
    requests:   pip install requests
    cabextract: apt-get install cabextract

Tested on: Windows 7 SP1 32 bits / Windows 7 SP1 64 bits
Ej:

```
bmerino@kali:~$ volatility --plugins="/usr/share/volatility/contrib/plugins"  -f memory.0c672b16.img --profile=Win7SP1x64 doublepulsar -D /tmp
Volatility Foundation Volatility Framework 2.6

Ptr                Module       Section     
------------------ ------------ ------------
0xfffff880038a9060 srv.sys      PAGE        
0xfffff88003873d90 srv.sys      PAGE        
0xfffff880038a6820 srv.sys      PAGE        
0xfffff880038758c0 srv.sys      PAGE        
0xfffff8800389b600 srv.sys      PAGE        
0xfffff880038738e0 srv.sys      PAGE        
0xfffff880038a9590 srv.sys      PAGE        
0xfffff8800386cbf0 srv.sys      PAGE        
0xfffff88003871310 srv.sys      PAGE        
0xfffff8800388fd20 srv.sys      PAGE        
0xfffff880038a93c0 srv.sys      PAGE        
0xfffff8800388fd20 srv.sys      PAGE        
0xfffff8800388fd20 srv.sys      PAGE        
0xfffff8800389bdd0 srv.sys      PAGE        
0xfffffa800074c060 UNKNOWN                  
0xfffff8800388fb20 srv.sys      PAGE        
0xfffff88003895830 srv.sys      PAGE 
```
More info: http://www.shelliscoming.com/2017/08/doublepulsar-smb-implant-detection-from.html
