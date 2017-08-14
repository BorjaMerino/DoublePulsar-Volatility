# DoublePulsar-Volatility
Volatility plugin to help identify DoublePulsar. The plugin is not based on Yara rules. It just dumps the array of functions pointers SrvTransaction2DispatchTable from the srv.sys driver and checks that all of them points to the binary address space (take a look at Zerosum0x0 analysis). Note that although the plugin dumps the whole table it would really only be necessary to verify that the SrvTransactionNotImplemented symbol points to the correct place.

The plugin resolves SrvTransaction2DispatchTable by getting the .pdb path from the debug directory section and downloads it from http://msdl.microsoft.com/download/symbols (or the server you provide with the SYMBOLS option). Once it gets the symbol offset it just dump the array of pointers. If SrvTransactionNotImplemented (entry14) points to an "unknown" location possibly your are dealing with DoublePulsar. It that case volshell and dis() will clear up any doubts.

To run the plugin be sure to have the following dependencies:

    construct:  pip install construct==2.5.5-reupload
    pdbparse:   pip install pdbparse
    pefile:	    pip install pefile
    requests:   pip install requests
    cabextract: apt-get install cabextract
