"""
Plugin that attempts to enumerate the array of pointers SrvTransaction2DispatchTable from the srv.sys driver.
Useful to identify the NSA implant DoublePulsar. 
 
@author:       Borja Merino
@license:      GNU General Public License 2.0
@contact:      bmerinofe@mgmail.com

Dependencies:
    construct:  pip install construct==2.5.5-reupload
    pdbparse:   pip install pdbparse
    pefile:	pip install pefile
    requests:	pip install requests
    cabextract:	apt-get install cabextract

References:
    [1] Geir Skjotskift (2017). Volatility memory forensics plugin for extracting Windows DNS Cache:
        https://github.com/mnemonic-no/dnscache
    [2] Carl Pulley (2013). PLugin designed to resolve addresses or symbol names:
        https://github.com/carlpulley/volatility/blob/master/symbols.py

"""

from volatility.renderers.basic import Address
from volatility.renderers import TreeGrid
import volatility.plugins.common as common
import volatility.cache as cache
import volatility.win32 as win32
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.debug as debug
import volatility.obj as obj
import struct
import pdbparse
import pdbparse.peinfo
import requests
import shutil
import subprocess
import logging
import os

class DoublePulsar(common.AbstractWindowsCommand):
    """Show the array of pointers SrvTransaction2DispatchTable from srv.sys (useful to detect the DoublePulsar implant)"""
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP_DIR', short_option='D', default=None,
                          help='Dump directory for the .pdb file',
                          action='store')
        config.add_option("SYMBOLS", short_option='S', default="http://msdl.microsoft.com/download/symbols",
                          help="Server to download the .pdb file from", action='store')
        config.add_option("PDB_FILE", default=None,
                          help="Path to the .pdb file",
                          action="store")
        config.add_option('PROXY', default=None,
                          help='Proxy server to download .PDB file',
                          action='store')
        config.add_option("CABEXTRACT", default="cabextract",
                          help="Path to cabextract utility",
                          action="store")

    # Taken from malware/idt.py
    def _get_section_name(self, mod, addr):
	try:
	    dos_header = obj.Object("_IMAGE_DOS_HEADER",
	                    offset = mod.DllBase, vm = mod.obj_vm)
	    nt_header = dos_header.get_nt_header()
	except (ValueError, exceptions.SanityCheckException):
	    return ''

	for sec in nt_header.get_sections():
	    if (addr > mod.DllBase + sec.VirtualAddress and
	            addr < sec.Misc.VirtualSize + (mod.DllBase + sec.VirtualAddress)):
	        return str(sec.Name or '')

	return ''

    def _get_debug_symbols(self, addr_space, mod):
        image_base = mod.DllBase
        debug_dir = mod.get_debug_directory()
        debug_data = addr_space.zread(image_base + debug_dir.AddressOfRawData, debug_dir.SizeOfData)

        if debug_data[:4] == 'RSDS':
            return pdbparse.peinfo.get_rsds(debug_data)
	else:
	    return ''

    # Useful code: https://github.com/mnemonic-no/dnscache/blob/master/dnscache.py
    def _download_pdb_file(self, guid, filename):
        archive = filename[:-1] + "_"
        url = "{0}/{1}/{2}/{3}".format(self._config.SYMBOLS, filename, guid, archive)

        proxies = None
        if self._config.PROXY:
            proxies = {
                    'http': self._config.PROXY,
                    'https': self._config.PROXY
                    }

	logging.getLogger("requests").setLevel(logging.WARNING)
        resp = requests.get(url, proxies=proxies, stream=True)

        if resp.status_code != 200:
            return None

        archive_path = os.path.join(self._config.DUMP_DIR, archive)

        with open(archive_path, "wb") as af:
            shutil.copyfileobj(resp.raw, af)

	fh = open("NUL","w")
        subprocess.call([self._config.CABEXTRACT, archive_path, "-d", self._config.DUMP_DIR], stdout = fh, stderr = fh)
	fh.close()

        return os.path.join(self._config.DUMP_DIR, filename)

    # Useful code: https://github.com/carlpulley/volatility/blob/master/symbols.py
    def _get_srvtrans_symbol(self, pdbfile, imgbase):
        pdb = pdbparse.parse(pdbfile, fast_load=True)
        pdb.STREAM_DBI.load()
	
        pdb._update_names()
        pdb.STREAM_GSYM = pdb.STREAM_GSYM.reload()
        pdb.STREAM_GSYM.load()
        pdb.STREAM_OMAP_FROM_SRC = pdb.STREAM_OMAP_FROM_SRC.reload()
        pdb.STREAM_OMAP_FROM_SRC.load()
        pdb.STREAM_SECT_HDR_ORIG = pdb.STREAM_SECT_HDR_ORIG.reload()
        pdb.STREAM_SECT_HDR_ORIG.load()

	sects = pdb.STREAM_SECT_HDR_ORIG.sections
	omap = pdb.STREAM_OMAP_FROM_SRC
        gsyms = pdb.STREAM_GSYM
	srv_trans_pointer = "SrvTransaction2DispatchTable"

	for sym in gsyms.globals:
	    if srv_trans_pointer.lower() in sym.name.lower():
   		    virt_base = sects[sym.segment-1].VirtualAddress
		    sym_rva = omap.remap(sym.offset + virt_base)
		    return sym_rva	
	
	return ''

    def _get_srv(self, addr_space):
	modules = win32.modules.lsmod(addr_space)

	for module in modules:
	    if str(module.BaseDllName) == "srv.sys":
	        return module
	        break
	return ''

    def calculate(self):
        addr_space = utils.load_as(self._config)
	if addr_space.profile.metadata.get("memory_model", "") == "32bit":
		inc = 4
	else:
		inc = 8

	srv_module = self._get_srv(addr_space)
    	if not srv_module:
		debug.error("Driver srv.sys not found.")
                return

	if not self._config.PDB_FILE:
		guid, pdb = self._get_debug_symbols(addr_space, srv_module)
		pdb_file = self._download_pdb_file(guid, pdb)
		if not pdb_file:
		    debug.error("The pdb file could not be downloaded. Try it with the PDB_FILE option.")
                    return
	else:
		pdb_file = self._config.PDB_FILE
	

	off_sym = self._get_srvtrans_symbol(pdb_file, srv_module.DllBase)

	if not off_sym:
		debug.error("SrvTransaction2DispatchTable symbol address not found")
                return

	rva_sym = off_sym + srv_module.DllBase
        mods = dict((addr_space.address_mask(mod.DllBase), mod) for mod in win32.modules.lsmod(addr_space))
        mod_addrs = sorted(mods.keys())

	for i in range(17):
		if inc == 4:
			addr = 	struct.unpack("<I", addr_space.zread(rva_sym, inc))[0]
		else:
			addr = 	struct.unpack("<Q", addr_space.zread(rva_sym, inc))[0]

                module = tasks.find_module(mods, mod_addrs, addr_space.address_mask(addr))
		rva_sym += inc
		yield Address(addr), module


    def render_text(self, outfd, data):
        self.table_header(outfd, [('Ptr', '[addrpad]'),
				  ('Module', '12'),
                                  ('Section', '12'),
                                  ])

        for addr, module in data:
            if module:
                module_name = str(module.BaseDllName or '')
                sect_name = self._get_section_name(module, addr)
            else:
                module_name = "UNKNOWN"
                sect_name = ''

	    self.table_row(outfd,
		  addr,
		  module_name,
		  sect_name)


    def unified_output(self, data):
        return TreeGrid([("Ptr", Address),
                       ("Module", str),
                       ("Section", str)],
                        self.generator(data))


    def generator(self, data):

        for addr, module in data:
            if module:
                module_name = str(module.BaseDllName or '')
                sect_name = self._get_section_name(module, addr)
            else:
                module_name = "UNKNOWN"
                sect_name = ''

	    yield (0, [
		Address(addr),
		str(module_name),
		str(sect_name)
		])

