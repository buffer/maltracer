# dumper.py
#
# Copyright(c) 2009-2010 Angelo Dell'Aera <buffer@antifork.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA


from ctypes import *
from defines import *

kernel32 = windll.kernel32

class Dumper(object):
    def __init__(self, pid, low_addr, hi_addr):
        self.pid      = pid
        self.low_addr = low_addr
        self.hi_addr  = hi_addr
        self.data     = ""

    def open_process(self):
        self.h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ,
                                              False,
                                              self.pid)

    def close_process(self):
        kernel32.CloseHandle(self.h_process)

    def get_system_info(self):
        self.system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(self.system_info))

    def dump_mem(self):
        page_size = self.system_info.dwPageSize
        #max_addr  = self.system_info.lpMaximumApplicationAddress
        #min_addr  = self.system_info.lpMinimumApplicationAddress
        mem       = self.low_addr
        data      = ""

        while (mem < self.hi_addr):
            #mbi   = MEMORY_BASIC_INFORMATION()
            buf   = create_string_buffer(page_size)
            count = c_ulong(0)

            if not kernel32.ReadProcessMemory(self.h_process,
                                              mem,
                                              buf,
                                              page_size,
                                              byref(count)):
                return False

            data = buf.raw
            cmem = mem
            hex_line  = ''
            ascii_line = ''
            prefix = ''
            first = True

            while (cmem < mem + page_size):
                if not cmem % 16:
                    if not first:
                        hex_line += '"'
                        self.data += "%s %s %s\n" % (prefix, hex_line, ascii_line)
                    first = False

                    prefix  = '/* 0x%x */ ' % (cmem, )
                    hex_line = '"'
                    ascii_line = '// '

                byte = data[int(cmem - mem)]
                if byte.isalnum():
                    ascii_line += byte
                else:
                    ascii_line += '.'

                hex_line += str("\\x%s" % (byte.encode('hex'), ))
                cmem += 1

            mem += page_size

    def run(self):
        self.get_system_info()
        self.open_process()
        self.dump_mem()
        self.close_process()

if __name__ == "__main__":
    pid      = raw_input("Process PID: ")
    min_addr = raw_input("Low address: ")
    max_addr = raw_input("High address: ")
    dumpfile = raw_input("Dump file:")
    dumper = Dumper(int(pid),
                    int(min_addr, 16),
                    int(max_addr, 16))
    dumper.run()

    fd = open(dumpfile, 'wb')
    fd.write(dumper.data)
    fd.close()

