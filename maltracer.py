# maltracer.py
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
import sys, os, time, datetime

kernel32 = windll.kernel32
psapi    = windll.psapi

DUMP_DIR = "output"

class Maltracer(object):
    def __init__(self):
        pass

    def check_acls(self):
        self.regexp = set()
        for line in file('re.txt'):
            self.regexp.add(line)

    def check_dump_dir(self):
        now = datetime.datetime.now()
        timestamp = int(time.mktime(now.timetuple()))

        if not os.access(DUMP_DIR, os.F_OK):
            try:
                os.makedirs(DUMP_DIR)
            except: 
                sys.exit(0)

        self.dumpdir = "%s\\%s" % (DUMP_DIR, str(timestamp))
        if not os.access(self.dumpdir, os.F_OK):
            try:
                os.makedirs(self.dumpdir)
            except:
                sys.exit(0)

    def open_process(self, pid):
        h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ,
                                         False,
                                         pid)
        return h_process

    def close_process(self, h_process):
        kernel32.CloseHandle(h_process)

    def get_system_info(self):
        self.system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(self.system_info))

    def isprintable(self, c):
        return ((c >= 0x20) and (c <= 0x7f))

    def strings(self, raw):
        count = 0
        lines = []
        line = ""
        data = raw
        for c in data:
            if self.isprintable(ord(c)):
                line += c
                count += 1
            else:
                if count > 4:
                    lines.append(line)
                count = 0
                line = ""

        return lines

    def dump_mem(self, pid, h_process):
        print "[*] PID: %d" % (pid,)
        page_size = self.system_info.dwPageSize
        max_addr  = self.system_info.lpMaximumApplicationAddress
        min_addr  = self.system_info.lpMinimumApplicationAddress
        mem       = min_addr

        while (mem < max_addr):
            mbi = MEMORY_BASIC_INFORMATION()
            count = c_ulong(0)

            if kernel32.VirtualQueryEx(h_process, mem, byref(mbi), sizeof(mbi)) < sizeof(mbi):
                mem += page_size
                continue

            if mbi.State == 0x1000 and mbi.Type == 0x20000:
                buf = create_string_buffer(mbi.RegionSize)
                if kernel32.ReadProcessMemory(h_process,
                                              mem,
                                              buf,
                                              mbi.RegionSize,
                                              byref(count)):
                    for regexp in self.regexp:
                        if buf.raw.find(regexp) != -1:
                            d = "%s\\%s" % (self.dumpdir, str(pid))
                            if not os.access(d, os.F_OK):
                                try:
                                    os.makedirs(d)
                                except:
                                    sys.exit(0)
                            fd = open("%s\\%s-0x%.8x.dmp" % (d, regexp, mem,), 'wb')
                            fd.write(buf.raw)
                            fd.close()
                            s = self.strings(buf.raw)
                            fd = open("%s\\%s-0x%.8x.txt" % (d, regexp, mem,), 'wb')
                            for p in s:
                                fd.write("%s\n" % (p,) )
                            fd.close()
                            break
                mem += mbi.RegionSize
            else:
                mem += page_size

    def enumerate_processes(self):
        array = c_ulong * 1024
        aProcesses = array()
        cb = sizeof(aProcesses)
        cbNeeded = c_ulong()

        psapi.EnumProcesses(byref(aProcesses), cb, byref(cbNeeded))
        nReturned = cbNeeded.value / sizeof(c_ulong)

        pids = [i for i in aProcesses][:nReturned]
        return pids

    def run_iexplore(self):
        si = STARTUPINFO()
        pi = PROCESS_INFORMATION()
        kernel32.CreateProcessA("C:\\Program Files\\Internet Explorer\\iexplore.exe",
                                "iexplore.exe www.google.com",
                                None,
                                None,
                                False,
                                0x00000010,
                                None,
                                None,
                                byref(si),
                                byref(pi))

        self.iexplore_pid = str(pi.dwProcessId)
        self.iexplore_handle = pi.hProcess
        print "[*] Starting Internet Explorer (PID %s)" % (self.iexplore_pid, )
        time.sleep(10)

    def terminate_iexplore(self):
        kernel32.TerminateProcess(self.iexplore_handle, 1)

    def run(self):
        self.check_acls()
        self.check_dump_dir()
        maltracer_pid = kernel32.GetCurrentProcessId()
        print "[*] Maltracer started (PID %d)" % (maltracer_pid, )
        self.run_iexplore()
        #pids = self.enumerate_processes()
        self.get_system_info()

        #for pid in pids:
        for pid in [int(self.iexplore_pid), ]:
            if pid == maltracer_pid:
                continue
            h_process = self.open_process(pid)
            self.dump_mem(pid, h_process)
            self.close_process(h_process)
        self.terminate_iexplore()


if __name__ == "__main__":
    maltracer = Maltracer()
    maltracer.run()

