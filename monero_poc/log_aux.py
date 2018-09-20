import fileinput
import re
import io
import os
import argparse
import logging
import coloredlogs
import time

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.INFO, use_chroot=False)


TICKS_PER_SECOND = 1000000.


def tic2sec(tic):
    return tic/TICKS_PER_SECOND


class LogAnalyzer(object):
    def __init__(self):
        self.args = None
        self.max_line_len = 0
        self.time_prev = 0
        self.time_prev_o = 0
        self.time_ref = 0
        self.time_ref_r = 0
        self.mem_alloc_prev = 0
        self.mem_alloc_ref = None
        self.mem_alloc_max = 0
        self.serial_device = None
        self.tee_file = None
        self.initial_ticks = None

    def print_line(self, line):
        print(line)
        if self.args.tee_aux:
            self.tee_line(line)

    def tee_line(self, line):
        if self.tee_file:
            self.tee_file.write(line)
            self.tee_file.write('\n')

    def process(self, line):
        line = line.strip()
        if not self.args.tee_aux:
            self.tee_line(line)

        m = re.match(r'^(\d+)\s([^\s]+?)\s([^\s]+?)\s(.*)$', line)
        if m is None:
            self.print_line(line)
            return

        ctime_r = time.time()
        ctime = int(m.group(1))
        ctime_o = ctime
        c_prev = self.time_prev
        c_prev_alloc = self.mem_alloc_prev

        if self.args.no_time:
            line = re.sub(r'^\d+\s*', '', line)

        elif self.args.norm_time:
            if self.initial_ticks is None:
                self.initial_ticks = ctime
                ctime = 0
            elif ctime < self.time_prev_o:
                ctime = self.time_prev + (ctime + (4294967296 - self.time_prev_o))
            else:
                ctime = self.time_prev + (ctime - self.time_prev_o)
            line = re.sub(r'^\d+', '%011d' % ctime, line)

        self.time_prev = ctime
        self.time_prev_o = ctime_o

        if '----diagnostic' in line:
            self.time_ref = ctime
            self.time_ref_r = ctime_r
            return

        self.max_line_len = max(self.max_line_len, min(len(line), 140))
        abs_time = tic2sec(ctime - self.time_ref)
        diff_time = tic2sec(ctime - c_prev)

        mem_free = None
        mem_alloc = None

        mmem = re.match(r'.+?F:\s*(\d+)\sA:\s*(\d+)', line)
        if mmem:
            mem_free = int(mmem.group(1))
            mem_alloc = int(mmem.group(2))

        mmem = re.match(r'.+?Free:\s*(\d+)\sAllocated:\s*(\d+)', line)
        if mmem:
            mem_free = int(mmem.group(1))
            mem_alloc = int(mmem.group(2))

        memstr = ''
        if mem_alloc:
            self.mem_alloc_prev = mem_alloc
            self.mem_alloc_max = max(self.mem_alloc_max, mem_alloc)
            if self.mem_alloc_ref is None:
                self.mem_alloc_ref = mem_alloc

            memstr = 'Alloc diff: %5d, refdi: %5d' % (mem_alloc - self.mem_alloc_ref, mem_alloc - c_prev_alloc)

        if self.args.no_aug:
            self.print_line(line)
            return

        ldiff = self.max_line_len - len(line)
        self.print_line('%s%s |  AbsTime: %7.3f,   Diff %5.3f  | %s' % (line, ' '*ldiff, abs_time, diff_time, memstr))

        if '====' in line or '####' in line:
            abs_r = ''
            if self.serial_device:
                abs_time_r = ctime_r - self.time_ref_r
                abs_r = 'r: %7.2f, ticks p.s.: %7.3f' % (abs_time_r, (ctime - self.time_ref) / float(abs_time_r))
            self.print_line(' ++ TOTAL: %7.2f, %s mem max: %s' % (abs_time, abs_r, self.mem_alloc_max - self.mem_alloc_ref))

            self.time_ref = ctime
            self.time_ref_r = ctime_r
            if mem_alloc is not None:
                self.mem_alloc_ref = mem_alloc
                self.mem_alloc_max = mem_alloc

    def read_serial(self, device, brate):
        try:
            import serial  # pip install pyserial
        except ImportError:
            raise ValueError('pip install pyserial')

        while True:
            try:
                ser = serial.Serial(device, brate, timeout=.1)
                logger.info('Connected: %s' % ser)

                sio = io.TextIOWrapper(io.BufferedRWPair(ser, ser))
                while True:
                    line = sio.readline()
                    line = line.strip()
                    if len(line) == 0:
                        continue

                    self.process(line)

            except Exception as e:
                logger.warning('Exc: %s' % e)
                time.sleep(2)

    def read_files(self, files):
        for idx, line in enumerate(fileinput.input(files)):
            anz.process(line)

    def main(self):
        parser = argparse.ArgumentParser(description='Trezor log reader and parser')
        parser.add_argument('--serial', default=None,
                            help='Serial device to read from')
        parser.add_argument('--brate', type=int, default=115200,
                            help='Baud rate')
        parser.add_argument("--retry", dest="retry", default=True, action="store_const", const=True,
                            help="Retry reconnect")
        parser.add_argument("--norm-time", dest="norm_time", default=False, action="store_const", const=True,
                            help="Normalize time")
        parser.add_argument("--no-time", dest="no_time", default=False, action="store_const", const=True,
                            help="Do not show time")
        parser.add_argument("--no-aug", dest="no_aug", default=False, action="store_const", const=True,
                            help="Do not augment the log output")
        parser.add_argument("--tee", dest="tee", default=None,
                            help="File to copy raw output to")
        parser.add_argument("--tee-aux", dest="tee_aux", default=False, action="store_const", const=True,
                            help="Tee augmented lines")
        parser.add_argument('files', metavar='FILE', nargs='*',
                            help='files to read, if empty, stdin is used')
        args = parser.parse_args()

        self.args = args
        if args.tee:
            if os.path.exists(args.tee):
                raise ValueError('Tee file already exists')
            self.tee_file = open(args.tee, 'w+')

        try:
            if args.serial:
                self.serial_device = args.serial
                self.read_serial(args.serial, args.brate)
            else:
                self.read_files(args.files)

        except KeyboardInterrupt:
            logger.info('Terminating')

        if self.tee_file:
            self.tee_file.close()


if __name__ == '__main__':
    anz = LogAnalyzer()
    anz.main()
