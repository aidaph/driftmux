#@credits to https://github.com/evyatarmeged
import subprocess
import re
#from raccoon_src.utils.help_utils import HelpUtilities
from itertools import islice
from utils import Logger, COLOR, COLORED_COMBOS

class NmapScan:

    def __init__(self, host, logger, port_range=None):
        self.host = host 
        self.port_range = port_range
        self.scripts = "vulscan/vulscan.nse"
        self.logger = logger

    def build_script(self):

        script = ["nmap", "--script", self.scripts, "-sV", self.host]

        if self.port_range:
            script.append("-p")
            script.append(self.port_range)
            self.logger.info("Port range added {} to Nmap script".format(self.port_range))
        return script

class Scanner:

    @classmethod
    def runNmap(cls, scan):
        scan.logger.info("Start the IFCA scan")
        script = scan.build_script()
        result = subprocess.run(script, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        #scan.logger.info("result {}".format(result))
        result, err = result.stdout.strip(), result.stderr.strip()
        result, err = result.decode().strip(), err.decode().strip()
        if result:
            parsed_result = cls._parse_scan_output(scan, result)
        return parsed_result

    @classmethod
    def _parse_scan_output(cls, scan, result):
        parsed_output = ""
        port_line = ""
        vulncheck = False
        count = 0
        for line in result.split("\n"):
            if "PORT" in line and "STATE" in line:
                parsed_output += "{} Nmap discovered the following ports:\n".format(COLORED_COMBOS.GOOD)
            elif "/tcp" in line or "/udp" in line and "open" in line:
                vulncheck = False
                port_line = line
                scan.logger.info("\t{}{}{}{}\n".format(COLOR.GREEN, line[0], COLOR.RESET, "".join(line[1:])))
            elif "VulDB" in line:
                vulncheck = True
                scan.logger.info("\t{}{}{}{}\n".format(COLOR.GREEN, line[0], COLOR.RESET, "".join(line)))
            elif "MITRE" in line or "Exploit-DB" in line:
                scan.logger.info("\t{}{}{}{}\n".format(COLOR.GREEN, line[0], COLOR.RESET, "".join(line)))
            elif vulncheck == True and port_line:
                resultcheck = cls.check_vuln(scan,port_line, line)
                if resultcheck == True:
                    count +=1
        scan.logger.info("\t Hay {}{} vulnerabilidades ".format(COLOR.RED, count))
        return parsed_output
    
    @classmethod
    def check_vuln(cls, scan, port_line, db_line):
        
        vulnchecked = False
        port_line = port_line.split()
        service = port_line[3].lower()
        special_characters = "=<>x"
        db_line = db_line.lower()
        ## CHECK (how-to fix): in Nextcloud 443 port, the version is empty
        ## The version is the same than port 80
        sversion = [i for i in port_line if cls.has_float_ver(i)]
        
        if service == "haproxy":
            service = "haproxy http"
        if service in db_line.split(" ")[1:] and sversion:
            idx = db_line.split(" ").index(service)
            if service == "apache" and ("http" in db_line or cls.has_float(db_line)) \
                                and (any(c in special_characters for c in db_line.split(" ")[idx+1]) \
                                        or (cls.has_float(db_line.split(" ")[idx+1])) \
                                        or ("http" in db_line.split(" ")[idx+1])):
                vulnchecked = cls.checkVersion(scan, service, db_line, sversion[0])
            elif service == "http" and not "ibm http server" in db_line \
                and not "http authentication" in db_line:
                vulnchecked = cls.checkVersion(scan, service, db_line, sversion[0])
            elif not sversion:
                scan.logger.info("No version to be checked")
            else:
                pass
                #scan.logger.info("2 Service {}, Version {}, line_versions {}, DB LINE {}".format(
                #    service, sversion[0], cls.get_version(db_line), db_line))
        return vulnchecked        

    @classmethod
    def has_float_ver(cls, inputString):
        return bool(re.search(r'\d+\.\d+', inputString))

    @classmethod
    def has_float(cls, inputString):
        return bool(re.search(r'\d+\.\d+\.\d+', inputString))

    @classmethod
    def get_version(cls, inputString):
        p = re.compile(r'\d+\.\d+\.\d+')
        return p.findall(inputString)

    @classmethod
    def through_version(cls, inputString):
        pat = r'(\d+\.\d+\.\d+) through (\d+\.\d+\.\d+)'
        result = None
        result = re.search(pat , inputString)
        if result:
            result = [result.group(1), result.group(2)]
        return result

    @classmethod
    def checkVersion(cls, scan, service, db_line, sversion):
        vulnchecked = False
        if ("<" in db_line or "prior" in db_line or "before" in db_line) \
            and any(sversion < ver for ver in cls.get_version(db_line)):
            scan.logger.info("1 Service {}, Version {}, line_versions {}, DB LINE {}".format(
                    service, sversion, cls.get_version(db_line), db_line))
            vulnchecked = True
        elif "through" in db_line:
            tversions = cls.through_version(db_line)
            if not tversions:
                vulnchecked = False
                pass
            if sversion >= tversions[0] and sversion <= tversions[1]: 
                scan.logger.info("1 Service {}, Version {}, line_versions {}, DB LINE {}".format(
                        service, sversion, cls.get_version(db_line), db_line))
            vulnchecked  = True
        elif any(sversion == ver for ver in cls.get_version(db_line)):
            scan.logger.info("1 Service {}, Version {}, line_versions {}, DB LINE {}".format(
                    service, sversion, cls.get_version(db_line), db_line))
            vulnchecked  = True
        else: 
            pass
        
        return vulnchecked


