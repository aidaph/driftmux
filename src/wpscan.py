import subprocess
import re
#from raccoon_src.utils.help_utils import HelpUtilities
from itertools import islice
from utils import Logger, COLOR, COLORED_COMBOS

class WPScan:

    def __init__(self, host, logger):
        self.host = host 
        self.logger = logger

    def build_script(self):

        script = ["wpscan", "--url", self.host]
        return script

class WPScanner:

    @classmethod
    def runWpscan(cls, scan):
        scan.logger.info("Start the wpscan")
        script = scan.build_script()
        result = subprocess.run(script, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        #scan.logger.info("result {}".format(result))
        result, err = result.stdout.strip(), result.stderr.strip()
        result, err = result.decode().strip(), err.decode().strip()
        if result:
            cls.check_vuln(scan, result)



    @classmethod
    def check_vuln(cls, scan, result):
        count = 0
        for line in result.split("\n"):
            scan.logger.info("{}".format(line))
            if "Confidence" in line:
                conf = re.search(r'\d+', line)
                conf = int(conf.group())
                if conf < 75:
                    count += 1
                    scan.logger.info("\t The confidence {}{}{} is lower than required\n".format(COLOR.RED, conf, COLOR.RESET))
        
        scan.logger.info("\t{}The final items with a low confidence are {}{}\n".format(COLOR.GRAY, count, COLOR.RESET))