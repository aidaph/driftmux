import re
import requests
import subprocess
#from raccoon_src.utils.help_utils import HelpUtilities
from bs4 import BeautifulSoup
from itertools import islice
from utils import Logger, COLOR, COLORED_COMBOS

class WPScan:

    def __init__(self, host, logger):
        self.host = host 
        self.logger = logger

    def build_script(self):

        script = ["wpscan", "--url", self.host]
        return script

    def checkWordpress(self, host, logger):
        url = f'https://'+host
        try: 
            response = requests.get(url)
            if response.status_code == 200 or response.status_code == 503:
                soup = BeautifulSoup(response.content, 'html.parser')

                meta_tags = [m for m in soup.find_all('meta') if m.get('content') and 'WordPress' in m['content']]
                if meta_tags:
                    return True
                else:
                    logger.info("Check Wordpress skipped because it is not Wordpress")
                    return False

            return False
        except:
            logger.info("Check Wordpress skipped because the host is not a web")


class WPScanner:

    @classmethod
    def runWpscan(cls, scan):
        scan.logger.info("Start the wpscan")
        script = scan.build_script()
        result = subprocess.run(script, input='\n', text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        result, err = result.stdout.strip(), result.stderr.strip()
        #result, err = result.decode().strip(), err.decode().strip()
        if result:
            return cls.check_vuln(scan, result)
        else:
            return None

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
                    scan.logger.info("\t {}The confidence {} is lower than required {}\n".format(COLOR.RED, conf, COLOR.RESET))
        
        scan.logger.info("\tThe final items with a low confidence are {}{}{}\n".format(COLOR.RED, count, COLOR.RESET))