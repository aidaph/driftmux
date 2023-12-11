from bs4 import BeautifulSoup
from nmapscan import NmapScan, Scanner
from wpscan import WPScan, WPScanner
from utils import Logger, COLOR, COLORED_COMBOS
import click
import pyfiglet
import requests
import subprocess
import os

def banner():
    ascii_banner = pyfiglet.figlet_format("AuditBBox")
    print("""{}{}{}""".format(COLOR.RED, ascii_banner, COLOR.RESET))

@click.command()
@click.option('--host_file', help="Server-defined file")
@click.option('--scripts', help="Nmap scripts")
@click.option('--port_range', help="Nmap scanned ports")
def main(host_file,
         scripts,
         port_range):

    banner()
    host_list = []
    with open(host_file) as file:
        for host in file:
            host_list.append(host)

    # Apply nmap scan to each host from the list
    for host in host_list:
        host = host.replace("\n", "").replace("'", "")
        logger = Logger(host=host)
        #banner(logger)

        # Apply qualys summary
        #logger.info("\n{} QUALYS summary".format(COLORED_COMBOS.INFO))

        logger.info("\n{} Start Nmap Scan for {}".format(COLORED_COMBOS.INFO, host))
        nmap_scan = NmapScan(host.replace("\n", ""), logger,
                             port_range=port_range)
        
        result = Scanner.runNmap(nmap_scan)
        #logger.info("Nmap Scanner Result {}".format(result))

        wp_scan = WPScan(host, logger)
        if wp_scan.checkWordpress(host, logger):
            result = WPScanner.runWpscan(wp_scan)
        logger.close()
    
    logger.info("\n{}### Ifca scan finished ###{}\n".format(COLOR.GREEN, COLOR.RESET))
    os.system("stty sane")


if __name__ == "__main__":
    main()
