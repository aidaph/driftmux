from nmapscan import NmapScan, Scanner
from wpscan import WPScan, WPScanner
from utils import Logger, COLOR, COLORED_COMBOS
import click
import subprocess
import os

def banner(logger):
    logger.info("""{}

 --------    --------    --------    -----------            ----           ----    ---      ---    ---           ---      ---
|        |  |        |  |        |  |           |           \   \         /   /   |   |    |   |  |   |         |   \    |   |
 --    --   |   -----   |   -----   |    ---    |            \   \       /   /    |   |    |   |  |   |         |    \   |   |
   |  |     |   |       |   |       |   |   |   |             \   \     /   /     |   |    |   |  |   |         |     \  |   |
   |  |     |   ---     |   |       |    ---    |              \   \   /   /      |   |    |   |  |   |         |      \ |   |
   |  |     |      |    |   |       |           |               \   \ /   /       |   |    |   |  |   |         |       \    |
   |  |     |   ---     |   |       |    ---    |                \       /        |   |    |   |  |   |         |   | \      |
 --    --   |   |       |   -----   |   |   |   |                 \     /         |   -----    |  |   -------   |   |  \     |
|        |  |   |       |        |  |   |   |   |                  \   /          |            |  |          |  |   |   \    |
 --------    ---         --------    ---     ---                    ---            ------------    ----------    ---     ----                                         


         ---------    --------    -----------    ---      ---    ---      ---    --------    --------
        |         |  |        |  |           |  |   \    |   |  |   \    |   |  |        |  |        |
        |   ------   |   -----   |    ---    |  |    \   |   |  |    \   |   |  |   -----   |   --   |
        |   |        |   |       |   |   |   |  |     \  |   |  |     \  |   |  |   |       |  |  |  |
        |   ------   |   |       |   |   |   |  |      \ |   |  |      \ |   |  |    --     |   --   |
        |         |  |   |       |    ---    |  |       \    |  |       \    |  |      |    |      -- 
         ------   |  |   |       |           |  |   |\       |  |   |\       |  |    --     |  |\  \
               |  |  |   |       |    ---    |  |   | \      |  |   | \      |  |   |       |  | \  \
         ------   |  |   -----   |   |   |   |  |   |  \     |  |   |  \     |  |   -----   |  |  \  \
        |         |  |        |  |   |   |   |  |   |   \    |  |   |   \    |  |        |  |  |   \  \
         ---------    --------    ---     ---    ---     ----    ---     ----    --------    --     ---
    {}
    """.format(COLOR.GRAY, COLOR.RESET))

@click.command()
@click.option('--host_file', help="Server-defined file")
@click.option('--scripts', help="Nmap scripts")
@click.option('--port_range', help="Nmap scanned ports")
def main(host_file,
         scripts,
         port_range):

    logger = Logger()
    banner(logger)

    # Apply qualys summary
    #logger.info("\n{} QUALYS summary".format(COLORED_COMBOS.INFO))

    logger.info("\n{} Start Nmap scan".format(COLORED_COMBOS.INFO))

    host_list = []
    with open(host_file) as file:
        for host in file:
            host_list.append(host)

    # Apply nmap scan to each host from the list
    for host in host_list:
        logger.info("Start scan for {}".format(host))
        nmap_scan = NmapScan(host.replace("\n", ""), logger,
                             port_range=port_range)
        
        result = Scanner.runNmap(nmap_scan)
        logger.info("Scanner Result {}".format(result))

        if "wordpress" in host:
            wp_scan = WPScan(host, logger)
            WPScanner.runWpscan(wp_scan)
            #logger.info("WPSCanner result {}".format(result))

    logger.info("\n{}### Ifca scan finished ###{}\n".format(COLOR.GRAY, COLOR.RESET))
    os.system("stty sane")

if __name__ == "__main__":
    main()
