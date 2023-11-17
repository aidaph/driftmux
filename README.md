# VulnScan: Vulnerability Scanner

Vulnscan is a package which uses nmap and wpscan as main tools
for finding vulnerability versions of a service. 

# Requirements

- nmap: `sudo apt install nmap`
- [Vulscan][def] is a module which enhances nmap to a vulnerability scanner: 

[def]: https://github.com/scipag/vulscan/tree/master

vulscan installation as `root``:

```
git clone https://github.com/scipag/vulscan vulscan
ln -s vulscan /usr/share/nmap/scripts/vulscan
cd /usr/share/nmap/scripts/vulscan
```

- Remove deprecated DBs and adapt `vulscan.nse` file:
```
rm securityfocus.csv openvas.csv securitytracker.csv
vim /usr/share/nmap/scripts/vulscan/vulscan.nse
```
```
 -- Add your own database, if you want to include it in the multi db mode
    db[1] = {name="VulDB",                  file="scipvuldb.csv",           url="https://vuldb.com",                        link="https://vuldb.com/id.{id}"}
    db[2] = {name="MITRE CVE",              file="cve.csv",                 url="https://cve.mitre.org",                    link="https://cve.mitre.org/cgi-bin/cvename.cgi?name={id}"}
    db[3] = {name="Exploit-DB",             file="exploitdb.csv",           url="https://www.exploit-db.com",               link="https://www.exploit-db.com/exploits/{id}"}

```

- Update de database for MITRE CVE. with this csv download and copy them into `/usr/share/nmap/scripts/vulscan`: https://cve.mitre.org/data/downloads/allitems.csv

- Install `wpscan`` package: 
```
sudo apt install ruby-dev
gem install wpscan
```

# Installation 

Use a virtualenv for the installation. This must be done by root to run `nmap` command without issues. 

```
root@x:~# source venv/bin/activate
root@x:~# python3 -m pip install -e .
```

# Usage

```
root@x:~# vulnscan  --host_file=serverList.txt --scripts=vulscan/vulscan.nse --port_range=1-10000
```