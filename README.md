
# PSQLi: Automated Tester For SQL Injection

## Installation

Install psqli with following steps:

```bash
$ git clone https://github.com/reewardius/psqli
$ cd psqli
$ pip install -r requirements.txt
$ python psqli.py -h

Usage: psqli.py [-h] [-l LIST] [-u URL] -p PAYLOADS [-v]

options:
  -h, --help            show this help message and exit
  -l LIST, --list LIST  To provide list of urls as an input
  -u URL, --url URL     To provide single url as an input
  -p PAYLOADS, --payloads PAYLOADS
                        To provide payload file having Blind SQL Payloads with delay of 30 sec
  -v, --verbose         Run on verbose mode
  -a, --approve         Pause and wait for approval if a vulnerability is found
```
### For Single URL:
```
$ python3 psqli.py -u http://testphp.vulnweb.com/listproducts.php?cat=1 -p payloads.txt -v
```
### For List of URLs:
```
$ python3 psqli.py -l urls.txt -p payloads.txt -v
```
![image](https://github.com/user-attachments/assets/e5cce679-855d-4ac7-8b45-a5000ac955e2)

### Output file with results

![image](https://github.com/user-attachments/assets/7550e646-1553-48f4-b1dd-c2bc8023d7cb)
