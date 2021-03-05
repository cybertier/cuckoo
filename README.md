# Cuckoo Sandbox Fork

This fork is for analyzing files with Cuckoo primarily on Ubuntu18.04 guests with Virtualbox5.2.
Tested on Ubuntu 20.04.

## Improvements of original cuckoo
This cuckoo forks main purpose is to allow the analysis of programms in docker-conatiners. It modifies the systemtap script and includes all programms running in containers into the analysis. It also writes down which Systemcall comes from which container (logs the id). Writing the container id into the log poptentially breaks other cuckoo features/analysis. The log with all syscalls is found in ~/.cuckoo/storage/analyses/X/logs/all.stap . Instead of the result.json created by cuckoo this forks creates an output in the STIX 2.0 format. The analysis result can be found in ~/.cuckoo/storage/analyses/X/stix-file.json . The file contains information about files written, processes created and network connections made.The fork also only logs syscalls that are processed by the STIX 2.0 reporting module. This drastically helps with performance. 

The fork also delivers a package called `buildwatch` it takes zips as input. The zip needs to include a `.buildwatch.sh` . The package unzips the zip and executes the shell script. Call `--package buildwatch` when submitting a file to use it.

## Difference in setup
The setup on differs slightly from the original setup.
On the host you have to install cuckoo with:
```shell
git clone https://github.com/axel1200/cuckoo.git cuckoo
cd cuckoo
python setup.py sdist
pip install .
```
instead of:
```shell
pip install cuckoo
```
On the guest install the systemtab script with:
```shell
wget https://raw.githubusercontent.com/axel1200/cuckoo/master/stuff/systemtap/strace.stp
stap -p4 -r $(uname -r) strace.stp -m stap_ -v -g
```
Notice that you just download the script from a different location and that you have to add the `-g` flag.

The Reporting Module "JSONDump" is disabled since it's been replace by the Stix2 Reporting Module.
If you want to reactivate it go to cuckoo/common/config.py 
