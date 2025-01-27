# APT2 install and requirements:
# The following steps will ensure the apt2 will run.
# It does not ensure that all of the tools are installed,
# just that all of the minimum requires for apt2 to run are satisfied.

apt-get update
apt-get upgrade
apt-get install git python3-pip
# git clone https://github.com/cqr-cryeye-forks/apt2.git
# cd apt2
# python3 setup.py install
# ./apt2.py -h

echo "At this point, run 'python apt2.py' and look for any line such as:"
echo "[!] Module ‘xxxxxxxx’ disabled. Dependency required: '['xxxxxxxx']'"
echo "and make sure you install and missing tools as needed"
