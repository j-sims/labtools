cmd=$@
# Populate hosts file
# manually ssh to each host and add ssh key
# update sudoers on each host
if [ ! -e "hosts" ]; then
  echo "Create hosts file"
  exit 1
fi

for host in `cat hosts`
do
echo :::: $host ::::
ssh $host $cmd
done