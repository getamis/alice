num=$1
echo $num
rm -rf logs/*.log

for i in $(seq 1 $num)
do
killall -9 example
nohup ./example  signer --config ./signer/id-10001-ed-input.yaml >>logs/signer.1.log 2>&1 &
sleep 1
nohup ./example  signer --config ./signer/id-10002-ed-input.yaml >>logs/signer.2.log 2>&1 &
sleep 1
nohup ./example  signer --config ./signer/id-10003-ed-input.yaml >>logs/signer.3.log 2>&1 &
sleep 3
cd logs
./count.sh
cd -
done

