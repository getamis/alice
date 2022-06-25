nohup ./example  dkg --config ./dkg/id-10001-input.yaml >logs/dkg.1.log 2>&1 &
sleep 2
nohup ./example  dkg --config ./dkg/id-10002-input.yaml >logs/dkg.2.log 2>&1 &
sleep 2
nohup ./example  dkg --config ./dkg/id-10003-input.yaml >logs/dkg.3.log 2>&1 &
sleep 3

cd signer
./updateInput.sh
