cd fabric-samples/test-network
./network.sh up createChannel -c mychannel -ca || echo "Channel already exists"
. scripts/envVar.sh 
setGlobals 1
# PATH=$PATH:$(pwd)/../bin FABRIC_CFG_PATH=$(pwd)/../config
./network.sh deployCC -ccn photovote -ccp ../../contracts/device-registration -ccl go -ccep "OR('Org1MSP.peer','Org2MSP.peer')"