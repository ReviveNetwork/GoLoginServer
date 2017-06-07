echo "Preparing Project Environment"
export GOPATH=$WORKSPACE/gopath
export GITHUBPATH=$GOPATH/src/github.com

echo "Cloning Project Dependencies"
git clone git@github.com:ReviveNetwork/GoRevive.git $GITHUBPATH/ReviveNetwork/GoRevive
go get .

make
