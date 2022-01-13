# predict_al
Prototype to predict Ethereum transactions' access lists. The project comes from [CDAP cohort-one](https://github.com/ethereum-cdap/cohort-one/issues/26).

The current design is to use a simplified EVM to execute transaction payloads, and record the access list at the same time. 
Most of the source code is based on [go-ethereum](https://github.com/ethereum/go-ethereum.git).


## Building

The source code is developed and tested with Go SDK 1.17.1. 

```shell
$ git clone https://github.com/alexchenzl/predict_al.git

$ cd predict_al

$ go build ./cmd/predict
```

## Running

```shell
# Check command help
$ ./predict --help 

# Provide RPC to fetch ethereum states on demand as it is needed, the tool will fetch ChainID to initialize the chain config 
$ ./predict --rpc  http://localhost:8545

# Re-execute a transaction from history referenced by it's hash
$ ./predict --rpc  http://localhost:8545 --tx hash

# Execute a new "transaction" with manually specified fields for sender/receiver/value/input data
$ ./predict --rpc  http://localhost:8545 --sender from --receiver to --input data

# Raw execute some code
$ ./predict --code 60f15400 --sender from --receiver to 

# display every step of transaction execution, stack, storage, memory and return data can be enabled or disabled
$ ./predict --code 60f15400 --debug --nostack=false --nostorage=false --nomemory=true

```

