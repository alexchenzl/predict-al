# predict_al
Prototype to predict Ethereum transactions' access lists. The project comes from [CDAP cohort-one](https://github.com/ethereum-cdap/cohort-one/issues/26).

Applying methodology like [taint checking](https://en.wikipedia.org/wiki/Taint_checking), the prototype, when tested with about one million historical transactions on 
Ethereum Mainnet, achieves an average improvement of 2.448x on reducing the number of iterations to retrieve state from the network.

[This post](https://hackmd.io/5i1rtSrrTZWEQLxN7ePt4w) explains how this tool works and how it has been tested in detail.


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

# Execute a new "transaction" with manually specified fields for from/to/value/data
$ ./predict --rpc  http://localhost:8545 --from sender --to receiver  --data data

# Raw execute some code
$ ./predict --code 60f15400 --from sender --to receiver 

# display every step of transaction execution, stack, storage, memory and return data can be enabled or disabled
$ ./predict --code 60f15400 --debug --nostack=false --nostorage=false --nomemory=true

```

