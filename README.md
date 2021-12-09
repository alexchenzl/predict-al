# predict_al
Prototype to predict Ethereum transactions' access lists. The project comes from [CDAP cohort-one](https://github.com/ethereum-cdap/cohort-one/issues/26).

The current design is to use a simplified EVM to execute transaction payloads, and record the access list at the same time. 
Most of the source code is based on [go-ethereum](https://github.com/ethereum/go-ethereum.git).

Now it can only run against very simple bytecodes.

TODO:
* Implement a state fetcher that fetches states from remote Geth nodes.
* Run the engine repeatedly to predict more accesses after it retrieves states that predicted in last round
* Make this engine run against massive history transactions to check whether it works well in real world
* Refactor and optimize the implementation
* Benchmark testing
* ...



## Building

The source code is developed and tested with Go SDK 1.17.1. 

```shell
$ git clone https://github.com/alexchenzl/predict_al.git

$ cd predict_al

$ go build ./cmd/predict
```

## Running

```shell
$ ./predict --help 

$ ./predict --code 60f15400 run
```

