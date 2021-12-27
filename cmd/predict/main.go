package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	goruntime "runtime"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"gopkg.in/urfave/cli.v1"

	vm "predict_acl/predictvm"
	"predict_acl/predictvm/fakestate"
	"predict_acl/predictvm/runtime"
)

func NewApp(usage string) *cli.App {
	app := cli.NewApp()
	app.Name = filepath.Base(os.Args[0])
	app.Author = ""
	app.Email = ""
	app.Version = "0.1.1"
	app.Usage = usage
	return app
}

var (
	app = NewApp("the evm command line interface")

	MainnetFlag = cli.BoolFlag{
		Name:  "mainnet",
		Usage: "Execute against mainnet",
	}
	RpcFlag = cli.StringFlag{
		Name:  "rpc",
		Usage: "Remote Geth RPC url",
	}

	TxHashFlag = cli.StringFlag{
		Name:  "tx",
		Usage: "Transaction hash",
	}

	BlockNumFlag = cli.StringFlag{
		Name:  "block",
		Usage: "Block number",
	}

	CodeFlag = cli.StringFlag{
		Name:  "code",
		Usage: "EVM code",
	}
	CodeFileFlag = cli.StringFlag{
		Name:  "codefile",
		Usage: "File containing EVM code. If '-' is specified, code is read from stdin ",
	}
	PriceFlag = utils.BigFlag{
		Name:  "price",
		Usage: "price set for the evm",
		Value: new(big.Int),
	}
	ValueFlag = utils.BigFlag{
		Name:  "value",
		Usage: "value set for the evm",
		Value: new(big.Int),
	}
	InputFlag = cli.StringFlag{
		Name:  "input",
		Usage: "input for the EVM",
	}
	VerbosityFlag = cli.IntFlag{
		Name:  "verbosity",
		Usage: "sets the verbosity level",
	}
	BenchFlag = cli.BoolFlag{
		Name:  "bench",
		Usage: "benchmark the execution",
	}
	CreateFlag = cli.BoolFlag{
		Name:  "create",
		Usage: "indicates the action should be create rather than call",
	}
	SenderFlag = cli.StringFlag{
		Name:  "sender",
		Usage: "The transaction origin",
	}
	ReceiverFlag = cli.StringFlag{
		Name:  "receiver",
		Usage: "The transaction receiver (execution context)",
	}

	OriginCommandHelpTemplate = `{{.Name}}{{if .Subcommands}} command{{end}}{{if .Flags}} [command options]{{end}} {{.ArgsUsage}}
{{if .Description}}{{.Description}}
{{end}}{{if .Subcommands}}
SUBCOMMANDS:
  {{range .Subcommands}}{{.Name}}{{with .ShortName}}, {{.}}{{end}}{{ "\t" }}{{.Usage}}
  {{end}}{{end}}{{if .Flags}}
OPTIONS:
{{range $.Flags}}   {{.}}
{{end}}
{{end}}`
)

var runCommand = cli.Command{
	Action:      runCmd,
	Name:        "run",
	Usage:       "run arbitrary evm binary",
	ArgsUsage:   "<code>",
	Description: `The run command runs arbitrary EVM code.`,
}

type execStats struct {
	time           time.Duration // The execution time.
	allocs         int64         // The number of heap allocations during execution.
	bytesAllocated int64         // The cumulative number of bytes allocated during execution.
}

func timedExec(bench bool, execFunc func() ([]byte, uint64, error)) (output []byte, gasLeft uint64, stats execStats, err error) {
	if bench {
		result := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				output, gasLeft, err = execFunc()
			}
		})

		// Get the average execution time from the benchmarking result.
		// There are other useful stats here that could be reported.
		stats.time = time.Duration(result.NsPerOp())
		stats.allocs = result.AllocsPerOp()
		stats.bytesAllocated = result.AllocedBytesPerOp()
	} else {
		var memStatsBefore, memStatsAfter goruntime.MemStats
		goruntime.ReadMemStats(&memStatsBefore)
		startTime := time.Now()
		output, gasLeft, err = execFunc()
		stats.time = time.Since(startTime)
		goruntime.ReadMemStats(&memStatsAfter)
		stats.allocs = int64(memStatsAfter.Mallocs - memStatsBefore.Mallocs)
		stats.bytesAllocated = int64(memStatsAfter.TotalAlloc - memStatsBefore.TotalAlloc)
	}

	return output, gasLeft, stats, err
}

func runCmd(ctx *cli.Context) error {
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	glogger.Verbosity(log.Lvl(ctx.GlobalInt(VerbosityFlag.Name)))
	log.Root().SetHandler(glogger)

	var (
		tracer        vm.Tracer
		statedb       *fakestate.FakeStateDB
		sender        = common.BytesToAddress([]byte("sender"))
		receiver      = common.BytesToAddress([]byte("receiver"))
		genesisConfig *core.Genesis
	)

	if ctx.GlobalString(RpcFlag.Name) != "" {
		return runCmdWithFetcher(ctx, ctx.GlobalString(RpcFlag.Name))
	}

	statedb = fakestate.NewStateDB()
	genesisConfig = new(core.Genesis)

	if ctx.GlobalString(SenderFlag.Name) != "" {
		sender = common.HexToAddress(ctx.GlobalString(SenderFlag.Name))
	}
	statedb.CreateAccount(sender)

	if ctx.GlobalString(ReceiverFlag.Name) != "" {
		receiver = common.HexToAddress(ctx.GlobalString(ReceiverFlag.Name))
	}

	tracer = vm.NewAccessListTracer(nil, &sender, &receiver, vm.PrecompiledAddressesBerlin)
	runtimeConfig := runtime.Config{
		Origin:      sender,
		State:       statedb,
		GasLimit:    uint64(10000000000),
		GasPrice:    utils.GlobalBig(ctx, PriceFlag.Name),
		Value:       utils.GlobalBig(ctx, ValueFlag.Name),
		Difficulty:  new(big.Int),
		Time:        new(big.Int).SetInt64(time.Now().Unix()),
		Coinbase:    genesisConfig.Coinbase,
		BlockNumber: new(big.Int).SetUint64(genesisConfig.Number),
		EVMConfig: vm.Config{
			Tracer: tracer,
			Debug:  true,
		},
	}

	if ctx.GlobalBool(MainnetFlag.Name) {
		runtimeConfig.ChainConfig = params.MainnetChainConfig
	} else {
		runtimeConfig.ChainConfig = params.AllEthashProtocolChanges
	}

	hexInput := []byte(ctx.GlobalString(InputFlag.Name))
	input := common.FromHex(string(bytes.TrimSpace(hexInput)))
	code := parseCode(ctx)

	return runTx(ctx, &runtimeConfig, &receiver, code, input)
}

func createAddress(hex string) *common.Address {
	address := new(common.Address)
	address.SetBytes(common.FromHex(hex))
	return address
}

func runCmdWithFetcher(ctx *cli.Context, rpc string) error {
	rpcCtx := context.Background()
	rpcClient, err := fakestate.DialContext(rpcCtx, rpc)
	if err != nil {
		return err
	}
	defer rpcClient.Close()

	var (
		parentBlockNum *big.Int
		blockNum       *big.Int
		tx             *fakestate.RpcTransaction
		pending        = true

		sender   *common.Address
		receiver *common.Address
		value    *big.Int
		input    []byte
		code     []byte
		price    *big.Int
	)

	txHash := ctx.GlobalString(TxHashFlag.Name)
	if len(txHash) > 0 {
		// if txHash is specified, retrieve tx parameters from remote Geth node,
		// arguments such as sender, receiver, value, input and code will be ignored
		tx, pending, err = rpcClient.GetTransactionByHash(rpcCtx, common.HexToHash(txHash))
		if err != nil {
			return err
		}
		if !pending {
			// history tx
			blockNum, _ = new(big.Int).SetString(*tx.BlockNumber, 0)
			parentBlockNum = blockNum.Sub(blockNum, big.NewInt(1))
		}

		sender = tx.From
		receiver = tx.Tx.To()
		value = tx.Tx.Value()
		input = tx.Tx.Data()
		price = tx.Tx.GasPrice()
	} else {
		// parse tx parameters from arguments
		if ctx.GlobalString(SenderFlag.Name) != "" {
			sender = new(common.Address)
			sender.SetBytes(common.FromHex(ctx.GlobalString(SenderFlag.Name)))
		}
		if ctx.GlobalString(ReceiverFlag.Name) != "" {
			receiver = new(common.Address)
			receiver.SetBytes(common.FromHex(ctx.GlobalString(ReceiverFlag.Name)))
		}

		hexInput := []byte(ctx.GlobalString(InputFlag.Name))
		input = common.FromHex(string(bytes.TrimSpace(hexInput)))
		value = utils.GlobalBig(ctx, ValueFlag.Name)

		code = parseCode(ctx)
		price = utils.GlobalBig(ctx, PriceFlag.Name)
	}

	// Get current block header to generate runtime config
	// If tx is not specified, get the latest block header, else:
	// for a pending tx, get the latest block header
	// for a history tx, get the block header in which the tx is included
	header, err := rpcClient.GetBlockHeader(rpcCtx, blockNum)
	if err != nil {
		return err
	}

	txTime := int64(header.Time)
	txBlockNum := header.Number
	if pending {
		txTime = time.Now().Unix()
		txBlockNum = big.NewInt(txBlockNum.Int64() + 1)

		parentBlockNum = header.Number
	}

	stateDB := fakestate.NewStateDB()
	fetcher := fakestate.NewStateFetcher(stateDB, rpc, 6)
	defer fetcher.Close()

	// Load sender and receiver states from remote Geth server
	if sender != nil || receiver != nil {
		var accounts = [2]*common.Address{sender, receiver}
		var keys [2]*common.Hash
		start, end := 0, 2
		if sender == nil {
			start++
		}
		if receiver == nil {
			end--
		}
		if end > start {
			fetcher.Fetch(accounts[start:end], keys[start:end], parentBlockNum)
		}
	}

	if sender == nil {
		sender = createAddress("sender")
		stateDB.CreateAccount(*sender)
	}
	// receiver should be nil if tx is a contract creation tx
	if tx == nil && receiver == nil {
		receiver = createAddress("receiver")
	}

	if code == nil && receiver != nil {
		code = stateDB.GetCode(*receiver)
	}

	// Load recent 256 block hashes
	hashmap, err := rpcClient.GetRecentBlockHashes(rpcCtx, parentBlockNum, 256)
	bhCache := fakestate.NewBlockHashCache(hashmap)

	// Set runtime config
	runtimeConfig := runtime.Config{
		ChainConfig: params.MainnetChainConfig,
		Origin:      *sender,
		GasLimit:    header.GasLimit,
		GasPrice:    price,
		Value:       value,
		Difficulty:  header.Difficulty,
		Time:        big.NewInt(txTime),
		Coinbase:    header.Coinbase,
		BlockNumber: txBlockNum,

		EVMConfig: vm.Config{
			Tracer: vm.NewAccessListTracer(nil, sender, receiver, vm.PrecompiledAddressesBerlin),
			Debug:  true,
		},
		BaseFee: header.BaseFee,

		State:     stateDB.Copy(),
		GetHashFn: bhCache.GetHashFn,
		Fetcher:   fetcher,
	}
	return runTx(ctx, &runtimeConfig, receiver, code, input)
}

func parseCode(ctx *cli.Context) []byte {

	codeFileFlag := ctx.GlobalString(CodeFileFlag.Name)
	codeFlag := ctx.GlobalString(CodeFlag.Name)

	// The '--code' or '--codefile' flag overrides code in state
	if codeFileFlag != "" || codeFlag != "" {
		var hexcode []byte
		if codeFileFlag != "" {
			var err error
			// If - is specified, it means that code comes from stdin
			if codeFileFlag == "-" {
				//Try reading from stdin
				if hexcode, err = ioutil.ReadAll(os.Stdin); err != nil {
					fmt.Printf("Could not load code from stdin: %v\n", err)
					os.Exit(1)
				}
			} else {
				// Codefile with hex assembly
				if hexcode, err = ioutil.ReadFile(codeFileFlag); err != nil {
					fmt.Printf("Could not load code from file: %v\n", err)
					os.Exit(1)
				}
			}
		} else {
			hexcode = []byte(codeFlag)
		}
		hexcode = bytes.TrimSpace(hexcode)
		if len(hexcode)%2 != 0 {
			fmt.Printf("Invalid input length for hex data (%d)\n", len(hexcode))
			os.Exit(1)
		}
		return common.FromHex(string(hexcode))
	}
	return nil
}

func runTx(ctx *cli.Context, runtimeConfig *runtime.Config, receiver *common.Address, code []byte, input []byte) error {
	var execFunc func() ([]byte, uint64, error)
	if receiver == nil || ctx.GlobalBool(CreateFlag.Name) {
		input = append(code, input...)
		execFunc = func() ([]byte, uint64, error) {
			output, _, gasLeft, err := runtime.Create(input, runtimeConfig)
			return output, gasLeft, err
		}
	} else {
		if len(code) > 0 {
			runtimeConfig.State.SetCode(*receiver, code)
		}
		execFunc = func() ([]byte, uint64, error) {
			return runtime.Call(*receiver, input, runtimeConfig)
		}
	}

	bench := ctx.GlobalBool(BenchFlag.Name)
	output, _, stats, err := timedExec(bench, execFunc)

	if bench {
		fmt.Fprintf(os.Stderr, "execution time: %v\n allocations: %d\n allocated bytes: %d",
			stats.time, stats.allocs, stats.bytesAllocated)
	}

	if alTracer, ok := runtimeConfig.EVMConfig.Tracer.(*vm.AccessListTracer); ok {
		fmt.Printf("0x%x\n", output)
		if err != nil {
			fmt.Printf(" error: %v\n", err)
		}
		fmt.Printf("----- Access List -----\n")
		al := alTracer.AccessList()
		for _, tuple := range al {
			fmt.Printf("%v\n", tuple.Address)
			for _, slot := range tuple.StorageKeys {
				fmt.Printf("\t%v\n", slot.Hex())
			}
		}

	}
	return nil
}

func init() {
	app.Flags = []cli.Flag{
		RpcFlag,
		BlockNumFlag,
		TxHashFlag,
		BenchFlag,
		CreateFlag,
		VerbosityFlag,
		CodeFlag,
		CodeFileFlag,
		PriceFlag,
		ValueFlag,
		InputFlag,
		SenderFlag,
		ReceiverFlag,
	}

	app.Commands = []cli.Command{
		runCommand,
	}
	cli.CommandHelpTemplate = OriginCommandHelpTemplate
}

func main() {
	if err := app.Run(os.Args); err != nil {
		code := 1
		fmt.Fprintln(os.Stderr, err)
		os.Exit(code)
	}
}
