package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gopkg.in/urfave/cli.v1"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"

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
	app = NewApp("a tool to predict transaction data access list")

	RpcFlag = cli.StringFlag{
		Name:  "rpc",
		Usage: "Remote Geth HTTP RPC url",
	}
	OutFlag = cli.StringFlag{
		Name:  "out",
		Usage: "File to save prediction result",
	}
	CacheFileFlag = cli.StringFlag{
		Name:  "cachefile",
		Usage: "File containing contract addresses whose bytecodes need to be fetched as a cache",
	}
	CacheBlockFlag = cli.Int64Flag{
		Name:  "cacheblock",
		Usage: "Block height parameter for fetching the bytecodes to be cached",
		Value: 13585500,
	}
	TxHashFlag = cli.StringFlag{
		Name:  "tx",
		Usage: "Hash of the historic transaction to be executed",
	}
	BlockFlag = cli.Int64Flag{
		Name:  "block",
		Usage: "Height of the historic block within which all transactions contained will be executed. If tx is provided, block would be ignored",
		Value: -1,
	}
	BatchFlag = cli.IntFlag{
		Name:  "batch",
		Usage: "number of transactions that will be run concurrently in a batch, default is 32",
		Value: 32,
	}
	TimeoutFlag = cli.IntFlag{
		Name:  "timeout",
		Usage: "maximum seconds to run a transaction, default is 5",
		Value: 5,
	}
	CodeFlag = cli.StringFlag{
		Name:  "code",
		Usage: "Raw EVM code",
	}
	CodeFileFlag = cli.StringFlag{
		Name:  "codefile",
		Usage: "File containing EVM code. If '-' is specified, code is read from stdin ",
	}
	ValueFlag = utils.BigFlag{
		Name:  "value",
		Usage: "The transaction value",
		Value: new(big.Int),
	}
	DataFlag = cli.StringFlag{
		Name:  "data",
		Usage: "The transaction input data",
	}
	GasFlag = cli.Uint64Flag{
		Name:  "gas",
		Usage: "gas limit for the evm",
		Value: 10000000000,
	}
	PriceFlag = utils.BigFlag{
		Name:  "price",
		Usage: "price set for the evm",
		Value: big.NewInt(50_000_000_000),
	}
	VerbosityFlag = cli.IntFlag{
		Name:  "verbosity",
		Usage: "sets the verbosity level",
	}
	CreateFlag = cli.BoolFlag{
		Name:  "create",
		Usage: "indicates the action should be create rather than call",
	}
	FromFlag = cli.StringFlag{
		Name:  "from",
		Usage: "The transaction origin",
	}
	ToFlag = cli.StringFlag{
		Name:  "to",
		Usage: "The transaction receiver (To)",
	}
	MaxProcsFlag = cli.IntFlag{
		Name:  "mp",
		Usage: "Max number of concurrent requests in the state fetcher, 0 means it will be set according to logical CPUs",
		Value: 0,
	}
	MaxRoundsFlag = cli.IntFlag{
		Name:  "mr",
		Usage: "Max rounds to run, 0 means it will run until there's no new data access found",
		Value: 0,
	}
	DebugFlag = cli.BoolFlag{
		Name:  "debug",
		Usage: "Output full evm execution logs if this flag is set",
	}
	DisableMemoryFlag = cli.BoolTFlag{
		Name:  "nomemory",
		Usage: "disable memory output in full evm execution logs, default true",
	}
	DisableStackFlag = cli.BoolTFlag{
		Name:  "nostack",
		Usage: "disable stack output, default true",
	}
	DisableStorageFlag = cli.BoolTFlag{
		Name:  "nostorage",
		Usage: "disable storage output, default true",
	}
	DisableReturnDataFlag = cli.BoolTFlag{
		Name:  "noreturndata",
		Usage: "enable return data output, default true",
	}
	TestNetworkFlag = cli.BoolFlag{
		Name:  "testnetwork",
		Usage: "test RPC server access",
	}
	SummaryFlag = cli.BoolFlag{
		Name:  "summary",
		Usage: "Only output execution summary without information of every round if this flag is set",
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

func getChainConfig(chainID uint64) *params.ChainConfig {
	switch chainID {
	case 1:
		return params.MainnetChainConfig
	case 3:
		return params.RopstenChainConfig
	case 4:
		return params.RinkebyChainConfig
	case 5:
		return params.GoerliChainConfig
	default:
		return params.AllEthashProtocolChanges
	}
}

func newChainConfig(client *fakestate.RpcClient) *params.ChainConfig {
	chainId, err := client.ChainID(context.Background())
	if err != nil {
		return params.AllEthashProtocolChanges
	}
	return getChainConfig(chainId.Uint64())
}

func newRuntimeConfig(header *types.Header, chainConfig *params.ChainConfig, txTime, txBlockNum *big.Int) *runtime.Config {
	runtimeConfig := &runtime.Config{
		ChainConfig: chainConfig,
		Difficulty:  header.Difficulty,
		Time:        txTime,
		Coinbase:    header.Coinbase,
		BlockNumber: txBlockNum,
		BaseFee:     header.BaseFee,
	}
	return runtimeConfig
}

// Load recent last 256 block hashes
func newBlockHashCache(client *fakestate.RpcClient, blockNumber *big.Int) (*fakestate.BlockHashCache, error) {
	hashmap, err := client.GetRecentBlockHashes(context.Background(), blockNumber, 256)
	if err != nil {
		return nil, err
	}
	return fakestate.NewBlockHashCache(hashmap), nil
}

func newStateCache(client *fakestate.RpcClient, cacheFile string, blockNumber int64) *fakestate.StateCache {
	if cacheFile != "" {
		stateCache := fakestate.NewStateCache()
		count := stateCache.Initialize(client, cacheFile, big.NewInt(blockNumber))
		fmt.Printf("Initialize state cache with %v objects\n", count)
		return stateCache
	}
	return nil
}

type txPredictTask struct {
	tx    *types.Transaction
	index int
}

type TxPredictResult struct {
	H  string          `json:"h"`  // tx hash
	Tt int             `json:"tt"` // total touches
	Tr int             `json:"tr"` // total rounds
	Ta int             `json:"ta"` // total accounts
	Ts int             `json:"ts"` // total storage slots
	Rd []TxRoundRecord `json:"rd"` // records of every round
	Rb []int           `json:"rb"` // states to retrieve in every round
	E  string          `json:"e,omitempty"`
	St time.Duration   `json:"st"` // stats: execution time, in nanoseconds
	Sa int64           `json:"sa"` // stats: The number of heap allocations during execution
	Sb int64           `json:"sb"` // stats: The cumulative number of bytes allocated during execution.

}

type TxRoundRecord struct {
	A []common.Address `json:"a,omitempty"` // new addresses
	S types.AccessList `json:"s,omitempty"` // new storage slots
}

func runCmd(ctx *cli.Context) error {
	gLogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	gLogger.Verbosity(log.Lvl(ctx.GlobalInt(VerbosityFlag.Name)))
	log.Root().SetHandler(gLogger)

	var (
		err    error
		result *TxPredictResult
	)

	rpc := ctx.GlobalString(RpcFlag.Name)
	if rpc != "" {
		if ctx.GlobalBool(TestNetworkFlag.Name) {
			return fakestate.TestNetworkAccess(rpc)
		}

		txHash := ctx.GlobalString(TxHashFlag.Name)
		block := ctx.GlobalInt64(BlockFlag.Name)
		if txHash != "" {
			result, err = runHistoryTransaction(ctx, rpc, txHash)
		} else if block >= 0 {
			var results []*TxPredictResult
			results, err = runHistoryBlock(ctx, rpc, big.NewInt(block))
			if err == nil {
				filename := ctx.GlobalString(OutFlag.Name)
				if len(filename) > 0 {
					filename = fmt.Sprintf("%v-%d.json", ctx.GlobalString(OutFlag.Name), block)
				}
				outputResults(filename, results)
				return nil
			}
		} else {
			result, err = runNewTransaction(ctx, rpc)
		}
	} else {
		result, err = runRawCodeLocally(ctx)
	}

	if err == nil {
		results := make([]*TxPredictResult, 1)
		results[0] = result
		filename := ctx.GlobalString(OutFlag.Name)
		if len(filename) > 0 {
			filename = fmt.Sprintf("%v.json", ctx.GlobalString(OutFlag.Name))
		}
		outputResults(filename, results)
	} else {
		fmt.Printf("Exit with error: %v\n", err)
	}
	return err
}

// runRawCodeLocally  will not fetch states from remote nodes
func runRawCodeLocally(ctx *cli.Context) (*TxPredictResult, error) {
	var (
		from          = common.BytesToAddress([]byte("from"))
		to            = common.BytesToAddress([]byte("to"))
		genesisConfig = new(core.Genesis)
	)

	startTime := time.Now()
	statedb := fakestate.NewStateDB()

	if ctx.GlobalString(FromFlag.Name) != "" {
		from = common.HexToAddress(ctx.GlobalString(FromFlag.Name))
	}
	statedb.CreateAccount(from)
	if ctx.GlobalString(ToFlag.Name) != "" {
		to = common.HexToAddress(ctx.GlobalString(ToFlag.Name))
	}

	runtimeConfig := runtime.Config{
		ChainConfig: params.AllEthashProtocolChanges,
		Origin:      from,
		State:       statedb,
		GasLimit:    uint64(10000000000),
		GasPrice:    new(big.Int),
		Value:       utils.GlobalBig(ctx, ValueFlag.Name),
		Difficulty:  new(big.Int),
		Time:        new(big.Int).SetInt64(time.Now().Unix()),
		Coinbase:    genesisConfig.Coinbase,
		BlockNumber: new(big.Int).SetUint64(genesisConfig.Number),
	}

	hexInput := []byte(ctx.GlobalString(DataFlag.Name))
	input := common.FromHex(string(bytes.TrimSpace(hexInput)))
	code := parseCode(ctx)

	if code == nil {
		cli.ShowAppHelpAndExit(ctx, 1)
	}
	return runTx(ctx, &runtimeConfig, "", &from, &to, code, input, startTime)
}

// runHistoryTransaction execute historic transaction based on its parent block states
// If it's a pending transaction, use the latest block header to create runtime configuration
func runHistoryTransaction(ctx *cli.Context, rpc string, txHash string) (*TxPredictResult, error) {

	rpcCtx := context.Background()
	rpcClient, err := fakestate.DialContext(rpcCtx, rpc)
	if err != nil {
		return nil, err
	}
	defer rpcClient.Close()

	// If txHash is provided, execute the historic transaction, but it also may be a pending tx
	tx, pending, err := rpcClient.GetTransactionByHash(rpcCtx, common.HexToHash(txHash))
	if err != nil {
		return nil, err
	}

	var blockNum *big.Int
	if !pending {
		blockNum, _ = new(big.Int).SetString(*tx.BlockNumber, 0)
		if blockNum.Sign() == 0 {
			return nil, errors.New("genesis is not predictable")
		}
	}

	// Get current block header to generate runtime config
	// for a pending tx, get the latest block header
	// for a history tx, get the block header in which the tx is included
	header, err := rpcClient.GetBlockHeader(rpcCtx, blockNum)
	if err != nil {
		return nil, err
	}

	txTime := int64(header.Time)
	txBlockNum := header.Number
	parentBlockNum := header.Number
	if pending {
		txTime = time.Now().Unix()
		txBlockNum = big.NewInt(header.Number.Int64() + 1)
	} else {
		parentBlockNum = big.NewInt(header.Number.Int64() - 1)
	}

	// Load recent 256 block hashes
	//hashmap, err := rpcClient.GetRecentBlockHashes(rpcCtx, parentBlockNum, 256)
	//bhCache := fakestate.NewBlockHashCache(hashmap)
	bhCache, err := newBlockHashCache(rpcClient, parentBlockNum)
	if err != nil {
		return nil, err
	}
	stateCache := newStateCache(rpcClient, ctx.GlobalString(CacheFileFlag.Name), ctx.GlobalInt64(CacheBlockFlag.Name))

	chainConfig := newChainConfig(rpcClient)
	runtimeConfig := newRuntimeConfig(header, chainConfig, big.NewInt(txTime), txBlockNum)
	runtimeConfig.GetHashFn = bhCache.GetHashFn
	runtimeConfig.StateCache = stateCache

	hash := tx.Tx.Hash().Hex()
	result, err := runPredictTxTask(ctx, rpcClient, runtimeConfig, hash, tx.From, tx.Tx.To(), tx.Tx.Value(), tx.Tx.GasPrice(), tx.Tx.Gas(), tx.Tx.Data(), nil)
	if err == nil {
		result.H = hash
	}
	return result, err
}

// runNewTransaction execute a new transaction, runtime configuration is created from the latest block header
// if code is provided, the code in fetched state will be overridden. Sender must be provided.
func runNewTransaction(ctx *cli.Context, rpc string) (*TxPredictResult, error) {
	var (
		from *common.Address
		to   *common.Address
	)

	// from must be provided to run against a remote Geth node
	if ctx.GlobalString(FromFlag.Name) == "" {
		return nil, errors.New("to run a new transaction against a remote Geth node, from must be provided")
	}
	from = new(common.Address)
	from.SetBytes(common.FromHex(ctx.GlobalString(FromFlag.Name)))

	// if to is nil, this is a contract creation tx
	if ctx.GlobalString(ToFlag.Name) != "" {
		to = new(common.Address)
		to.SetBytes(common.FromHex(ctx.GlobalString(ToFlag.Name)))
	}

	rpcCtx := context.Background()
	rpcClient, err := fakestate.DialContext(rpcCtx, rpc)
	if err != nil {
		return nil, err
	}
	defer rpcClient.Close()

	// Get current block header to generate runtime runtimeConfig
	header, err := rpcClient.GetBlockHeader(rpcCtx, nil)
	if err != nil {
		return nil, err
	}
	txBlockNum := big.NewInt(header.Number.Int64() + 1)

	// Load recent 256 block hashes
	hashmap, err := rpcClient.GetRecentBlockHashes(rpcCtx, header.Number, 256)
	bhCache := fakestate.NewBlockHashCache(hashmap)

	chainConfig := newChainConfig(rpcClient)
	runtimeConfig := newRuntimeConfig(header, chainConfig, big.NewInt(time.Now().Unix()), txBlockNum)
	runtimeConfig.GetHashFn = bhCache.GetHashFn

	// provided code will override the fetched state
	code := parseCode(ctx)
	hexInput := []byte(ctx.GlobalString(DataFlag.Name))
	input := common.FromHex(string(bytes.TrimSpace(hexInput)))
	value := utils.GlobalBig(ctx, ValueFlag.Name)

	gasLimit := ctx.GlobalUint64(GasFlag.Name)
	price := utils.GlobalBig(ctx, PriceFlag.Name)
	return runPredictTxTask(ctx, rpcClient, runtimeConfig, "", from, to, value, price, gasLimit, input, code)
}

func runBatch(ctx *cli.Context, rpc string, chainConfig *params.ChainConfig, bhCache *fakestate.BlockHashCache, stateCache *fakestate.StateCache, block *types.Block, txs []*types.Transaction) ([]*TxPredictResult, error) {
	var (
		signer  = types.MakeSigner(chainConfig, block.Number())
		results = make([]*TxPredictResult, len(txs))
		pend    = new(sync.WaitGroup)
		jobs    = make(chan *txPredictTask, 8)
	)

	threads := goruntime.NumCPU()
	if threads > len(txs) {
		threads = len(txs)
	}
	for th := 0; th < threads; th++ {
		pend.Add(1)
		go func() {
			defer pend.Done()

			for task := range jobs {
				runtimeConfig := newRuntimeConfig(block.Header(), chainConfig, big.NewInt(int64(block.Time())), block.Number())
				runtimeConfig.GetHashFn = bhCache.GetHashFn
				runtimeConfig.StateCache = stateCache

				tx := task.tx
				msg, _ := tx.AsMessage(signer, block.BaseFee())
				from := msg.From()
				hash := tx.Hash().Hex()

				//fmt.Fprintf(os.Stdout, "task %v begin\n", hash)
				res, err := runPredictTxTask(ctx, nil, runtimeConfig, hash, &from, msg.To(), msg.Value(), msg.GasPrice(), msg.Gas(), msg.Data(), nil)
				if err != nil {
					results[task.index] = &TxPredictResult{H: hash, E: err.Error()}
					fmt.Fprintf(os.Stderr, "task error %v:%v: %v\n", block.Number().Int64(), hash, err)
				} else if res != nil {
					res.H = hash
					results[task.index] = res
					//fmt.Fprintf(os.Stdout, "task %v done\n", hash)
				}
			}
		}()
	}

	for i, tx := range txs {
		jobs <- &txPredictTask{tx: tx, index: i}
	}
	close(jobs)
	pend.Wait()
	return results, nil
}

// runHistoryBlock execute all transactions in this block concurrently based on its parent block states. Because this
// tool is not an archive node, it can not generate exact pre-states before executing any transaction in this block
// like running a tracer on an archive node.
func runHistoryBlock(ctx *cli.Context, rpc string, blockNum *big.Int) ([]*TxPredictResult, error) {

	if blockNum != nil && blockNum.Sign() == 0 {
		return nil, errors.New("genesis is not predictable")
	}

	rpcCtx := context.Background()
	rpcClient, err := fakestate.DialContext(rpcCtx, rpc)
	if err != nil {
		return nil, err
	}
	defer rpcClient.Close()

	block, err := rpcClient.GetBlock(rpcCtx, blockNum)
	if err != nil {
		return nil, err
	}

	txs := block.Transactions()
	txNum := len(txs)
	if txNum == 0 {
		return nil, nil
	}

	chainConfig := newChainConfig(rpcClient)
	bhCache, err := newBlockHashCache(rpcClient, big.NewInt(block.Number().Int64()-1))
	if err != nil {
		return nil, err
	}
	stateCache := newStateCache(rpcClient, ctx.GlobalString(CacheFileFlag.Name), ctx.GlobalInt64(CacheBlockFlag.Name))

	// Execute all the transaction contained within the block concurrently
	results := make([]*TxPredictResult, 0, txNum)

	batch := ctx.GlobalInt(BatchFlag.Name)
	batchNum := txNum / batch

	pos := 0
	i := 0
	for ; i < batchNum; i++ {
		fmt.Fprintf(os.Stdout, "%v Block %v batch %d\n", time.Now().Format("2006-01-02 15:04:05"), block.Number().Int64(), i)
		pos = batch * i
		batchResult, _ := runBatch(ctx, rpc, chainConfig, bhCache, stateCache, block, txs[pos:pos+batch])
		results = append(results, batchResult...)
	}
	pos = batch * batchNum
	if pos < txNum {
		fmt.Fprintf(os.Stdout, "%v Block %v batch %d\n", time.Now().Format("2006-01-02 15:04:05"), block.Number().Int64(), i)
		batchResult, _ := runBatch(ctx, rpc, chainConfig, bhCache, stateCache, block, txs[pos:])
		results = append(results, batchResult...)
	}
	return results, err
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

func runPredictTxTask(ctx *cli.Context, rpcClient *fakestate.RpcClient, runtimeConfig *runtime.Config, hash string, from, to *common.Address, value, gasPrice *big.Int, gasLimit uint64, data, code []byte) (*TxPredictResult, error) {
	startTime := time.Now()
	if rpcClient == nil {
		var err error
		rpcClient, err = fakestate.DialContext(context.Background(), ctx.GlobalString(RpcFlag.Name))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error occured in runBatch %d: %v", runtimeConfig.BlockNumber.Int64(), err.Error())
			return nil, err
		}
		defer rpcClient.Close()
	}
	stateDB := fakestate.NewStateDB()
	if runtimeConfig.StateCache != nil {
		stateDB.SetCache(runtimeConfig.StateCache)
	}
	// states need to be fetched from parent block
	fetcher := fakestate.NewStateFetcher(stateDB, rpcClient, big.NewInt(runtimeConfig.BlockNumber.Int64()-1))

	// fetch initial states from and to accounts
	fetcher.FetchFromAndTo(from, to)
	if to != nil && code == nil {
		code = stateDB.GetCode(*to)
	}

	runtimeConfig.Fetcher = fetcher
	runtimeConfig.State = fetcher.CopyStatedb()

	runtimeConfig.GasLimit = gasLimit
	runtimeConfig.Origin = *from
	runtimeConfig.GasPrice = gasPrice
	runtimeConfig.Value = value
	return runTx(ctx, runtimeConfig, hash, from, to, code, data, startTime)
}

func runTx(ctx *cli.Context, runtimeConfig *runtime.Config, hash string, sender *common.Address, receiver *common.Address, code []byte, data []byte, startTime time.Time) (*TxPredictResult, error) {

	var txResult *TxPredictResult
	var memStatsBefore goruntime.MemStats
	goruntime.ReadMemStats(&memStatsBefore)

	defer func() {
		if txResult != nil {
			var memStatsAfter goruntime.MemStats
			goruntime.ReadMemStats(&memStatsAfter)
			txResult.St = time.Since(startTime)
			txResult.Sa = int64(memStatsAfter.Mallocs - memStatsBefore.Mallocs)
			txResult.Sb = int64(memStatsAfter.TotalAlloc - memStatsBefore.TotalAlloc)
		}
	}()

	logConfig := &vm.LogConfig{
		EnableMemory:     !ctx.GlobalBoolT(DisableMemoryFlag.Name),
		DisableStack:     ctx.GlobalBoolT(DisableStackFlag.Name),
		DisableStorage:   ctx.GlobalBoolT(DisableStorageFlag.Name),
		EnableReturnData: !ctx.GlobalBoolT(DisableReturnDataFlag.Name),
		Debug:            ctx.GlobalBool(DebugFlag.Name),
	}
	tracer := vm.NewAccessListTracer(nil, sender, receiver, vm.PrecompiledAddressesBerlin, logConfig)
	runtimeConfig.EVMConfig = vm.Config{
		Tracer: tracer,
		// always true because we use tracer to record access list
		Debug: true,
	}

	txResult = &TxPredictResult{
		Rd: make([]TxRoundRecord, 1, 2),
		Rb: make([]int, 1, 2),
	}
	// Initial state accesses
	txResult.Rd[0] = TxRoundRecord{
		A: tracer.GetKnownAccounts(),
	}
	txResult.Rb[0] = len(txResult.Rd[0].A)

	txResult.Ta = len(txResult.Rd[0].A)

	creating := false
	if (receiver == nil || ctx.GlobalBool(CreateFlag.Name)) && data != nil {
		data = append(code, data...)
		creating = true
	} else if len(code) > 0 {
		runtimeConfig.State.SetCode(*receiver, code)
	} else {
		// simple transfer
		return txResult, nil
	}

	// Handle timeouts
	timeout := time.Duration(ctx.GlobalInt(TimeoutFlag.Name)) * time.Second
	deadlineCtx, cancel := context.WithTimeout(context.Background(), timeout)
	go func() {
		<-deadlineCtx.Done()
		if deadlineCtx.Err() == context.DeadlineExceeded {
			tracer.Stop(errors.New("execution timeout " + hash))
			fmt.Fprintf(os.Stderr, "execution timeout %v\n", hash)
		}
	}()
	defer cancel()

	mr := ctx.GlobalInt(MaxRoundsFlag.Name)
	for {
		tracer.LogRound()

		if creating {
			runtime.Create(data, runtimeConfig)
		} else {
			runtime.Call(*receiver, data, runtimeConfig)
		}
		tracer.Round++

		roundResult := TxRoundRecord{
			A: tracer.GetNewAccounts(),
			S: tracer.GetNewStorageSlots(),
		}
		accountNum := len(roundResult.A)
		slotNum := roundResult.S.StorageKeys()

		txResult.Ta = txResult.Ta + accountNum
		txResult.Ts = txResult.Ts + slotNum
		txResult.Rd = append(txResult.Rd, roundResult)
		txResult.Rb = append(txResult.Rb, accountNum+slotNum)

		if runtimeConfig.Fetcher == nil || accountNum == 0 && slotNum == 0 || mr > 0 && tracer.Round >= mr || !tracer.HasMore {
			break
		}

		// Fetch new access list
		var (
			accountsToFetch      []common.Address
			slotContractsToFetch []common.Address
			slotKeysToFetch      []common.Hash
		)

		if accountNum > 0 {
			accountsToFetch = make([]common.Address, 0, accountNum)
			for _, account := range roundResult.A {
				accountsToFetch = append(accountsToFetch, account)
			}
		}

		if slotNum > 0 {
			slotContractsToFetch = make([]common.Address, 0, slotNum)
			slotKeysToFetch = make([]common.Hash, 0, slotNum)
			for _, tuple := range roundResult.S {
				for _, key := range tuple.StorageKeys {
					slotContractsToFetch = append(slotContractsToFetch, tuple.Address)
					slotKeysToFetch = append(slotKeysToFetch, key)
				}
			}
		}

		runtimeConfig.Fetcher.Fetch(slotContractsToFetch, slotKeysToFetch, accountsToFetch)
		runtimeConfig.State = runtimeConfig.Fetcher.CopyStatedb()

		// Prepare for next round
		tracer.AppendListToKnownList()
		tracer.Touches = 0
		tracer.Step = 0
		tracer.HasMore = false
	}

	txResult.Tr = tracer.Round
	txResult.Tt = tracer.Touches

	if ctx.GlobalBool(SummaryFlag.Name) {
		// merge all rounds' records into one record
		tracer.AppendListToKnownList()
		summaryResult := TxRoundRecord{
			A: tracer.GetKnownAccounts(),
			S: tracer.GetKnownStorageSlots(),
		}
		txResult.Rd[0] = summaryResult
		txResult.Rd = txResult.Rd[0:1]
	}
	return txResult, nil
}

// Write to console with a more readable format
func printResults(results []*TxPredictResult) {
	for idx, result := range results {
		if result == nil {
			continue
		}
		if len(result.H) > 0 {
			fmt.Printf("\nTX %d:\t%v\n", idx, result.H)
		} else {
			fmt.Printf("\nTX %d\n", idx)
		}
		for idx2, round := range result.Rd {
			fmt.Printf("\nRound %d\n", idx2)
			batch := 0
			if len(round.A) > 0 {
				fmt.Printf("Accounts:\n")
				for _, account := range round.A {
					fmt.Printf("\t%v\n", account)
				}
				batch += len(round.A)
			}

			if len(round.S) > 0 {
				fmt.Printf("Slots:\n")
				for _, tuple := range round.S {
					fmt.Printf("\t%v\n", tuple.Address)
					for _, slot := range tuple.StorageKeys {
						fmt.Printf("\t\t%v\n", slot.Hex())
					}
					batch += len(tuple.StorageKeys)
				}
			}
		}
		// Summary
		fmt.Printf("\nSummary\n")
		fmt.Printf("Last round:           %d\n", result.Tr)
		fmt.Printf("Total touches:        %d\n", result.Tt)
		fmt.Printf("Total accounts:       %d\n", result.Ta)
		fmt.Printf("Total storage slots:  %d\n", result.Ts)
		fmt.Printf("Retrieval batches:    %v\n", result.Rb)
		fmt.Printf("Execution time:       %v\n", result.St)
		fmt.Printf("Allocations:          %v\n", result.Sa)
		fmt.Printf("Bytes allocated:      %v\n", result.Sb)

	}

}

func outputResults(filename string, results []*TxPredictResult) error {
	if len(results) > 0 {
		if len(filename) > 0 {
			// Dump to file as json format
			outputFile, outputError := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0666)
			if outputError != nil {
				return outputError
			}
			defer outputFile.Close()

			writer := bufio.NewWriter(outputFile)
			encoder := json.NewEncoder(writer)
			encoder.Encode(results)
			defer writer.Flush()
		} else {
			printResults(results)
		}
	}
	return nil
}

func init() {
	app.Flags = []cli.Flag{
		CacheFileFlag,
		CacheBlockFlag,
		RpcFlag,
		OutFlag,
		TxHashFlag,
		BlockFlag,
		BatchFlag,
		TimeoutFlag,
		CreateFlag,
		VerbosityFlag,
		CodeFlag,
		CodeFileFlag,
		ValueFlag,
		DataFlag,
		FromFlag,
		ToFlag,
		MaxProcsFlag,
		MaxRoundsFlag,
		DebugFlag,
		DisableMemoryFlag,
		DisableStackFlag,
		DisableStorageFlag,
		DisableReturnDataFlag,
		TestNetworkFlag,
		SummaryFlag,
	}

	app.Action = runCmd

	cli.CommandHelpTemplate = OriginCommandHelpTemplate
}

func main() {
	if err := app.Run(os.Args); err != nil {
		code := 1
		fmt.Fprintln(os.Stderr, err)
		os.Exit(code)
	}
}
