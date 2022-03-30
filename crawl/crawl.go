package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"flag"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/trillian/merkle/compact"

	"github.com/google/trillian/merkle/rfc6962"

	_ "github.com/go-sql-driver/mysql"
)

// entryData contains the index / sequence number of an entry, as well as the
// leaf input contained at that index. It also implements the Orderable interface
// so that it can be used in a Heap.
type entryData struct {
	index     int64
	leafInput []byte
}

func (ed entryData) Before(other entryData) bool {
	return ed.index < other.index
}

func main() {
	logURI := flag.String("log_uri", "https://oak.ct.letsencrypt.org/2022/", "CT log base URI")
	batchSize := flag.Int("batch_size", 256, "Max number of entries to request at per call to get-entries")
	numWorkers := flag.Int("num_workers", 2, "Number of concurrent workers")
	startIndex := flag.Int64("start_index", 0, "Log index to start scanning at")
	endIndex := flag.Int64("end_index", 0, "Log index to end scanning at (non-inclusive, 0 = end of log)")
	treeId := flag.Int64("tree_id", 0, "Tree ID for identification in the DB")
	flag.Parse()

	dsn := os.Getenv("DB")
	if dsn == "" {
		log.Fatal("$DB is unset; put a DB connection string in $DB")
	}
	db, err := sql.Open("mysql", os.Getenv("DB"))
	if err != nil {
		log.Fatal("opening DB: %w", err)
	}

	db.SetMaxIdleConns(*numWorkers)
	db.SetMaxOpenConns(*numWorkers)
	db.SetConnMaxLifetime(time.Minute)

	logClient, err := client.New(*logURI, &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, jsonclient.Options{UserAgent: "le-ct-crawler/0.1"})
	if err != nil {
		log.Fatal("Failed to create log client")
	}

	hasher := rfc6962.DefaultHasher
	fact := compact.RangeFactory{Hash: hasher.HashChildren}
	compactRange := fact.NewEmptyRange(0)

	fetcher := scanner.NewFetcher(
		logClient,
		&scanner.FetcherOptions{
			BatchSize:     *batchSize,
			StartIndex:    *startIndex,
			EndIndex:      *endIndex,
			ParallelFetch: *numWorkers,
			Continuous:    false,
		},
	)

	var wg sync.WaitGroup

	// Create a callback that sends fetched entries to a channel to be processed.
	entries := make(chan entryData)
	processBatch := func(batch scanner.EntryBatch) {
		for i, e := range batch.Entries {
			wg.Add(1)
			entries <- entryData{index: batch.Start + int64(i), leafInput: e.LeafInput}
		}
	}

	// Set up a context and a signal-catcher to cancel the context so we can
	// break out cleanly if we need to.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM)
		signal.Notify(sigChan, syscall.SIGINT)
		signal.Notify(sigChan, syscall.SIGHUP)

		<-sigChan
		cancel()

		os.Exit(0)
	}()

	start := time.Now()
	for i := 0; i < *numWorkers; i++ {
		go func() {
			for e := range entries {
				h := sha256.New()
				h.Write([]byte{0})
				h.Write(e.leafInput)
				/// XXX wrong - these must be ordered first
				compactRange.Append(h.Sum(nil), nil)
				rootHash, err := compactRange.GetRootHash(nil)
				if err != nil {
					// The only way this could happen is if we didn't start
					// the range at 0, which we definitely did, so it's okay to
					// die here.
					log.Fatalf("index %d: %s", e.index, err)
				}
				for i := 0; i < 20; i++ {
					_, err = db.Exec("INSERT IGNORE INTO Hashes (TreeId, SequenceNumber, MerkleLeafHash) VALUES (?, ?, ?)",
						*treeId, e.index, h.Sum(nil))
					if err != nil {
						log.Print(err)
						time.Sleep(time.Second * time.Duration(1+rand.Int()/math.MaxInt))
					} else {
						break
					}
				}
				if e.index%1000 == 0 && e.index > 0 {
					elapsed := time.Since(start).Seconds()
					fraction := float64(e.index) / float64(*endIndex)
					rate := time.Duration(float64(e.index) / float64(elapsed))
					eta := time.Duration(*endIndex-e.index) / rate * time.Second

					log.Printf("processed entry %d out of %d, %2.1f%%; ETA %s; root hash %x", e.index, *endIndex, fraction*100, eta, rootHash)
				}
				wg.Done()
			}
		}()
	}

	// Finally, run the fetcher, letting it feed data into the worker above.
	err = fetcher.Run(ctx, processBatch)
	if err != nil {
		log.Fatal(err)
	}

	close(entries)
	wg.Wait()
	log.Printf("Done. Elapsed time: %s", time.Since(start))
}
