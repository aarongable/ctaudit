package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/trillian/merkle/compact"
	"github.com/google/trillian/merkle/logverifier"

	"github.com/google/trillian/merkle/rfc6962"

	_ "github.com/go-sql-driver/mysql"
)

// entryData contains the index / sequence number of an entry, as well as the
// leaf input contained at that index. It also implements the Orderable interface
// so that it can be used in a Heap.
type entryData struct {
	index          int64
	merkleLeafHash []byte
}

func (ed entryData) Before(other entryData) bool {
	return ed.index < other.index
}

func showHash(h []byte) string {
	return base64.StdEncoding.EncodeToString(h)
}

func main() {
	logURI := flag.String("log_uri", "https://oak.ct.letsencrypt.org/2022/", "CT log base URI")
	batchSize := flag.Int("batch_size", 256, "Max number of entries to request per call to get-entries")
	numWorkers := flag.Int("num_workers", 2, "Number of concurrent workers")
	startIndex := flag.Int64("start_index", 0, "Log index to start scanning at")
	// endIndex := flag.Int64("end_index", 0, "Log index to end scanning at (non-inclusive)")
	// treeId := flag.Int64("tree_id", 0, "Tree ID for identification in the DB")
	flag.Parse()

	// dsn := os.Getenv("DB")
	// if dsn == "" {
	// 	log.Fatal("$DB is unset; put a DB connection string in $DB")
	// }
	// db, err := sql.Open("mysql", os.Getenv("DB"))
	// if err != nil {
	// 	log.Fatal("opening DB: %w", err)
	// }

	// db.SetMaxIdleConns(*numWorkers)
	// db.SetMaxOpenConns(*numWorkers)
	// db.SetConnMaxLifetime(time.Minute)

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
		log.Fatalf("creating log client: %s", err)
	}

	sth, err := logClient.GetSTH(context.Background())
	if err != nil {
		log.Fatalf("getting STH: %s", err)
	}

	log.Printf("verifying tree integrity at size %d (%s) with root hash %s", sth.TreeSize,
		time.Unix(0, int64(sth.Timestamp*1e6)), sth.SHA256RootHash.Base64String())
	endIndex := int64(sth.TreeSize - 1)

	hasher := rfc6962.DefaultHasher
	verifier := logverifier.New(hasher)
	fact := compact.RangeFactory{Hash: hasher.HashChildren}
	compactRange := fact.NewEmptyRange(0)

	fetcher := scanner.NewFetcher(
		logClient,
		&scanner.FetcherOptions{
			BatchSize:     *batchSize,
			StartIndex:    *startIndex,
			EndIndex:      endIndex,
			ParallelFetch: *numWorkers,
			Continuous:    false,
		},
	)

	// Create a callback that sends fetched entries to a channel to be processed.
	entries := make(chan entryData)
	sortedEntries := make(chan entryData)

	// Start a worker which reads entries from the fetchers. If it receives an
	// entry for which it has not already processed the immediately preceding
	// entry, it buffers it and waits to process it until the intervening entries
	// have been backfilled. When processing an entry, it compares it to the
	// immediately prior entry: if the timestamp has traveled backwards in time,
	// it outputs the *prior* entry, on the assumption that its timestamp was
	// incorrectly forward in time.
	buffer := NewHeap[entryData]()
	go func() {
		var nextIndex int64 = 0
		for e := range entries {
			buffer.Push(e)

			// Try to process the buffer, just in case we've caught up to it.
			for buffer.Len() > 0 && buffer.Peek().index == nextIndex {
				e = buffer.Pop()
				sortedEntries <- e
				nextIndex += 1
			}
		}
		close(sortedEntries)
	}()

	rootHashChan := make(chan []byte)
	start := time.Now()
	go func() {
		var rootHash []byte
		var err error
		var e entryData
		rootHash, err = compactRange.GetRootHash(nil)
		if err != nil {
			log.Fatal(err)
		}
		for e = range sortedEntries {
			compactRange.Append(e.merkleLeafHash, nil)
			rootHash, err = compactRange.GetRootHash(nil)
			if err != nil {
				// The only way this could happen is if we didn't start
				// the range at 0, which we definitely did, so it's okay to
				// die here.
				log.Fatalf("index %d: %s", e.index, err)
			}
			elapsed := time.Since(start).Seconds()
			fraction := float64(e.index) / float64(endIndex)
			rate := time.Duration(float64(e.index) / float64(elapsed))
			var eta time.Duration
			if rate > 0 {
				eta = time.Duration(endIndex-e.index) / rate * time.Second
			}

			if e.index%98689 == 0 {
				log.Printf("index %d of %d; %2.1f%%; ETA %s; leaf %s; root %s",
					e.index,
					endIndex,
					fraction*100,
					eta,
					url.QueryEscape(showHash(e.merkleLeafHash)),
					showHash(rootHash))

				treeSize := e.index + 1
				pbh, err := logClient.GetProofByHash(context.Background(), e.merkleLeafHash, uint64(treeSize))
				if err != nil {
					log.Printf("getting proof by hash: %s", err)
				}

				err = verifier.VerifyInclusionProof(e.index, treeSize, pbh.AuditPath, rootHash, e.merkleLeafHash)
				if err != nil {
					var auditPathPrintable []string
					for _, h := range pbh.AuditPath {
						auditPathPrintable = append(auditPathPrintable, showHash(h))
					}
					log.Fatalf("Failed to VerifyInclusionProof(%d, %d, %s, %s, %s)=%s",
						e.index, treeSize, auditPathPrintable,
						showHash(rootHash), showHash(e.merkleLeafHash), err)
				}
			}
		}
		if e.index != endIndex-1 {
			log.Printf("channel closed early? processed %d entries; expected %d", e.index, endIndex)
		}
		log.Printf("Final entry %d. Elapsed %s. Root hash %s",
			e.index, time.Since(start), showHash(rootHash))
		rootHashChan <- rootHash
	}()

	// Finally, run the fetcher, letting it feed data into the worker above.
	err = fetcher.Run(context.Background(), func(batch scanner.EntryBatch) {
		for i, e := range batch.Entries {
			h := sha256.New()
			h.Write([]byte{0})
			h.Write(e.LeafInput)
			entries <- entryData{index: batch.Start + int64(i), merkleLeafHash: h.Sum(nil)}
		}
	})
	if err != nil {
		log.Fatal(err)
	}

	close(entries)
	rootHash := <-rootHashChan
	if !bytes.Equal(rootHash, sth.SHA256RootHash[:]) {
		log.Printf(
			"calculated root hash differed from log's reported root hash at tree size %d: calculated %s, log reported %s",
			sth.TreeSize,
			showHash(rootHash),
			showHash(sth.SHA256RootHash[:]))
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
