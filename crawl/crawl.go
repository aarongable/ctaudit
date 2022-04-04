package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/trillian/merkle/compact"
	"github.com/google/trillian/merkle/logverifier"
	"github.com/google/trillian/merkle/rfc6962"
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

func b64(h []byte) string {
	return base64.StdEncoding.EncodeToString(h)
}

func runFetcher(fetcher *scanner.Fetcher) <-chan entryData {
	entries := make(chan entryData)
	go func() {
		err := fetcher.Run(context.Background(), func(batch scanner.EntryBatch) {
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
	}()
	return entries
}

// runSorter starts a goroutine that reads entryData from its input, and emits
// them in sorted order (by increasing index) on the output channel it returns.
func runSorter(entries <-chan entryData) <-chan entryData {
	sortedEntries := make(chan entryData)
	buffer := NewHeap[entryData]()
	go func() {
		var nextIndex int64 = 0
		for e := range entries {
			buffer.Push(e)

			for buffer.Len() > 0 && buffer.Peek().index == nextIndex {
				e = buffer.Pop()
				sortedEntries <- e
				nextIndex += 1
			}
		}
		close(sortedEntries)
	}()
	return sortedEntries
}

// verify requests `get-proof-by-hash` for a given entry and calculates the
// root hash based on the returned audit_path plus the entry's hash. It then
// compares that against a root hash calculated by another method. This
// provides a way to do partial consistency checks along the way to verifying
// a full root hash from scratch. It also ensures that if the log is serving
// get-proof-by-hash requests using precalculated hashes, those precalculated
// hashes have not been corrupted.
func verify(logClient *client.LogClient, e entryData, rootHash []byte) error {
	currentTreeSize := e.index + 1

	var pbh *ct.GetProofByHashResponse
	var err error
	for {
		pbh, err = logClient.GetProofByHash(context.Background(), e.merkleLeafHash, uint64(currentTreeSize))
		if err != nil {
			var netError net.Error
			if errors.As(err, &netError) && netError.Timeout() {
				log.Printf("get-proof-by-hash: %s", err)
				time.Sleep(3 * time.Second)
				continue
			}
			return fmt.Errorf("getting proof by hash: %w", err)
		}
		break
	}

	verifier := logverifier.New(rfc6962.DefaultHasher)
	err = verifier.VerifyInclusionProof(e.index, currentTreeSize, pbh.AuditPath, rootHash, e.merkleLeafHash)
	if err != nil {
		var auditPathPrintable []string
		for _, h := range pbh.AuditPath {
			auditPathPrintable = append(auditPathPrintable, b64(h))
		}
		return fmt.Errorf("verify failed: VerifyInclusionProof(%d, %d, %s, %s, %s)=%w",
			e.index, currentTreeSize, auditPathPrintable,
			b64(rootHash), b64(e.merkleLeafHash), err)
	}
	return nil
}

func main() {
	logURI := flag.String("log_uri", "", "CT log base URI")
	batchSize := flag.Int("batch_size", 256, "Max number of entries to request per call to get-entries")
	numWorkers := flag.Int("num_workers", 2, "Number of concurrent workers")
	flag.Usage = func() {
		fmt.Print(`This tool gets the current STH of a log, then fetches all
entries up to that STH's tree_size, building the root hash as it goes. If the
root hash doesn't match, it exits with an error.

It also checks get-proof-by-hash along the way, builds the implied root hash
from the response, and checks that it matches the currently calculated root.
If there's a mismatch, this tool exits with an error.

`)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *logURI == "" {
		log.Fatal("must provide the -log_uri flag")
	}

	logClient, err := client.New(*logURI, &http.Client{
		Timeout: 10 * time.Second,
	}, jsonclient.Options{UserAgent: "le-ct-crawler/0.1"})
	if err != nil {
		log.Fatalf("creating log client: %s", err)
	}

	// Fetch whatever the log is serving as the current STH. Currently we just
	// trust the contents; we don't verify the signature.
	sth, err := logClient.GetSTH(context.Background())
	if err != nil {
		log.Fatalf("getting STH: %s", err)
	}

	log.Printf("verifying tree integrity at size %d (%s) with root hash %s", sth.TreeSize,
		time.UnixMilli(int64(sth.Timestamp)), sth.SHA256RootHash.Base64String())
	endIndex := int64(sth.TreeSize)

	fetcher := scanner.NewFetcher(
		logClient,
		&scanner.FetcherOptions{
			BatchSize:     *batchSize,
			StartIndex:    0,
			EndIndex:      endIndex,
			ParallelFetch: *numWorkers,
			Continuous:    false,
		},
	)

	// Fetch the entries as fast as possible
	entries := runFetcher(fetcher)
	// Filter them into sorted order
	sortedEntries := runSorter(entries)

	compactRange := (&compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}).NewEmptyRange(0)

	start := time.Now()
	var rootHash []byte
	var e entryData
	for e = range sortedEntries {
		compactRange.Append(e.merkleLeafHash, nil)
		rootHash, err = compactRange.GetRootHash(nil)
		if err != nil {
			// The only way this could happen is if we didn't start
			// the range at 0, which we definitely did.
			log.Fatalf("index %d: %s", e.index, err)
		}
		elapsed := time.Since(start).Seconds()
		fraction := float64(e.index) / float64(endIndex)
		rate := time.Duration(float64(e.index) / float64(elapsed))
		var eta time.Duration
		if rate > 0 {
			eta = time.Duration(endIndex-e.index) / rate * time.Second
		}

		// Sample by a medium-sized prime number so we're not always verifying
		// at even-length tree sizes; this might give us more coverage of
		// different kinds of paths through the tree.
		if e.index%98689 == 0 {
			log.Printf("index %d of %d; %2.1f%%; ETA %s; leaf %s; root %s",
				e.index, endIndex, fraction*100, eta,
				b64(e.merkleLeafHash), b64(rootHash))

			go func(e entryData, rootHash []byte) {
				err := verify(logClient, e, rootHash)
				if err != nil {
					log.Fatal(err)
				}
			}(e, rootHash)
		}
	}
	if e.index != endIndex-1 {
		log.Printf("channel closed early? processed %d entries; expected %d", e.index, endIndex)
	}
	log.Printf("final entry %d. Elapsed %s. Root hash %s",
		e.index, time.Since(start), b64(rootHash))
	if !bytes.Equal(rootHash, sth.SHA256RootHash[:]) {
		log.Fatalf(
			"calculated root hash differed from log's reported root hash at tree size %d: calculated %s, log reported %s",
			sth.TreeSize,
			b64(rootHash),
			b64(sth.SHA256RootHash[:]))
	}
	log.Printf(
		"success: calculated root hash at tree size %d was an exact match for get-sth: %s",
		sth.TreeSize,
		b64(rootHash))
}
