// Command bench — the PQ-07 measurement harness entry point (not a
// release artifact): decomposed throughput and rate measurements for the
// M0 SLO cells (spec §7.8).
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shsingh/pqscan/internal/microbench"
)

func main() {
	target := flag.String("target", "", "addr host:port to measure")
	host := flag.String("host", "", "SNI for the handshake (default: target host)")
	n := flag.Int("n", 20, "handshakes per worker")
	workers := flag.Int("w", 1, "concurrent workers")
	timeout := flag.Duration("timeout", 5*time.Second, "per-handshake timeout")
	mode := flag.String("mode", "seq", "seq | concurrent")
	flag.Parse()
	if *target == "" {
		fmt.Fprintln(os.Stderr, "usage: bench -target host:port [-host sni] [-n N] [-w W] [-mode seq|concurrent]")
		os.Exit(64)
	}
	sni := *host
	if sni == "" {
		sni = strings.Split(*target, ":")[0]
	}

	var res *microbench.Results
	var err error
	if *mode == "concurrent" {
		res, err = microbench.MeasureConcurrent(*target, sni, *workers, *n, *timeout)
	} else {
		res, err = microbench.MeasureHost(*target, sni, *n, *timeout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
	rate := float64(0)
	if res.ElapsedTotalS > 0 {
		rate = float64(res.Negotiated) / res.ElapsedTotalS
	}
	fmt.Printf("| target | n | negotiated | rate (h/s) | elapsed (s) |\n|---|---|---|---|---|\n")
	fmt.Printf("| %s | %s | %d | %.0f | %.3f |\n", *target, workerLabel(*mode, *workers, *n), res.Negotiated, rate, res.ElapsedTotalS)
	if len(res.Decompositions) > 20 {
		res.Decompositions = res.Decompositions[:20]
	}
	var cSum, hSum, cN float64
	for _, d := range res.Decompositions {
		if d.HandshakeMs > 0 {
			cSum += d.ConnectMs
			hSum += d.HandshakeMs
			cN++
		}
	}
	if cN > 0 {
		fmt.Printf("\nmean decomposition (negotiated flights): connect %.3f ms | handshake %.3f ms | total %.3f ms\n", cSum/cN, hSum/cN, (cSum+hSum)/cN)
	}
}

func workerLabel(mode string, w, n int) string {
	if mode == "concurrent" {
		return strconv.Itoa(w) + "w×" + strconv.Itoa(n)
	}
	return "seq×" + strconv.Itoa(n)
}
