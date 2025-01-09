package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	tfjson "github.com/hashicorp/terraform-json"
	"github.com/jonjohnsonjr/tfimages/tfimages"
	"github.com/skratchdot/open-golang/open"
	"golang.org/x/sync/errgroup"
)

func main() {
	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt)
	defer done()

	if err := run(ctx); err != nil {
		if ctx.Err() == nil {
			log.Panic(err)
		}
	}
}

func run(ctx context.Context) error {
	log.Printf("decoding plan")
	var p tfjson.Plan
	if err := json.NewDecoder(os.Stdin).Decode(&p); err != nil {
		return err
	}

	h, err := tfimages.New(p, "")
	if err != nil {
		return err
	}

	http.HandleFunc("/", h.ServeHTTP)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              l.Addr().String(),
		ReadHeaderTimeout: 3 * time.Second,
	}

	log.Printf("%s", l.Addr().String())

	var g errgroup.Group
	g.Go(func() error {
		return server.Serve(l)
	})

	g.Go(func() error {
		return open.Run(fmt.Sprintf("http://localhost:%d", l.Addr().(*net.TCPAddr).Port))
	})

	g.Go(func() error {
		<-ctx.Done()
		server.Close()
		return ctx.Err()
	})

	return g.Wait()
}
