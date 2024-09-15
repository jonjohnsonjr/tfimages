package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"time"

	"chainguard.dev/apko/pkg/build/types"
	"github.com/google/go-cmp/cmp"
	tfjson "github.com/hashicorp/terraform-json"
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

func runDiff(ctx context.Context, args []string) error {
	var hs []handler
	for _, arg := range args {
		log.Printf("decoding plan")
		f, err := os.Open(arg)
		if err != nil {
			return err
		}
		var p tfjson.Plan
		if err := json.NewDecoder(f).Decode(&p); err != nil {
			return err
		}

		h := handler{
			configs:   map[string]map[string]*imageConfig{},
			byPackage: map[string]map[string]*imageConfig{},
		}

		log.Printf("walking modules")
		if err := h.walkModules(p.PlannedValues.RootModule); err != nil {
			return err
		}
		hs = append(hs, h)
	}

	lhs, rhs := hs[0], hs[1]

	same := 0
	for repo, lByAddr := range lhs.configs {
		if err := ctx.Err(); err != nil {
			return err
		}

		rByAddr := rhs.configs[repo]

		for addr, lcfg := range lByAddr {
			rcfg := rByAddr[addr]

			if rcfg == nil {
				if same != 0 {
					fmt.Printf("%d same\n", same)
				}
				same = 0
				fmt.Printf("missing rcfg for %q\n", addr)
				continue
			}

			if diff := cmp.Diff(lcfg.config, rcfg.config); diff != "" {
				if same != 0 {
					fmt.Printf("%d same\n", same)
				}
				same = 0
				fmt.Printf("diff %q\n", addr)
				fmt.Printf("%s\n\n", diff)
			} else {
				same++
			}
		}
	}
	if same != 0 {
		fmt.Printf("%d same\n", same)
	}
	return nil
}

func run(ctx context.Context) error {
	if len(os.Args) == 3 {
		return runDiff(ctx, os.Args[1:])
	}

	log.Printf("decoding plan")
	var p tfjson.Plan
	if err := json.NewDecoder(os.Stdin).Decode(&p); err != nil {
		return err
	}

	h := handler{
		configs:   map[string]map[string]*imageConfig{},
		byPackage: map[string]map[string]*imageConfig{},
	}

	log.Printf("walking modules")
	if err := h.walkModules(p.PlannedValues.RootModule); err != nil {
		return err
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		if err := h.handle(w, r); err != nil {
			log.Printf("error: %s", err)
		}
	})

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

type handler struct {
	configs   map[string]map[string]*imageConfig
	byPackage map[string]map[string]*imageConfig
}

type imageConfig struct {
	repo   string
	addr   string
	config *types.ImageConfiguration
}

func (h *handler) add(repo, addr string, ic *types.ImageConfiguration) {
	byAddr, ok := h.configs[repo]
	if !ok {
		byAddr = map[string]*imageConfig{}
	}

	cfg := &imageConfig{
		repo:   repo,
		addr:   addr,
		config: ic,
	}

	byAddr[addr] = cfg

	h.configs[repo] = byAddr

	for _, pkg := range ic.Contents.Packages {
		byAddr, ok := h.byPackage[pkg]
		if !ok {
			byAddr = map[string]*imageConfig{}
		}
		byAddr[addr] = cfg

		h.byPackage[pkg] = byAddr
	}
}

func (h *handler) handle(w http.ResponseWriter, r *http.Request) error {
	if r.URL.Path == "/images" {
		return h.renderImages(w)
	}

	if r.URL.Path == "/packages" {
		return h.renderPackages(w)
	}

	if r.URL.Path != "/" {
		return nil
	}

	qs := r.URL.Query()
	addr := qs.Get("addr")
	repo := qs.Get("repo")
	pkg := qs.Get("pkg")

	if addr != "" {
		return h.renderAddr(w, repo, addr)
	} else if pkg != "" && repo != "" {
		return h.renderPkgRepo(w, pkg, repo)
	} else if pkg != "" {
		return h.renderPkg(w, pkg)
	} else if repo != "" {
		return h.renderRepo(w, repo)
	} else {
		h.renderLanding(w)
	}

	return nil
}

func (h *handler) renderAddr(w http.ResponseWriter, repo, addr string) error {
	defer boilerplate(w)()

	byAddr, ok := h.configs[repo]
	if !ok {
		return errorf(w, "no repo %q", repo)
	}

	config, ok := byAddr[addr]
	if !ok {
		return errorf(w, "no addr %q", addr)
	}

	fmt.Fprintf(w, "<h1>%s</h1>\n", repo)
	fmt.Fprintf(w, "<h2>%s</h2>\n", addr)
	fmt.Fprintf(w, "<pre>\n")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(linkify(*config.config)); err != nil {
		return errorf(w, "encode: %w", err)
	}
	fmt.Fprintf(w, "</pre>\n")

	return nil
}

func linkify(ic types.ImageConfiguration) types.ImageConfiguration {
	packages := slices.Clone(ic.Contents.Packages)
	for i, pkg := range packages {
		packages[i] = fmt.Sprintf("<a href=/?pkg=%s>%s</a>", url.QueryEscape(pkg), html.EscapeString(pkg))
	}
	ic.Contents.Packages = packages
	return ic
}

func (h *handler) renderRepo(w http.ResponseWriter, repo string) error {
	defer boilerplate(w)()

	fmt.Fprintf(w, "<h1>%s</h1>\n", repo)
	fmt.Fprintf(w, "<ul>\n")
	byAddr, ok := h.configs[repo]
	if !ok {
		return errorf(w, "no repo %q", repo)
	}
	for _, addr := range slices.Sorted(maps.Keys(byAddr)) {
		href := fmt.Sprintf("/?repo=%s&addr=%s", url.QueryEscape(repo), url.QueryEscape(addr))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(addr))
	}
	fmt.Fprintf(w, "</ul>\n")

	return nil
}

func (h *handler) renderPkgRepo(w http.ResponseWriter, pkg, repo string) error {
	defer boilerplate(w)()

	fmt.Fprintf(w, "<h1>%s</h1>\n", repo)
	fmt.Fprintf(w, "<h2>containing %s</h2>\n", pkg)
	fmt.Fprintf(w, "<ul>\n")
	fromRepo, ok := h.configs[repo]
	if !ok {
		return errorf(w, "no repo %q", repo)
	}
	fromPkg, ok := h.byPackage[pkg]
	if !ok {
		return errorf(w, "no pkg %q", pkg)
	}
	for _, addr := range slices.Sorted(maps.Keys(fromRepo)) {
		if _, ok := fromPkg[addr]; !ok {
			continue
		}
		href := fmt.Sprintf("/?repo=%s&addr=%s", repo, url.QueryEscape(addr))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(addr))
	}
	fmt.Fprintf(w, "</ul>\n")

	return nil
}

func (h *handler) renderPkg(w http.ResponseWriter, pkg string) error {
	defer boilerplate(w)()

	fmt.Fprintf(w, "<h1>Images containing %s</h1>\n", pkg)
	fmt.Fprintf(w, "<ul>\n")
	fromPkg, ok := h.byPackage[pkg]
	if !ok {
		return errorf(w, "no pkg %q", pkg)
	}

	byRepo := map[string]struct{}{}
	for _, cfg := range fromPkg {
		byRepo[cfg.repo] = struct{}{}
	}
	for _, repo := range slices.Sorted(maps.Keys(byRepo)) {
		href := fmt.Sprintf("/?repo=%s&pkg=%s", url.QueryEscape(repo), url.QueryEscape(pkg))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(repo))
	}
	fmt.Fprintf(w, "</ul>\n")

	return nil
}

func (h *handler) renderImages(w http.ResponseWriter) error {
	defer boilerplate(w)()

	fmt.Fprintf(w, "<h1>Images</h1>\n")
	fmt.Fprintf(w, "<ul>\n")
	for _, repo := range slices.Sorted(maps.Keys(h.configs)) {
		href := fmt.Sprintf("/?repo=%s", url.QueryEscape(repo))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(repo))
	}
	fmt.Fprintf(w, "</ul>\n")

	return nil
}

func (h *handler) renderPackages(w http.ResponseWriter) error {
	defer boilerplate(w)()

	fmt.Fprintf(w, "<h1>Packages</h1>\n")
	fmt.Fprintf(w, "<ul>\n")
	for _, pkg := range slices.Sorted(maps.Keys(h.byPackage)) {
		href := fmt.Sprintf("/?pkg=%s", url.QueryEscape(pkg))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(pkg))
	}
	fmt.Fprintf(w, "</ul>\n")

	return nil
}

func (h *handler) renderLanding(w http.ResponseWriter) {
	defer boilerplate(w)()

	fmt.Fprintf(w, "<h1>Plan</h1>\n")
	fmt.Fprintf(w, "<p><a href=%q>Images (%d)</a></p>\n", "images", len(h.configs))
	fmt.Fprintf(w, "<p><a href=%q>Packages (%d)</a></p>\n", "packages", len(h.byPackage))
}

func (h *handler) walkModules(m *tfjson.StateModule) error {
	for _, r := range m.Resources {
		if r.Type == "apko_build" {
			val, ok := r.AttributeValues["repo"]
			if !ok {
				return fmt.Errorf("missing repo: %s", r.Address)
			}

			repo, ok := val.(string)
			if !ok {
				return fmt.Errorf("repo is a %T: %s", repo, r.Address)
			}

			config, ok := r.AttributeValues["config"]
			if !ok {
				return fmt.Errorf("missing config: %s", r.Address)
			}

			b, err := json.Marshal(config)
			if err != nil {
				return fmt.Errorf("marshal: %w", err)
			}

			var ic types.ImageConfiguration
			if err := json.Unmarshal(b, &ic); err != nil {
				return fmt.Errorf("unmarshal: %w", err)
			}

			h.add(repo, r.Address, &ic)
		}
	}

	for _, c := range m.ChildModules {
		if err := h.walkModules(c); err != nil {
			return err
		}
	}

	return nil
}

func errorf(w http.ResponseWriter, msg string, args ...any) error {
	err := fmt.Errorf(msg, args...)
	fmt.Fprintf(w, "<span>%s</span>\n", err.Error())
	return err
}

func boilerplate(w http.ResponseWriter) func() {
	fmt.Fprintf(w, "<html>\n")
	fmt.Fprintf(w, "<style>\n")
	fmt.Fprintf(w, `body {
	font-family: monospace;
	width: fit-content;
	overflow-wrap: anywhere;
	padding: 12px;
}`)
	fmt.Fprintf(w, "</style>\n")
	fmt.Fprintf(w, "<body>\n")

	return func() {
		fmt.Fprintf(w, "</body>\n")
		fmt.Fprintf(w, "</html>\n")
	}
}
