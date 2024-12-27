package main

import (
	"bytes"
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
	"strings"
	"time"

	"chainguard.dev/apko/pkg/build/types"
	"github.com/google/go-cmp/cmp"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/skratchdot/open-golang/open"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v2"
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
	if len(os.Args) == 3 {
		return runDiff(ctx, os.Args[1:])
	}

	log.Printf("decoding plan")
	var p tfjson.Plan
	if err := json.NewDecoder(os.Stdin).Decode(&p); err != nil {
		return err
	}

	h := handler{
		repoByAddr:   map[string]string{},
		configs:      map[string]*imageConfig{},
		byRepo:       map[string]map[string]*imageBuild{},
		builds:       map[string]*imageBuild{},
		byPackage:    map[string]map[string]*imageBuild{},
		byConstraint: map[string]map[string]*imageConfig{},
	}

	if apkoConfig, ok := p.Config.ProviderConfigs["apko"]; ok {
		if exprs, ok := apkoConfig.Expressions["extra_packages"]; ok {
			cv := exprs.ConstantValue
			list, ok := cv.([]any)
			if !ok {
				return fmt.Errorf("extra_packages is a %T", cv)
			}

			for _, el := range list {
				if pkg, ok := el.(string); ok {
					h.extraPackages = append(h.extraPackages, pkg)
				} else {
					return fmt.Errorf("extra_packages element is a %T", el)
				}
			}
		}
	}

	log.Printf("walking planned values")
	if err := h.walkModules(p.PlannedValues.RootModule); err != nil {
		return err
	}
	log.Printf("walking prior state")
	if err := h.walkModules(p.PriorState.Values.RootModule); err != nil {
		return err
	}

	log.Printf("%d configs, %d builds", len(h.configs), len(h.builds))

	h.orphans = make([]string, 0, len(h.configs)-len(h.builds))

	for addr := range h.configs {
		buildAddr := strings.ReplaceAll(addr, "data.apko_config", "apko_build")
		if _, ok := h.builds[buildAddr]; !ok {
			h.orphans = append(h.orphans, addr)
		}
	}

	slices.Sort(h.orphans)

	versions := map[string]map[string]any{}
	for pkg := range h.byPackage {
		p, v, ok := strings.Cut(pkg, "=")
		if !ok {
			panic(pkg)
		}
		if _, ok := versions[p]; !ok {
			versions[p] = map[string]any{}
		}
		versions[p][v] = struct{}{}
	}

	h.duplicates = map[string]map[string]any{}
	for p, vs := range versions {
		if len(vs) != 1 {
			h.duplicates[p] = vs
		}
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
	configs      map[string]*imageConfig
	byConstraint map[string]map[string]*imageConfig
	builds       map[string]*imageBuild
	byRepo       map[string]map[string]*imageBuild
	byPackage    map[string]map[string]*imageBuild
	repoByAddr   map[string]string
	orphans      []string
	duplicates   map[string]map[string]any

	extraPackages []string
}

type imageBuild struct {
	repo   string
	addr   string
	config *types.ImageConfiguration
}

type imageConfig struct {
	addr   string
	config *types.ImageConfiguration
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

			h.build(repo, r.Address, &ic)
		}
		if r.Type == "apko_config" {
			config, ok := r.AttributeValues["config_contents"]
			if !ok {
				return fmt.Errorf("missing config: %s", r.Address)
			}

			s, ok := config.(string)
			if !ok {
				return fmt.Errorf("config is a %T: %s", config, r.Address)
			}

			var ic types.ImageConfiguration
			if err := yaml.UnmarshalStrict([]byte(s), &ic); err != nil {
				log.Printf("%s", s)
				return fmt.Errorf("unmarshal: %w", err)
			}

			extra, ok := r.AttributeValues["extra_packages"]
			if ok && extra != nil {
				pkgs, ok := extra.([]any)
				if !ok {
					return fmt.Errorf("extra_packages is a %T: %s", extra, r.Address)
				}
				for _, pkg := range pkgs {
					ic.Contents.Packages = append(ic.Contents.Packages, pkg.(string))
				}
			}

			h.config(r.Address, &ic)
		}
	}

	for _, c := range m.ChildModules {
		if err := h.walkModules(c); err != nil {
			return err
		}
	}

	return nil
}

func (h *handler) build(repo, addr string, ic *types.ImageConfiguration) {
	byAddr, ok := h.byRepo[repo]
	if !ok {
		byAddr = map[string]*imageBuild{}
	}

	cfg := &imageBuild{
		repo:   repo,
		addr:   addr,
		config: ic,
	}

	byAddr[addr] = cfg
	h.builds[addr] = cfg

	h.byRepo[repo] = byAddr

	h.repoByAddr[addr] = repo

	for _, pkg := range ic.Contents.Packages {
		byAddr, ok := h.byPackage[pkg]
		if !ok {
			byAddr = map[string]*imageBuild{}
		}
		byAddr[addr] = cfg

		h.byPackage[pkg] = byAddr
	}
}

func (h *handler) config(addr string, ic *types.ImageConfiguration) {
	cfg := &imageConfig{
		addr:   addr,
		config: ic,
	}

	h.configs[addr] = cfg

	for _, pkg := range ic.Contents.Packages {
		byAddr, ok := h.byConstraint[pkg]
		if !ok {
			byAddr = map[string]*imageConfig{}
		}
		byAddr[addr] = cfg

		h.byConstraint[pkg] = byAddr
	}
}

func (h *handler) renderLanding(w http.ResponseWriter) {
	defer boilerplate(w)()

	fmt.Fprintf(w, "<p><a href=%q>Images (%d)</a></p>\n", "images", len(h.byRepo))
	fmt.Fprintf(w, "<p><a href=%q>Builds (%d)</a></p>\n", "builds", len(h.builds))
	fmt.Fprintf(w, "<p><a href=%q>Packages (%d)</a></p>\n", "packages", len(h.byPackage))
	fmt.Fprintf(w, "<p><a href=%q>Configs (%d)</a></p>\n", "configs", len(h.configs))
	fmt.Fprintf(w, "<p><a href=%q>Constraints (%d)</a></p>\n", "constraints", len(h.byConstraint))
}

func (h *handler) handle(w http.ResponseWriter, r *http.Request) error {
	if r.URL.Path == "/images" {
		return h.renderImages(w)
	}

	if r.URL.Path == "/builds" {
		return h.renderBuilds(w)
	}

	if r.URL.Path == "/packages" {
		return h.renderPackages(w)
	}

	if r.URL.Path == "/configs" {
		return h.renderConfigs(w)
	}

	if r.URL.Path == "/constraints" {
		return h.renderConstraints(w)
	}

	if r.URL.Path != "/" {
		return nil
	}

	qs := r.URL.Query()
	addr := qs.Get("addr")
	repo := qs.Get("repo")
	pkg := qs.Get("pkg")
	cfg := qs.Get("cfg")
	constraint := qs.Get("constraint")

	if addr != "" {
		return h.renderAddr(w, repo, addr)
	} else if pkg != "" && repo != "" {
		return h.renderPkgRepo(w, pkg, repo)
	} else if pkg != "" {
		return h.renderPkg(w, pkg)
	} else if constraint != "" {
		return h.renderConstraint(w, constraint)
	} else if repo != "" {
		return h.renderRepo(w, repo)
	} else if cfg != "" {
		return h.renderCfg(w, cfg)
	} else {
		h.renderLanding(w)
	}

	return nil
}

func (h *handler) renderAddr(w http.ResponseWriter, repo, addr string) error {
	defer boilerplate(w)()

	if repo == "" {
		repo = h.repoByAddr[addr]
	}

	byAddr, ok := h.byRepo[repo]
	if !ok {
		return errorf(w, "no repo %q", repo)
	}

	build, ok := byAddr[addr]
	if !ok {
		return errorf(w, "no addr %q", addr)
	}

	fmt.Fprintf(w, "<h2>%s</h2>\n", repo)
	fmt.Fprintf(w, "<h3>%s</h3>\n", addr)

	cfgAddr := strings.ReplaceAll(addr, "apko_build", "data.apko_config")
	if _, ok := h.configs[cfgAddr]; ok {
		fmt.Fprintf(w, "<a href=/?cfg=%s>%s</a>\n", url.QueryEscape(cfgAddr), html.EscapeString(cfgAddr))
	}

	fmt.Fprintf(w, "<pre>\n")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(linkify(*build.config, "pkg")); err != nil {
		return errorf(w, "encode: %w", err)
	}
	fmt.Fprintf(w, "</pre>\n")

	return nil
}

func linkify(ic types.ImageConfiguration, page string) types.ImageConfiguration {
	packages := slices.Clone(ic.Contents.Packages)
	for i, pkg := range packages {
		packages[i] = fmt.Sprintf("<a href=/?%s=%s>%s</a>", page, url.QueryEscape(pkg), html.EscapeString(pkg))
	}
	ic.Contents.Packages = packages
	return ic
}

func (h *handler) renderRepo(w http.ResponseWriter, repo string) error {
	defer boilerplate(w)()

	fmt.Fprintf(w, "<h2>%s</h2>\n", repo)
	fmt.Fprintf(w, "<ul>\n")
	byAddr, ok := h.byRepo[repo]
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

	fmt.Fprintf(w, "<h2>%s</h2>\n", repo)
	fmt.Fprintf(w, "<h3>containing %s</h3>\n", pkg)
	fmt.Fprintf(w, "<ul>\n")
	fromRepo, ok := h.byRepo[repo]
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

	fmt.Fprintf(w, "<h2>Images containing %s</h2>\n", pkg)
	fmt.Fprintf(w, "<p>This is every repo containing a apko_build.config with a packages field containing %q.</p>\n", pkg)
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

func (h *handler) renderCfg(w http.ResponseWriter, addr string) error {
	defer boilerplate(w)()

	config, ok := h.configs[addr]
	if !ok {
		return errorf(w, "no addr %q", addr)
	}

	fmt.Fprintf(w, "<h2>%s</h2>\n", addr)

	cfg := *config.config

	buildAddr := strings.ReplaceAll(addr, "data.apko_config", "apko_build")
	if build, ok := h.builds[buildAddr]; ok {
		fmt.Fprintf(w, "<a href=/?addr=%s>%s</a>\n", url.QueryEscape(buildAddr), html.EscapeString(buildAddr))

		// Defensive copy to avoid mutating the build.
		copied := types.ImageConfiguration{}
		if err := build.config.MergeInto(&copied); err != nil {
			return errorf(w, "copying %s: %w", buildAddr, err)
		}

		// Carry over packages from apko_config.
		copied.Contents.Packages = cfg.Contents.Packages

		// Add global extra packages at apko provider level.
		copied.Contents.Packages = append(copied.Contents.Packages, h.extraPackages...)

		cfg = copied
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")

	if err := enc.Encode(cfg); err != nil {
		return errorf(w, "encode: %w", err)
	}

	// For Jason.
	fmt.Fprintf(w, `<script>
	function updateClipboard() {
		const button = document.getElementById('button');
		var text = %q;
		navigator.clipboard.writeText(text).then(
			() => {
				button.textContent = 'Copied';
			},
			() => {
				button.textContent = 'Failed';
			},
		);
	}
	</script>
	`, buf.String())
	fmt.Fprintf(w, "<p><button id=\"button\" onclick=\"updateClipboard()\">Copy</button></p>\n")

	enc = json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	fmt.Fprintf(w, "<pre>\n")
	if err := enc.Encode(linkify(cfg, "constraint")); err != nil {
		return errorf(w, "encode: %w", err)
	}
	fmt.Fprintf(w, "</pre>\n")

	return nil
}

func (h *handler) renderConstraint(w http.ResponseWriter, constraint string) error {
	defer boilerplate(w)()

	fmt.Fprintf(w, "<h2>Configs containing %s</h2>\n", constraint)
	fmt.Fprintf(w, "<p>This is every apko_config.config_contents with a packages field containing %q.</p>\n", constraint)
	fmt.Fprintf(w, "<ul>\n")
	fromConstraint, ok := h.byConstraint[constraint]
	if !ok {
		return errorf(w, "no constraint %q", constraint)
	}

	for _, addr := range slices.Sorted(maps.Keys(fromConstraint)) {
		href := fmt.Sprintf("/?cfg=%s", url.QueryEscape(addr))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(addr))
	}
	fmt.Fprintf(w, "</ul>\n")

	return nil
}

func (h *handler) renderImages(w http.ResponseWriter) error {
	defer boilerplate(w)()

	fmt.Fprintf(w, "<h2>Images</h2>\n")
	fmt.Fprintf(w, "<p>This is every apko_build grouped by repo.</p>\n")
	fmt.Fprintf(w, "<ul>\n")
	for _, repo := range slices.Sorted(maps.Keys(h.byRepo)) {
		href := fmt.Sprintf("/?repo=%s", url.QueryEscape(repo))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(repo))
	}
	fmt.Fprintf(w, "</ul>\n")

	return nil
}

func (h *handler) renderPackages(w http.ResponseWriter) error {
	defer boilerplate(w)()

	fmt.Fprintf(w, "<h2>Packages</h2>\n")
	fmt.Fprintf(w, "<p>Every packages entry in a apko_build.config will show up here.</p>\n")
	fmt.Fprintf(w, "<ul>\n")
	for _, pkg := range slices.Sorted(maps.Keys(h.byPackage)) {
		href := fmt.Sprintf("/?pkg=%s", url.QueryEscape(pkg))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(pkg))
	}
	fmt.Fprintf(w, "</ul>\n")

	if len(h.duplicates) == 0 {
		return nil
	}

	fmt.Fprintf(w, "<h3>Duplicates</h3>\n")
	fmt.Fprintf(w, "<p>These packages have more than one version somewhere.</p>\n")
	fmt.Fprintf(w, "<ul>\n")
	for _, pkg := range slices.Sorted(maps.Keys(h.duplicates)) {
		fmt.Fprintf(w, "<li>%s</li>\n", pkg)
		fmt.Fprintf(w, "<ul>\n")
		for v := range h.duplicates[pkg] {
			href := fmt.Sprintf("/?pkg=%s", url.QueryEscape(pkg+"="+v))
			fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(v))
		}
		fmt.Fprintf(w, "</ul>\n")
	}
	fmt.Fprintf(w, "</ul>\n")

	return nil
}

func (h *handler) renderBuilds(w http.ResponseWriter) error {
	defer boilerplate(w)()

	fmt.Fprintf(w, "<h2>Builds</h2>\n")
	fmt.Fprintf(w, "<p>These are the apko_build.config contents for every build.</p>\n")
	fmt.Fprintf(w, "<ul>\n")
	for _, addr := range slices.Sorted(maps.Keys(h.builds)) {
		href := fmt.Sprintf("/?addr=%s", url.QueryEscape(addr))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(addr))
	}
	fmt.Fprintf(w, "</ul>\n")

	return nil
}

func (h *handler) renderConfigs(w http.ResponseWriter) error {
	defer boilerplate(w)()

	fmt.Fprintf(w, "<h2>Configs</h2>\n")
	fmt.Fprintf(w, "<p>These are the config_contents of every apko_config in the plan's prior_state.</p>\n")
	fmt.Fprintf(w, "<ul>\n")
	for _, addr := range slices.Sorted(maps.Keys(h.configs)) {
		href := fmt.Sprintf("/?cfg=%s", url.QueryEscape(addr))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(addr))
	}
	fmt.Fprintf(w, "</ul>\n")

	if len(h.orphans) == 0 {
		return nil
	}

	fmt.Fprintf(w, "<h3>Orphans</h3>\n")
	fmt.Fprintf(w, "<p>These configs are not directly associated with a build.</p>\n")
	fmt.Fprintf(w, "<ul>\n")
	for _, addr := range h.orphans {
		href := fmt.Sprintf("/?cfg=%s", url.QueryEscape(addr))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(addr))
	}
	fmt.Fprintf(w, "</ul>\n")

	return nil
}

func (h *handler) renderConstraints(w http.ResponseWriter) error {
	defer boilerplate(w)()

	fmt.Fprintf(w, "<h2>Constraints</h2>\n")
	fmt.Fprintf(w, "<p>Every packages entry in apko_config.config_contents will show up here.</p>\n")
	fmt.Fprintf(w, "<p>This will include most locked constraints as well thanks to dev variants.</p>\n")
	fmt.Fprintf(w, "<ul>\n")
	for _, pkg := range slices.Sorted(maps.Keys(h.byConstraint)) {
		href := fmt.Sprintf("/?constraint=%s", url.QueryEscape(pkg))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(pkg))
	}
	fmt.Fprintf(w, "</ul>\n")

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
	fmt.Fprintf(w, "<h1><a href=%q>tfimages</a></h1>\n", "/")

	return func() {
		fmt.Fprintf(w, "</body>\n")
		fmt.Fprintf(w, "</html>\n")
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
			repoByAddr:   map[string]string{},
			configs:      map[string]*imageConfig{},
			byRepo:       map[string]map[string]*imageBuild{},
			byPackage:    map[string]map[string]*imageBuild{},
			byConstraint: map[string]map[string]*imageConfig{},
		}

		log.Printf("walking planned values")
		if err := h.walkModules(p.PlannedValues.RootModule); err != nil {
			return err
		}
		hs = append(hs, h)
	}

	lhs, rhs := hs[0], hs[1]

	same := 0
	for repo, lByAddr := range lhs.byRepo {
		if err := ctx.Err(); err != nil {
			return err
		}

		rByAddr := rhs.byRepo[repo]

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
