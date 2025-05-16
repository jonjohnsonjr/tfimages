package tfimages

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"chainguard.dev/apko/pkg/build/types"
	tfjson "github.com/hashicorp/terraform-json"
	"gopkg.in/yaml.v2"
)

func New(p tfjson.Plan, root string) (*Handler, error) {
	h := &Handler{
		root:         root,
		repoByAddr:   map[string]string{},
		configs:      map[string]*imageConfig{},
		byRepo:       map[string]map[string]*imageBuild{},
		builds:       map[string]*imageBuild{},
		byPackage:    map[string]map[string]*imageBuild{},
		byConstraint: map[string]map[string]*imageConfig{},
	}

	// Do this once just cause.
	if apkoConfig, ok := p.Config.ProviderConfigs["apko"]; ok {
		if exprs, ok := apkoConfig.Expressions["extra_packages"]; ok {
			cv := exprs.ConstantValue
			list, ok := cv.([]any)
			if !ok {
				return nil, fmt.Errorf("extra_packages is a %T", cv)
			}

			for _, el := range list {
				if pkg, ok := el.(string); ok {
					h.extraPackages = append(h.extraPackages, pkg)
				} else {
					return nil, fmt.Errorf("extra_packages element is a %T", el)
				}
			}
		}
	}

	if err := h.Index(p); err != nil {
		return nil, err
	}

	return h, nil
}

func (h *Handler) Index(p tfjson.Plan) error {
	if p.PlannedValues != nil && p.PlannedValues.RootModule != nil {
		log.Printf("walking planned values")
		if err := h.walkModules(p.PlannedValues.RootModule); err != nil {
			return err
		}
	}

	if p.PriorState != nil && p.PriorState.Values != nil && p.PriorState.Values.RootModule != nil {
		log.Printf("walking prior state")
		if err := h.walkModules(p.PriorState.Values.RootModule); err != nil {
			return err
		}
	}

	log.Printf("%d configs, %d builds", len(h.configs), len(h.builds))

	h.versionGetters = make([]string, 0, max(0, len(h.configs)-len(h.builds)))
	h.orphans = make([]string, 0, max(0, len(h.configs)-len(h.builds)))

	for addr, cfg := range h.configs {
		buildAddr := strings.ReplaceAll(addr, "data.apko_config", "apko_build")
		if _, ok := h.builds[buildAddr]; !ok {
			if len(cfg.config.Contents.Packages) == 1 {
				// TODO: This conditional isn't really sufficient.
				h.versionGetters = append(h.versionGetters, addr)
			} else {
				h.orphans = append(h.orphans, addr)
			}
		}
	}

	slices.Sort(h.versionGetters)
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

	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.String())
	if err := h.handle(w, r); err != nil {
		log.Printf("error: %s", err)
	}
}

type Handler struct {
	root string

	configs        map[string]*imageConfig
	byConstraint   map[string]map[string]*imageConfig
	builds         map[string]*imageBuild
	byRepo         map[string]map[string]*imageBuild
	byPackage      map[string]map[string]*imageBuild
	repoByAddr     map[string]string
	orphans        []string
	versionGetters []string
	duplicates     map[string]map[string]any

	extraPackages []string
}

func (h *Handler) ref(format string, a ...any) string {
	return fmt.Sprintf("%s/%s", h.root, fmt.Sprintf(format, a...))
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

func (h *Handler) walkModules(m *tfjson.StateModule) error {
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

func (h *Handler) build(repo, addr string, ic *types.ImageConfiguration) {
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

func (h *Handler) config(addr string, ic *types.ImageConfiguration) {
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

func (h *Handler) renderLanding(w http.ResponseWriter) {
	fmt.Fprintf(w, "<p><a href=%q>Images (%d)</a></p>\n", h.ref("images"), len(h.byRepo))
	fmt.Fprintf(w, "<p><a href=%q>Builds (%d)</a></p>\n", h.ref("builds"), len(h.builds))
	fmt.Fprintf(w, "<p><a href=%q>Packages (%d)</a></p>\n", h.ref("packages"), len(h.byPackage))
	fmt.Fprintf(w, "<p><a href=%q>Configs (%d)</a></p>\n", h.ref("configs"), len(h.configs))
	fmt.Fprintf(w, "<p><a href=%q>Constraints (%d)</a></p>\n", h.ref("constraints"), len(h.byConstraint))
}

func (h *Handler) match(r *http.Request, p string) bool {
	return r.URL.Path == h.root+"/"+p
}

func (h *Handler) handle(w http.ResponseWriter, r *http.Request) error {
	if h.match(r, "images.json") {
		return h.renderImagesJSON(w)
	}

	if h.match(r, "images") {
		return h.renderImages(w)
	}

	if h.match(r, "builds") {
		return h.renderBuilds(w)
	}

	if h.match(r, "packages") {
		return h.renderPackages(w)
	}

	if h.match(r, "configs") {
		return h.renderConfigs(w)
	}

	if h.match(r, "constraints") {
		return h.renderConstraints(w)
	}

	if !h.match(r, "") {
		return errorf(w, "unexpected path: %q", r.URL.Path)
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

func (h *Handler) renderAddr(w http.ResponseWriter, repo, addr string) error {
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
		href := h.ref("?cfg=%s", url.QueryEscape(cfgAddr))
		fmt.Fprintf(w, "<a href=%q>%s</a>\n", href, html.EscapeString(cfgAddr))
	}

	fmt.Fprintf(w, "<pre>\n")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(h.linkify(*build.config, "pkg")); err != nil {
		return errorf(w, "encode: %w", err)
	}
	fmt.Fprintf(w, "</pre>\n")

	return nil
}

func (h *Handler) linkify(ic types.ImageConfiguration, page string) types.ImageConfiguration {
	packages := slices.Clone(ic.Contents.Packages)
	for i, pkg := range packages {
		href := h.ref("?%s=%s", page, url.QueryEscape(pkg))
		packages[i] = fmt.Sprintf("<a href=%s>%s</a>", href, html.EscapeString(pkg)) // TODO: Why do we have to use %s for href here???
	}
	ic.Contents.Packages = packages
	return ic
}

func (h *Handler) renderRepo(w http.ResponseWriter, repo string) error {
	fmt.Fprintf(w, "<h2>%s</h2>\n", repo)
	fmt.Fprintf(w, "<ul>\n")
	byAddr, ok := h.byRepo[repo]
	if !ok {
		return errorf(w, "no repo %q", repo)
	}
	for _, addr := range slices.Sorted(maps.Keys(byAddr)) {
		href := h.ref("?repo=%s&addr=%s", url.QueryEscape(repo), url.QueryEscape(addr))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(addr))
	}
	fmt.Fprintf(w, "</ul>\n")

	return nil
}

func (h *Handler) renderPkgRepo(w http.ResponseWriter, pkg, repo string) error {
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
		href := h.ref("?repo=%s&addr=%s", repo, url.QueryEscape(addr))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(addr))
	}
	fmt.Fprintf(w, "</ul>\n")

	return nil
}

func (h *Handler) renderPkg(w http.ResponseWriter, pkg string) error {
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
		href := h.ref("?repo=%s&pkg=%s", url.QueryEscape(repo), url.QueryEscape(pkg))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(repo))
	}
	fmt.Fprintf(w, "</ul>\n")

	return nil
}

func (h *Handler) renderCfg(w http.ResponseWriter, addr string) error {
	config, ok := h.configs[addr]
	if !ok {
		return errorf(w, "no addr %q", addr)
	}

	fmt.Fprintf(w, "<h2>%s</h2>\n", addr)

	cfg := *config.config

	buildAddr := strings.ReplaceAll(addr, "data.apko_config", "apko_build")
	if build, ok := h.builds[buildAddr]; ok {
		href := h.ref("?addr=%s", url.QueryEscape(buildAddr))
		fmt.Fprintf(w, "<a href=%q>%s</a>\n", href, html.EscapeString(buildAddr))

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
	if err := enc.Encode(h.linkify(cfg, "constraint")); err != nil {
		return errorf(w, "encode: %w", err)
	}
	fmt.Fprintf(w, "</pre>\n")

	return nil
}

func (h *Handler) renderConstraint(w http.ResponseWriter, constraint string) error {
	fmt.Fprintf(w, "<h2>Configs containing %s</h2>\n", constraint)
	fmt.Fprintf(w, "<p>This is every apko_config.config_contents with a packages field containing %q.</p>\n", constraint)
	fmt.Fprintf(w, "<ul>\n")
	fromConstraint, ok := h.byConstraint[constraint]
	if !ok {
		return errorf(w, "no constraint %q", constraint)
	}

	for _, addr := range slices.Sorted(maps.Keys(fromConstraint)) {
		href := h.ref("?cfg=%s", url.QueryEscape(addr))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(addr))
	}
	fmt.Fprintf(w, "</ul>\n")

	return nil
}

func (h *Handler) renderImages(w http.ResponseWriter) error {
	fmt.Fprintf(w, "<h2>Images (%d)</h2>\n", len(h.byRepo))
	fmt.Fprint(w, "<a href=./images.json>Images JSON</a>\n")

	fmt.Fprintf(w, "<p>This is every apko_build grouped by repo.</p>\n")
	fmt.Fprintf(w, "<ul>\n")
	for _, repo := range slices.Sorted(maps.Keys(h.byRepo)) {
		href := h.ref("?repo=%s", url.QueryEscape(repo))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(repo))
	}
	fmt.Fprintf(w, "</ul>\n")

	return nil
}

func (h *Handler) renderImagesJSON(w http.ResponseWriter) error {

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// write slices.Sorted(maps.Keys(h.byRepo)) to json
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(slices.Sorted(maps.Keys(h.byRepo))); err != nil {
		return errorf(w, "encode: %w", err)
	}
	return nil
}

func (h *Handler) renderPackages(w http.ResponseWriter) error {
	fmt.Fprintf(w, "<h2>Packages (%d)</h2>\n", len(h.byPackage))
	fmt.Fprintf(w, "<details>")
	fmt.Fprintf(w, "<summary>Every packages entry in a apko_build.config will show up here.</summary>\n")
	fmt.Fprintf(w, "<ul>\n")
	for _, pkg := range slices.Sorted(maps.Keys(h.byPackage)) {
		href := h.ref("?pkg=%s", url.QueryEscape(pkg))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(pkg))
	}
	fmt.Fprintf(w, "</ul>\n")
	fmt.Fprintf(w, "</details>")

	if len(h.duplicates) != 0 {
		fmt.Fprintf(w, "<h3>Duplicates (%d)</h3>\n", len(h.duplicates))
		fmt.Fprintf(w, "<details>")
		fmt.Fprintf(w, "<summary>These packages have more than one version somewhere.</summary>\n")
		fmt.Fprintf(w, "<ul>\n")
		for _, pkg := range slices.Sorted(maps.Keys(h.duplicates)) {
			fmt.Fprintf(w, "<li>%s</li>\n", pkg)
			fmt.Fprintf(w, "<ul>\n")
			for v := range h.duplicates[pkg] {
				href := h.ref("?pkg=%s", url.QueryEscape(pkg+"="+v))
				fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(v))
			}
			fmt.Fprintf(w, "</ul>\n")
		}
		fmt.Fprintf(w, "</ul>\n")
		fmt.Fprintf(w, "</details>")
	}

	return nil
}

func (h *Handler) renderBuilds(w http.ResponseWriter) error {
	fmt.Fprintf(w, "<h2>Builds (%d)</h2>\n", len(h.builds))
	fmt.Fprintf(w, "<p>These are the apko_build.config contents for every build.</p>\n")
	fmt.Fprintf(w, "<ul>\n")
	for _, addr := range slices.Sorted(maps.Keys(h.builds)) {
		href := h.ref("?addr=%s", url.QueryEscape(addr))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(addr))
	}
	fmt.Fprintf(w, "</ul>\n")

	return nil
}

func (h *Handler) renderConfigs(w http.ResponseWriter) error {
	fmt.Fprintf(w, "<h2>Configs (%d)</h2>\n", len(h.configs))
	fmt.Fprintf(w, "<details>")
	fmt.Fprintf(w, "<summary>These are the config_contents of every apko_config in the plan's prior_state.</summary>\n")
	fmt.Fprintf(w, "<ul>\n")
	for _, addr := range slices.Sorted(maps.Keys(h.configs)) {
		href := h.ref("?cfg=%s", url.QueryEscape(addr))
		fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(addr))
	}
	fmt.Fprintf(w, "</ul>\n")
	fmt.Fprintf(w, "</details>")

	if len(h.versionGetters) != 0 {
		fmt.Fprintf(w, "<h3>Version Getters (%d)</h3>\n", len(h.versionGetters))
		fmt.Fprintf(w, "<details>")
		fmt.Fprintf(w, "<summary>These configs are not directly associated with a build and heuristically look like version getters.</summary>\n")
		fmt.Fprintf(w, "<ul>\n")
		for _, addr := range h.versionGetters {
			href := h.ref("?cfg=%s", url.QueryEscape(addr))
			fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(addr))
		}
		fmt.Fprintf(w, "</ul>\n")
		fmt.Fprintf(w, "</details>")
	}

	if len(h.orphans) != 0 {
		fmt.Fprintf(w, "<h3>Orphans (%d)</h3>\n", len(h.orphans))
		fmt.Fprintf(w, "<details>")
		fmt.Fprintf(w, "<summary>These configs are not directly associated with a build.</summary>\n")
		fmt.Fprintf(w, "<ul>\n")
		for _, addr := range h.orphans {
			href := h.ref("?cfg=%s", url.QueryEscape(addr))
			fmt.Fprintf(w, "<li><a href=%q>%s</a></li>\n", href, html.EscapeString(addr))
		}
		fmt.Fprintf(w, "</ul>\n")
		fmt.Fprintf(w, "</details>")
	}

	return nil
}

func (h *Handler) renderConstraints(w http.ResponseWriter) error {
	fmt.Fprintf(w, "<h2>Constraints (%d)</h2>\n", len(h.byConstraint))
	fmt.Fprintf(w, "<p>Every packages entry in apko_config.config_contents will show up here.</p>\n")
	fmt.Fprintf(w, "<p>This will include most locked constraints as well thanks to dev variants.</p>\n")
	fmt.Fprintf(w, "<ul>\n")
	for _, pkg := range slices.Sorted(maps.Keys(h.byConstraint)) {
		href := h.ref("?constraint=%s", url.QueryEscape(pkg))
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
