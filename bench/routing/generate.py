#!/usr/bin/env python3
"""Deterministic routing inputs; no framework installation or external packages."""

import argparse
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path
import random


class Contract(str, Enum):
    EXACT = "exact"
    SEGMENT_PREFIX = "segment_prefix"


class Method(str, Enum):
    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    ANY = "ANY"


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    templates: tuple  # (Method, normalized route template)
    sources: tuple = ()
    features: tuple = ()
    max_routes: int = 4096


G, P, D = Method.GET, Method.POST, Method.DELETE
PROFILES = (
    Profile("root_only", "单个根路由；直接方法分派候选", ((Method.ANY, "/"),), max_routes=1),
    Profile("tiny_static", "完全静态短地址；1/2/4/8 路由的直接比较基线",
            tuple((G, path) for path in ("/health", "/ready", "/live", "/metrics",
                                        "/index.html", "/robots.txt", "/favicon.ico", "/version")),
            features=("fixed_literal_addresses",), max_routes=8),
    Profile("flat_static", "健康检查/内部接口形态；短路径、根节点高扇出",
            ((G, "/{r}"),)),
    Profile("prefix_collision", "分段边界、相似前缀、嵌套前缀",
            ((G, "/{r}"), (G, "/{r}x"), (G, "/{r}/v1"))),
    Profile("cdn_assets", "CDN/静态资源：后缀、内容哈希、较长路径",
            ((G, "/assets/{r}/chunks/application.8e52194acff031d7.js"),
             (G, "/media/{r}/thumbnails/2026/09/banner.webp"))),
    Profile("shared_prefix", "长公共前缀；压缩路径与比较分支压力",
            ((G, "/internal/platform/production/control/services/{r}/status"),)),
    Profile("saas_gateway", "SaaS 网关：版本、资源、管理端、Webhook",
            ((G, "/api/v1/{r}"), (P, "/api/v1/{r}"),
             (G, "/admin/{r}"), (P, "/webhooks/{r}"))),
    Profile("saas_tenant", "SaaS 应用：租户、项目、成员、多方法",
            ((G, "/api/v1/tenants/:tenant/{r}"),
             (P, "/api/v1/tenants/:tenant/{r}"),
             (G, "/api/v1/tenants/:tenant/{r}/:id"),
             (D, "/api/v1/tenants/:tenant/{r}/:id")), features=("parameters",)),
    Profile("internet_gateway", "大型互联网合成网关：多服务、多版本、横向扇出",
            ((G, "/{r}/v1/search"), (P, "/{r}/v2/events"),
             (G, "/{r}/v1/feed"), (P, "/{r}/v2/checkout"))),
    Profile("internet_resources", "大型互联网合成 API：用户、内容、评论、对象资源",
            ((G, "/api/v1/{r}/:id/comments/:comment"),
             (P, "/api/v2/{r}/:id/reactions"),
             (G, "/storage/{r}/:bucket/:object")), features=("parameters",)),
    Profile("php_laravel", "Laravel 风格：资源、嵌套资源、管理分组",
            ((G, "/api/{r}"), (P, "/api/{r}"), (G, "/api/{r}/:id"),
             (G, "/admin/{r}/:id/edit")),
            ("https://laravel.com/docs/12.x/routing",), ("parameters",)),
    Profile("php_symfony", "Symfony 风格：语言前缀、slug、管理端",
            ((G, "/:locale/{r}/:slug"), (G, "/admin/{r}/new"),
             (P, "/admin/{r}/:id")),
            ("https://symfony.com/doc/current/routing.html",), ("parameters",)),
    Profile("php_wordpress", "WordPress/CMS 风格：REST namespace 和脚本入口",
            ((G, "/wp-json/wp/v2/{r}"), (G, "/wp-json/wp/v2/{r}/:id"),
             (P, "/plugins/{r}/index.php")),
            ("https://developer.wordpress.org/rest-api/reference/",), ("parameters", "suffix")),
    Profile("java_spring", "Spring MVC 风格：版本、资源、动作、业务嵌套",
            ((G, "/api/v1/{r}"), (P, "/api/v1/{r}"),
             (G, "/api/v1/{r}/:id"), (P, "/api/v1/{r}/:id/approve")),
            ("https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-requestmapping.html",),
            ("parameters",)),
    Profile("java_legacy", "传统 Java 网关形态：深层 context path、.do/.action 后缀",
            ((P, "/enterprise/portal/{r}/submit.do"),
             (G, "/enterprise/portal/{r}/list.action"))),
    Profile("ruby_rails", "Rails 风格：REST 七动作的路径/方法形态、嵌套资源",
            ((G, "/{r}"), (P, "/{r}"), (G, "/{r}/new"),
             (G, "/{r}/:id"), (G, "/{r}/:id/edit"),
             (Method.PATCH, "/{r}/:id"), (D, "/{r}/:id"),
             (G, "/{r}/:id/comments/:comment")),
            ("https://guides.rubyonrails.org/routing.html",), ("parameters", "static_parameter_overlap")),
    Profile("go_serve_mux", "Go ServeMux 风格：方法+资源，静态与参数交叉",
            ((G, "/{r}/latest"), (G, "/{r}/:id"), (P, "/{r}")),
            ("https://go.dev/blog/routing-enhancements",), ("parameters", "static_parameter_overlap")),
    Profile("python_django", "Django 风格：尾斜杠、年月归档、多级 include",
            ((G, "/{r}/:year/:month/"), (G, "/{r}/:year/:month/:slug/"),
             (P, "/admin/{r}/:id/change/")),
            ("https://docs.djangoproject.com/en/5.2/topics/http/urls/",), ("parameters", "trailing_slash")),
    Profile("python_fastapi", "FastAPI 风格：固定 me 路径、ID 参数、多方法",
            ((G, "/{r}/me"), (G, "/{r}/:id"), (P, "/{r}")),
            ("https://fastapi.tiangolo.com/tutorial/path-params/",), ("parameters", "static_parameter_overlap")),
    Profile("python_flask", "Flask 风格：简短 endpoint、用户名、文章 slug",
            ((G, "/{r}/login"), (P, "/{r}/login"),
             (G, "/{r}/users/:name"), (G, "/{r}/posts/:slug")),
            ("https://flask.palletsprojects.com/en/stable/quickstart/#routing",), ("parameters",)),
)
PROFILE_BY_NAME = {p.name: p for p in PROFILES}
RESOURCE_NAMES = ("projects", "users", "orders", "products", "teams", "messages",
                  "payments", "search", "media", "inventory", "sessions", "audit")
SIZES = (1, 2, 4, 8, 16, 32, 64, 128)


def canonical(target):
    """Corpus contract: strip query/fragment and outer slash runs; no decoding."""
    return target.split("?", 1)[0].split("#", 1)[0].strip("/")


def parts(path):
    value = canonical(path)
    return value.split("/") if value else []


def route_precedence(route, specificity, method, declaration_index):
    """Return the corpus dispatch precedence for one matching route.

    A deeper match wins before literal segments are compared.  The final
    tie-break uses the route's declaration position; route IDs are payload
    identifiers and do not define dispatch order.
    """
    return (len(parts(route["path"])), tuple(specificity),
            route["method"] == method if method is not None else route["method"] != Method.ANY,
            -declaration_index)


def reference_match(routes, method, target, contract):
    """Deliberately simple oracle, never used to time a candidate implementation.

    Literal segment before parameter, deeper terminal before its ancestor,
    specific method before ANY at the same terminal, then declaration order.
    This is the corpus contract, NOT an emulator for framework dispatch.
    """
    request = parts(target)
    best_key, best = None, None
    for declaration_index, route in enumerate(routes):
        if route["method"] not in (method, Method.ANY):
            continue
        pattern = parts(route["path"])
        if len(request) < len(pattern):
            continue
        if contract == Contract.EXACT and len(request) != len(pattern):
            continue
        captures, specificity = {}, []
        for expected, actual in zip(pattern, request):
            if expected.startswith(":"):
                if not actual:
                    break
                captures[expected[1:]] = actual
                specificity.append(0)
            elif expected == actual:
                specificity.append(1)
            else:
                break
        else:
            key = route_precedence(route, specificity, method, declaration_index)
            if best_key is None or key > best_key:
                best_key = key
                best = {"route_id": route["id"], "captures": captures}
    return best


def resource(index):
    stem = RESOURCE_NAMES[index % len(RESOURCE_NAMES)]
    return stem if index < len(RESOURCE_NAMES) else f"{stem}-{index // len(RESOURCE_NAMES):04d}"


def routes_for(profile, count):
    if count < 1 or count > 4096:
        raise ValueError("route count must be between 1 and 4096")
    if count > profile.max_routes:
        raise ValueError(f"{profile.name} has at most {profile.max_routes} distinct routes")
    routes = []
    for index in range(count):
        method, template = profile.templates[index % len(profile.templates)]
        path = template.format(r=resource(index // len(profile.templates)))
        routes.append({"id": index, "method": method, "path": path})
    return routes


def concrete(path, index):
    values = {"tenant": "acme", "id": str(10000 + index), "comment": "42",
              "locale": "en", "slug": "routing-guide", "year": "2026", "month": "09",
              "bucket": "images", "object": "avatar.png", "name": "alice"}
    return "/" + "/".join(values.get(s[1:], "item") if s.startswith(":") else s
                           for s in parts(path))


def case_for(profile, count, contract, seed):
    routes = routes_for(profile, count)
    # At stress scales sample endpoints explicitly; report coverage rather than
    # pretending that a short trace uniformly exercises thousands of routes.
    sampled = sorted(set(range(count)) if count <= 128 else
                     {0, count // 2, count - 1} |
                     set(random.Random(seed).sample(range(count), 61)))
    probes = []

    def add(tag, method, target, observation=False):
        probes.append({"tag": tag, "method": method, "target": target,
                       "canonical_path": canonical(target),
                       "check": "observe" if observation else "assert",
                       "expected": None if observation else
                           reference_match(routes, method, target, contract)})

    for index in sampled:
        route = routes[index]
        path = concrete(route["path"], index)
        method = route["method"] if route["method"] != Method.ANY else Method.GET
        add("endpoint", method, path)
        add("query", method, path + "?page=2&filter=active")
        add("descendant", method, path.rstrip("/") + "/details")
        # A suffix can still match a parameter. Compute the result; don't
        # mislabel every mutated target as a miss.
        add("segment_suffix", method, path.rstrip("/") + "xyz")
        add("head", Method.HEAD, path)
        add("options", Method.OPTIONS, path)
    add("unregistered", Method.GET, "/__unregistered__/no-route")
    add("root", Method.GET, "/")
    anchor = concrete(routes[0]["path"], 0)
    add("trailing_slash", Method.GET, anchor.rstrip("/") + "/")
    # Normalization belongs to an independent protocol/dispatch audit.
    for target in ("//" + anchor.lstrip("/"), anchor + "//child",
                   anchor + "/%2F", anchor + "/%2e%2e", anchor + "/../child",
                   anchor + "/%E4%B8%AD%E6%96%87", anchor + "/" + "x" * 2048):
        add("normalization_or_length", Method.GET, target, observation=True)
    asserted = [i for i, probe in enumerate(probes) if probe["check"] == "assert"]
    endpoints = [i for i in asserted if probes[i]["tag"] == "endpoint"]
    misses = [i for i in asserted if probes[i]["expected"] is None]
    rng = random.Random(seed)
    # These are index traces, not timings. All candidates consume identical input.
    traces = {
        "first": [endpoints[0]] * 1024,
        "middle": [endpoints[len(endpoints) // 2]] * 1024,
        "last": [endpoints[-1]] * 1024,
        "uniform_sampled_endpoints": [rng.choice(endpoints) for _ in range(1024)],
        "hot_first_80_percent": [endpoints[0] if i % 5 else rng.choice(endpoints)
                                  for i in range(1024)],
        "mixed_asserted": [rng.choice(asserted) for _ in range(1024)],
    }
    if misses:
        traces["miss_only"] = [rng.choice(misses) for _ in range(1024)]
    return {
        "name": profile.name, "description": profile.description,
        "provenance": "synthetic", "sources": profile.sources, "features": profile.features,
        "contract": contract, "route_count": count, "sampled_route_ids": sampled,
        "execution_modes": (["local_static", "proxy"] if profile.name in ("root_only", "tiny_static")
                            else ["proxy"]),
        "static_response_bytes": [0, 16, 1024, 65536] if profile.name in ("root_only", "tiny_static") else [],
        "rut_route_capacity": "within_128" if count <= 128 else "exceeds_128",
        "candidate_constraints": {
            "art": ("ineligible_parameters" if "parameters" in profile.features else
                    "requires_exact_terminal_guard" if contract == Contract.EXACT else
                    "segment_prefix_mode"),
            "exact_hash": "requires_exact_contract_and_no_parameters",
            "framework_compatibility": "not_claimed",
        },
        "routes": routes, "probes": probes, "traces": traces,
    }


def boundary_case(contract):
    routes = [{"id": i, "method": method, "path": path} for i, (method, path) in enumerate((
        (Method.ANY, "/"), (G, "/api"), (G, "/api/v1"), (G, "/apix"),
        (P, "/api"), (G, "/users/new"), (G, "/users/:id")))]
    probes = []
    for method, target in ((G, "/apifoo"), (G, "/api/v1x"), (G, "/apix"),
                           (G, "/api/v1/users"), (P, "/api"), (Method.HEAD, "/api"),
                           (G, "/users/new"), (G, "/users/42"), (G, "/api?q=1")):
        probes.append({"method": method, "target": target,
                       "expected": reference_match(routes, method, target, contract)})
    return {"name": "boundary_and_precedence", "contract": contract,
            "routes": routes, "probes": probes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--profiles", nargs="+", choices=tuple(PROFILE_BY_NAME))
    parser.add_argument("--sizes", nargs="+", type=int, default=SIZES)
    parser.add_argument("--contracts", nargs="+", choices=[c.value for c in Contract],
                        default=[c.value for c in Contract])
    parser.add_argument("--seed", type=int, default=20260928)
    parser.add_argument("--output", type=Path, default=Path("build/routing-corpus"))
    args = parser.parse_args()
    if args.list:
        for profile in PROFILES:
            print(f"{profile.name:22} {profile.description}")
        return
    if any(n < 1 or n > 4096 for n in args.sizes):
        parser.error("--sizes values must be between 1 and 4096")
    args.output.mkdir(parents=True, exist_ok=True)
    entries = []
    excluded_sizes = []
    for name in dict.fromkeys(args.profiles or PROFILE_BY_NAME):
        profile = PROFILE_BY_NAME[name]
        for count in ([1] if name == "root_only" else sorted(set(args.sizes))):
            if count > profile.max_routes:
                excluded_sizes.append({"profile": name, "size": count,
                                       "reason": f"fixed shape has at most {profile.max_routes} routes"})
                continue
            for contract in map(Contract, dict.fromkeys(args.contracts)):
                data = case_for(profile, count, contract, args.seed)
                raw = (json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
                filename = f"{name}-{count}-{contract.value}.json"
                (args.output / filename).write_bytes(raw)
                entries.append({"file": filename, "sha256": hashlib.sha256(raw).hexdigest(),
                                "routes": count, "probes": len(data["probes"]),
                                "contract": contract.value,
                                "execution_modes": data["execution_modes"],
                                "response_bytes": data["static_response_bytes"] or [16],
                                "asserted_probes": sum(p["check"] == "assert" for p in data["probes"])})
    for contract in map(Contract, dict.fromkeys(args.contracts)):
        data = boundary_case(contract)
        filename = f"boundaries-{contract.value}.json"
        raw = (json.dumps(data, indent=2) + "\n").encode()
        (args.output / filename).write_bytes(raw)
        entries.append({"file": filename, "sha256": hashlib.sha256(raw).hexdigest(),
                        "routes": len(data["routes"]), "probes": len(data["probes"]),
                        "contract": contract.value,
                        "execution_modes": ["proxy"], "response_bytes": [16],
                        "asserted_probes": len(data["probes"])})
    manifest = {"schema_version": 1, "seed": args.seed, "cases": entries,
                "excluded_sizes": excluded_sizes,
                "note": "Synthetic workload corpus, not runtime benchmark results."}
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Generated {len(entries)} cases in {args.output}")


if __name__ == "__main__":
    main()
