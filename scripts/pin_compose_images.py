#!/usr/bin/env python3
"""Pin every third-party image in docker-compose.yml to the digest its tag points at.

    python scripts/pin_compose_images.py           # rewrite docker-compose.yml
    python scripts/pin_compose_images.py --check    # verify only: exit 1 on a missing digest

Why: `image: postgres:16-alpine` is a moving target (the tag can be re-pushed), while
`image: postgres:16-alpine@sha256:...` is the exact bytes we tested. Docker Hub serves the
tag metadata anonymously and the digest is then verified against the registry manifest
endpoint - the same lookup `docker pull` performs - so a typo, a removed tag or a stale
pointer never lands in the file.

Images built by this repository have a `build:` block instead of `image:`, so they are not
touched here (their base images are pinned in the Dockerfiles). Re-run without --check after
an intentional upgrade to move the pins forward.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import urllib.error
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[1]
COMPOSE = REPO / "docker-compose.yml"
# matches "  image: postgres:16-alpine" (optionally "- image: ...") and keeps any trailing comment
IMAGE_RE = re.compile(r"^(?P<head>\s*(?:-\s+)?image:\s*)(?P<ref>\S+)(?P<tail>.*)$")
ACCEPT = ", ".join((
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
))
HUB = "https://hub.docker.com/v2/repositories"
UA = {"User-Agent": "smartsecure-pin-images"}


def _request(url: str, headers: dict[str, str] | None = None, method: str = "GET"):
    req = urllib.request.Request(url, headers=headers or UA)
    req.get_method = lambda: method
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.status, response.read(), dict(response.headers)


def hub_repo(ref: str) -> str:
    """`postgres:16-alpine` -> `library/postgres`; `jasonish/suricata:7.0.8` -> unchanged."""
    name = ref.split("@", 1)[0].rsplit(":", 1)[0]
    name = name.removeprefix("docker.io/").removeprefix("index.docker.io/")
    return name if "/" in name else f"library/{name}"


def hub_digest(repo: str, tag: str) -> str | None:
    """The digest that tag currently points at, or None when the tag does not exist."""
    try:
        _, body, _ = _request(f"{HUB}/{repo}/tags/{tag}")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    return json.loads(body)["digest"]


def digest_is_fetchable(repo: str, digest: str) -> bool:
    """True when the registry can serve that digest, i.e. `docker pull` would work."""
    _, body, _ = _request("https://auth.docker.io/token?service=registry.docker.io"
                          f"&scope=repository:{repo}:pull")
    token = json.loads(body)["token"]
    status, _, _ = _request(f"https://registry-1.docker.io/v2/{repo}/manifests/{digest}",
                            {**UA, "Authorization": f"Bearer {token}", "Accept": ACCEPT},
                            method="HEAD")
    return status == 200


def pinned(ref: str, tag: str, digest: str) -> str:
    """`repo:tag@digest`, keeping the tag so the file stays readable."""
    name = ref.split("@", 1)[0].rsplit(":", 1)[0]
    return f"{name}:{tag}@{digest}"


def read_lines(path: pathlib.Path) -> list[str]:
    """Read keeping the file's own line endings (Windows must not rewrite them)."""
    with open(path, encoding="utf-8", newline="") as handle:
        return handle.readlines()


def write_lines(path: pathlib.Path, lines: list[str]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.writelines(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="only verify that every image carries a fetchable digest")
    args = parser.parse_args()

    lines = read_lines(COMPOSE)
    changed, problems, images = [], [], 0
    for number, line in enumerate(lines):
        match = IMAGE_RE.match(line.rstrip("\n"))
        if match is None or "${" in match["ref"]:
            continue
        images += 1
        ref, _, current = match["ref"].partition("@")
        if ":" not in ref:
            problems.append(f"{COMPOSE.name}:{number + 1}: {ref} has no tag")
            continue
        name, tag = ref.rsplit(":", 1)
        repo = hub_repo(ref)
        if args.check:
            if not current:
                problems.append(f"{COMPOSE.name}:{number + 1}: {name}:{tag} is not pinned")
            elif not digest_is_fetchable(repo, current):
                problems.append(f"{COMPOSE.name}:{number + 1}: {name}:{tag}@{current} "
                                "is not fetchable")
            continue
        digest = hub_digest(repo, tag)
        if digest is None:
            problems.append(f"{COMPOSE.name}:{number + 1}: {name}:{tag} does not exist upstream")
            continue
        if not digest_is_fetchable(repo, digest):
            problems.append(f"{COMPOSE.name}:{number + 1}: {name}:{tag} -> {digest} "
                            "cannot be fetched")
            continue
        if digest == current:
            print(f"ok      {name}:{tag}  (already {digest[:19]}...)")
            continue
        lines[number] = f"{match['head']}{pinned(ref, tag, digest)}{match['tail']}\n"
        changed.append(f"{name}:{tag} -> {digest}")
        print(f"pin     {name}:{tag}  {digest}")

    if args.check:
        for problem in problems:
            print(f"ERROR   {problem}")
        print(f"{images} third-party image(s) checked, {len(problems)} problem(s)")
        return 1 if problems else 0

    if problems:
        for problem in problems:
            print(f"ERROR   {problem}")
        return 1
    if changed:
        write_lines(COMPOSE, lines)
        print(f"\nwrote {COMPOSE.name}: {len(changed)} pin(s) updated")
    else:
        print(f"\n{COMPOSE.name} was already up to date ({images} image(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())