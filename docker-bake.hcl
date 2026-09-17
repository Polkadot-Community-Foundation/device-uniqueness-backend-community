# Build graph for THE service image.
#
# One target, because there is one image: every service and worker is a role of
# the single `dub` binary it holds (`--role <name>`, selected by the compose
# `command:` / chart `args:`). This replaced ten targets that differed only in
# which binary they copied — see docs/plans/active/one-image-one-binary.md.
#
#   docker buildx bake all                 # the image, local tag
#   IMAGE_REPO=ghcr.io/paritytech/device-uniqueness-backend IMAGE_TAG=$(git rev-parse HEAD) \
#     docker buildx bake --push all
#
# `IMAGE_REPO` is a full repository path, not a registry: the tag is appended
# directly. Keeping it as one value is what lets a registry change be a variable
# change — `ghcr.io/paritytech/device-uniqueness-backend`,
# `docker.io/paritytech/device-uniqueness-backend`, or a GAR
# `<location>-docker.pkg.dev/<project>/<repo>/device-uniqueness-backend` all fit.

variable "IMAGE_REPO" {
  # Local default keeps `docker buildx bake all` working with no environment.
  default = "device-uniqueness-backend"
}

variable "IMAGE_TAG" {
  default = "local"
}

# The People runtime the image targets: testnet or polkadot. Baked into
# the binary (vendored metadata, invite-tickets roles), so give images for
# different networks different tags.
variable "DUB_NETWORK" {
  default = "testnet"
}

# Cache refs are opt-in so a laptop build needs no registry. CI sets them to a
# registry-backed cache; a plain `docker buildx bake` ignores them.
variable "CACHE_FROM" { default = "" }
variable "CACHE_TO" { default = "" }

# The release lane pushes by DIGEST and joins the digests into one tagged
# manifest list afterwards. buildkit refuses to push a *tagged* ref by digest
# ("can't push tagged ref ... by digest"), so digest mode must clear `tags` and
# name the repo in the exporter instead.
variable "PUSH_BY_DIGEST" { default = "" }

function "digest_mode" {
  params = []
  result = PUSH_BY_DIGEST == "true"
}

function "tags_for" {
  params = []
  result = digest_mode() ? [] : ["${IMAGE_REPO}:${IMAGE_TAG}"]
}

function "output_for" {
  params = []
  result = digest_mode() ? ["type=image,name=${IMAGE_REPO},push-by-digest=true,name-canonical=true,push=true"] : []
}

function "cache_from" {
  params = []
  result = CACHE_FROM == "" ? [] : ["type=registry,ref=${CACHE_FROM}"]
}

function "cache_to" {
  params = []
  result = CACHE_TO == "" ? [] : ["type=registry,ref=${CACHE_TO},mode=max"]
}

target "_common" {
  context    = "."
  dockerfile = "Dockerfile"
  args       = { DUB_NETWORK = DUB_NETWORK }
  cache-from = cache_from()
  cache-to   = cache_to()
}

# The target name, the Dockerfile stage and the binary are all `dub`.
target "dub" {
  inherits = ["_common"]
  target   = "dub"
  tags     = tags_for()
  output   = output_for()
}

# The deployable set. Every compose service and chart workload runs this image
# with a different `--role`; scripts/verify_role_split.sh checks the roles they
# name against `dub --list-roles`.
group "all" {
  targets = ["dub"]
}

# Default for a bare `docker buildx bake`.
group "default" {
  targets = ["all"]
}
