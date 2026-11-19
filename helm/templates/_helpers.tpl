{{/*
Shared naming and labelling. One workload = one Deployment named after the
service, which is also its image repo, its Dockerfile stage, its bake target and
its compose service — the same string end to end, so a rename cannot half-land.
*/}}

{{- define "dub.labels" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/part-of: dub
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
dub.parity.io/env-id: {{ .root.Values.global.envId | quote }}
{{- end -}}

{{- define "dub.selectorLabels" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
{{- end -}}

{{/*
THE image: one repo, one tag, for every workload. What makes a workload that
service is its `--role` arg, not its image — so there is deliberately no
per-workload image or tag override.
*/}}
{{- define "dub.image" -}}
{{- $g := .root.Values.global -}}
{{- printf "%s:%s" $g.imageRepo $g.imageTag -}}
{{- end -}}

{{/*
The env block for a workload, assembled from three disjoint sources:
  1. globalEnv — keys inherited verbatim from global.env (paired flags live
     there so two workloads cannot disagree)
  2. env       — this workload's own literals
  3. secretKeys — pulled from this workload's Secret, never inlined
plus INVITER_ADDRESS, which is per-workload because an inviter owns a nonce
lane and must not be shared with another submitter.
*/}}
{{- define "dub.env" -}}
{{- $root := .root -}}
{{- $w := .workload -}}
{{- range $key := $w.globalEnv | default list }}
{{- $val := index $root.Values.global.env $key }}
{{- if kindIs "invalid" $val }}{{ fail (printf "%s: globalEnv names %s, which global.env does not define" $.name $key) }}{{ end }}
- name: {{ $key }}
  value: {{ $val | quote }}
{{- end }}
{{- if $w.inviter }}
- name: INVITER_ADDRESS
  value: {{ index $root.Values.global.inviters $w.inviter | quote }}
{{- end }}
{{- range $key, $val := $w.env | default dict }}
- name: {{ $key }}
  value: {{ $val | quote }}
{{- end }}
{{/* The path the key-file mount lands on, rendered ONLY when that mount exists.
     It was a literal in `env` once, which set the variable whether or not a
     volume backed it — and a path naming no file is a hard error in the
     service, not a fall back to the stub provider. Tying the two to one
     condition is what makes "no secret named" mean "unconfigured" again. */}}
{{- if and $w.keyFile $w.keyFile.secret $w.keyFile.envKey }}
- name: {{ $w.keyFile.envKey }}
  value: {{ printf "%s/%s" $w.keyFile.path $w.keyFile.fileName | quote }}
{{- end }}
{{- $present := index $root.Values.secrets $.name | default dict }}
{{- range $key := $w.secretKeys | default list }}
- name: {{ $key }}
  valueFrom:
    secretKeyRef:
      name: {{ $.name }}
      key: {{ $key }}
{{- end }}
{{- range $key := $w.optionalSecretKeys | default list }}
{{- if hasKey $present $key }}
- name: {{ $key }}
  valueFrom:
    secretKeyRef:
      name: {{ $.name }}
      key: {{ $key }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
The deployment invariants, enforced at RENDER time rather than in CI.

Each has a silent, expensive failure mode: a second writer racing nonces, two
workloads disagreeing about a paired flag, a plaintext secret in git history.
CI can be bypassed; `helm template` cannot — the deploy tooling renders this
chart every time, so a `fail` here is the last check that always runs.
*/}}
{{- define "dub.validate" -}}
{{- $g := .Values.global -}}

{{- if not $g.imageTag }}
{{- fail "global.imageTag is required — the promotion sets it; there is no default, because a defaulted tag deploys something nobody chose" }}
{{- end }}

{{/* The network the IMAGE was built for (DUB_NETWORK at build time), which
     decides which roles exist in it: `polkadot` builds have no invite-tickets
     roles at all, so a workload asking for one would crash-loop on an unknown
     --role. Release images carry it in the tag (`<tag>-<network>`). */}}
{{- $network := $g.network | default "" -}}
{{- if not (has $network (list "testnet" "polkadot")) }}
{{- fail (printf "global.network is %q — expected testnet or polkadot, matching the DUB_NETWORK the image was built with" $network) }}
{{- end }}
{{- if eq $network "polkadot" }}
{{- range $name := list "invite-tickets-api" "invite-tickets-pool" }}
{{- $w := index $.Values.workloads $name | default dict }}
{{- if $w.enabled }}
{{- fail (printf "%s is enabled but global.network is polkadot — that build has no invite-tickets roles. Set workloads.%s.enabled: false" $name $name) }}
{{- end }}
{{- end }}
{{- end }}

{{- if not $g.ingress.host }}
{{- fail "global.ingress.host is required — every environment is reachable only under its own hostname" }}
{{- end }}

{{- $enabled := dict -}}
{{- range $name, $w := .Values.workloads }}
{{- if $w.enabled }}{{ $_ := set $enabled $name $w }}{{ end }}
{{- end }}

{{/* The three processes that submit to a chain or advance a chain-facing queue.
     A LIST, not a per-workload flag: a flag can be unset in an overlay, and
     `{singleton: false, replicas: 3}` would then render three writers on one
     signing account with nothing to stop it. Membership is asserted in both
     directions below, so neither a missing flag nor a spurious one passes. */}}
{{- $singletons := list "device-attestation-chain-writer" "registration-queue" "invite-tickets-pool" -}}

{{/* Dev and placeholder credentials, rejected wherever a secret is set. The
     prefix of a secret cannot be asserted instead: deploy tooling that resolves
     `ref+vault://` does so before helm runs, so a correctly configured render
     sees the real value, not the reference. */}}
{{- $devSecrets := list "//Alice" "//Bob" "//Charlie" "//Dave" "//Eve" "TODO" "tbd" "changeme" -}}

{{/* ── Topology ─────────────────────────────────────────────────────────────

     A deployment renders the STANDARD topology (five per-service HTTP workloads)
     or the SMALL one (`all-in-one`, which serves all five surfaces in one
     process) — plus the three workers above, which belong to both. Never a mix.

     The small topology collapses the secret compartmentalisation the standard
     one enforces: one process holds JWT_ED25519_SECRET (mint any token),
     POC_HMAC_SECRET, the TURN credential secret and all three database URLs, in the same address
     space that serves the unauthenticated public search. That is a legitimate
     trade for a small deployment and a bad accident for anyone else, so it is
     gated on an explicit acknowledgement rather than on a workload being
     enabled. See "Deployment topologies" in docs/architecture.md. */}}
{{- $merged := list "all-in-one" -}}
{{- $perService := list "device-attestation-api" "username-indexer" "invite-tickets-api" "turn-api" "notify-relay" -}}
{{- $mergedOn := list -}}
{{- $perServiceOn := list -}}
{{- range $name, $w := $enabled }}
{{- if has $name $merged }}{{ $mergedOn = append $mergedOn $name }}{{ end }}
{{- if has $name $perService }}{{ $perServiceOn = append $perServiceOn $name }}{{ end }}
{{- end }}

{{- if and $mergedOn $perServiceOn }}
{{- fail (printf "both topologies are enabled: %v alongside %v. A mix pays the small topology's secret union while still running the compartmentalised services — enable one or the other (docs/architecture.md, Deployment topologies)" $mergedOn $perServiceOn) }}
{{- end }}

{{- if $mergedOn }}
{{- if not $g.allInOne }}
{{- fail "all-in-one is enabled but global.allInOne is unset — the small topology must be chosen deliberately, not inherited by copying a values file" }}
{{- end }}
{{- if not (eq (toString $g.allInOne.acknowledgedSecretUnion) "true") }}
{{- fail "all-in-one is enabled but global.allInOne.acknowledgedSecretUnion is not true. This topology puts JWT_ED25519_SECRET (mint any token), POC_HMAC_SECRET, the TURN credential secret and all three database URLs in ONE process with the unauthenticated public search endpoint. Read docs/architecture.md \"Deployment topologies\" and set it explicitly to accept that" }}
{{- end }}
{{- range $name := $perService }}
{{- if hasKey $.Values.secrets $name }}
{{- fail (printf "the small topology is enabled but secrets.%s is still populated — a per-service secret set left behind is a credential nobody is deploying and nobody is rotating" $name) }}
{{- end }}
{{- end }}
{{- end }}

{{/* Every workload, not just the enabled ones: a plaintext secret parked under a
     disabled workload is a secret in git that nobody is checking, and it goes
     live the day someone flips `enabled`. */}}
{{- range $name, $w := .Values.workloads }}

  {{- $must_be_single := has $name $singletons }}
  {{- if and $must_be_single (ne (int $w.replicas) 1) }}
  {{- fail (printf "%s is single-instance (one signer/advancer = one nonce lane) but replicas=%v" $name $w.replicas) }}
  {{- end }}
  {{- if and $must_be_single (not $w.singleton) }}
  {{- fail (printf "%s must be marked singleton: true — it signs or advances on a single lane" $name) }}
  {{- end }}
  {{- if and $w.singleton (not $must_be_single) }}
  {{- fail (printf "%s is marked singleton but is not one of the three chain-facing workloads; if that changed, update the list in _helpers.tpl" $name) }}
  {{- end }}

  {{/* A workload-local literal that shadows a global would let two workloads
       disagree about a paired flag — exactly what globals exist to prevent. */}}
  {{- range $key, $_ := $w.env | default dict }}
  {{- if hasKey $g.env $key }}
  {{- fail (printf "%s.env sets %s, which is a global. Add it to globalEnv instead — a local copy can drift from the other workload that reads it" $name $key) }}
  {{- end }}
  {{- end }}

  {{/* Secrets: present (only where the workload actually runs — a disabled one
       needs nothing), declared, and never plaintext. */}}
  {{- range $key := $w.secretKeys | default list }}
  {{- $vals := index $.Values.secrets $name | default dict }}
  {{- $ref := index $vals $key | default "" }}
  {{- if and (not $ref) $w.enabled }}
  {{- fail (printf "%s needs secret %s — add secrets.%s.%s as a ref+vault:// reference" $name $key $name $key) }}
  {{- end }}
  {{- if and $ref (has (toString $ref) $devSecrets) }}
  {{- fail (printf "secrets.%s.%s is the dev/placeholder value %q — set this environment's real credential" $name $key $ref) }}
  {{- end }}
  {{- end }}

  {{/* A secret nobody declared is a secret handed to a workload that should not
       hold it — the boundary the compose allowlists enforce today. */}}
  {{- range $key, $_ := index $.Values.secrets $name | default dict }}
  {{- $declared := concat ($w.secretKeys | default list) ($w.optionalSecretKeys | default list) }}
  {{- if not (has $key $declared) }}
  {{- fail (printf "secrets.%s.%s is set but %s declares neither secretKeys nor optionalSecretKeys entry for it — a secret handed to a workload that should not hold it" $name $key $name) }}
  {{- end }}
  {{- if has (toString (index (index $.Values.secrets $name) $key)) $devSecrets }}
  {{- fail (printf "secrets.%s.%s is a dev/placeholder value — set this environment's real credential" $name $key) }}
  {{- end }}
  {{- end }}

  {{/* TURN credentials: the provider picks which secret is required, and the
       other one being present is refused at boot (crates/turn/src/config.rs).
       Both live in optionalSecretKeys because exactly one of them applies, so
       this is what keeps the missing one a render error rather than a
       crash-loop. Only where the workload actually mints credentials. */}}
  {{- $turnProvider := (index ($w.env | default dict) "TURN_PROVIDER") | default "" }}
  {{- if and $w.enabled $turnProvider }}
  {{- $vals := index $.Values.secrets $name | default dict }}
  {{- if eq (toString $turnProvider) "coturn" }}
  {{- if not (index $vals "TURN_SECRET" | default "") }}
  {{- fail (printf "%s sets TURN_PROVIDER=coturn but has no TURN_SECRET — add secrets.%s.TURN_SECRET as a ref+vault:// reference, or move the workload to TURN_PROVIDER=cloudflare" $name $name) }}
  {{- end }}
  {{- if index $vals "TURN_API_TOKEN" | default "" }}
  {{- fail (printf "%s sets TURN_PROVIDER=coturn but also holds TURN_API_TOKEN — a Cloudflare minting credential nothing reads. Remove secrets.%s.TURN_API_TOKEN" $name $name) }}
  {{- end }}
  {{- else if eq (toString $turnProvider) "cloudflare" }}
  {{- if index $vals "TURN_SECRET" | default "" }}
  {{- fail (printf "%s sets TURN_PROVIDER=cloudflare but also holds TURN_SECRET — refused at boot. Remove secrets.%s.TURN_SECRET, or set TURN_PROVIDER=coturn to keep the relay" $name $name) }}
  {{- end }}
  {{- if not (index $vals "TURN_API_TOKEN" | default "") }}
  {{- fail (printf "%s sets TURN_PROVIDER=cloudflare but has no TURN_API_TOKEN — add secrets.%s.TURN_API_TOKEN as a ref+vault:// reference" $name $name) }}
  {{- end }}
  {{- if not (index ($w.env | default dict) "TURN_KEY_ID" | default "") }}
  {{- fail (printf "%s sets TURN_PROVIDER=cloudflare but leaves TURN_KEY_ID empty — it names the Realtime TURN app and is required by that provider" $name) }}
  {{- end }}
  {{- else }}
  {{- fail (printf "%s sets TURN_PROVIDER=%q — expected cloudflare or coturn" $name (toString $turnProvider)) }}
  {{- end }}
  {{- end }}

  {{/* APNs: the signing key alone configures nothing. ApnsConfig::from_getter
       calls required() on all four selectors the moment the key resolves, so a
       key without them is a crash loop at boot. Same shape as TURN_KEY_ID
       above — a render error instead, and the reason the key is worth carrying
       at all. Only where the workload actually sends pushes. */}}
  {{- if $w.enabled }}
  {{- $apns := index $.Values.secrets $name | default dict }}
  {{- if index $apns "APNS_PRIVATE_KEY" | default "" }}
  {{- range $sel := list "APNS_KEY_ID" "APNS_TEAM_ID" "APNS_TOPIC" "APNS_ENVIRONMENT" }}
  {{- if not (index ($w.env | default dict) $sel | default "") }}
  {{- fail (printf "%s holds APNS_PRIVATE_KEY but leaves %s empty — APNs needs the key id, team id, topic and environment together, and the service refuses to start without them" $name $sel) }}
  {{- end }}
  {{- end }}
  {{- end }}
  {{- end }}

  {{/* Only where the workload runs: an environment that does not deploy the
       ticket service has no inviter to configure. */}}
  {{- if and $w.inviter $w.enabled }}
  {{- if not (index $g.inviters $w.inviter) }}
  {{- fail (printf "%s draws its inviter from global.inviters.%s, which is empty" $name $w.inviter) }}
  {{- end }}
  {{- end }}
{{- end }}

{{/* The dev keypair is committed in docker-compose.yml. Defaulting to it means an
     environment file that merely OMITS the key gets four services verifying
     tokens anyone with this repo can mint. An omission must fail, not degrade. */}}
{{- $devPub := "0x8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c" }}
{{- $devAlice := "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY" }}
{{- if and (not $g.env.JWT_JWKS_JSON) (or (not $g.env.JWT_ED25519_PUBLIC_KEY) (eq $g.env.JWT_ED25519_PUBLIC_KEY $devPub)) }}
{{- fail "global.env.JWT_ED25519_PUBLIC_KEY is unset or is the committed DEV key — set this environment's real verification key (or JWT_JWKS_JSON)" }}
{{- end }}
{{- if or (not $g.env.ATTESTER_ACCOUNT) (eq $g.env.ATTESTER_ACCOUNT $devAlice) }}
{{- fail "global.env.ATTESTER_ACCOUNT is unset or is the dev //Alice account — set this environment's attester" }}
{{- end }}

{{/* dotNS writes a GLOBAL, unrecoverable on-chain name claim. It may only run
     where the Asset Hub belongs to the same network as the People chain; the
     chart can at least refuse the case where there is no Asset Hub at all. */}}
{{- if not $g.env.ASSET_HUB_RPC_URL }}
{{- fail "ASSET_HUB_RPC_URL is empty — the writer and device-attestation-api (or all-in-one) abort at boot without it" }}
{{- end }}
{{- if not (hasKey $enabled "device-attestation-chain-writer") }}
{{- fail "device-attestation-chain-writer is not deployed — dotNS intake would be accepted and never submitted" }}
{{- end }}

{{/* The headless workers serve no HTTP but the metrics exporter, so :9090/metrics is
     their only liveness signal. Turning metrics off does not lose observability,
     it crash-loops every worker. */}}
{{- if eq (toString $g.env.METRICS_ENABLED) "false" }}
{{- fail "METRICS_ENABLED is false, but the headless workers are probed on :9090/metrics — they would fail liveness and crash-loop" }}
{{- end }}

{{/* The queue's only drain is registration-queue. On, without it, claims park
     as QUEUED forever. */}}
{{- if eq (toString $g.env.QUEUE_ENABLED) "true" }}
{{- if not (hasKey $enabled "registration-queue") }}
{{- fail "QUEUE_ENABLED is true but registration-queue is not deployed — it is the queue's only exit, so claims would park as QUEUED indefinitely" }}
{{- end }}
{{- end }}
{{- end -}}
