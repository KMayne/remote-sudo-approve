# remote-sudo-approve: approved cluster changes (the applier)

Status: design v1, for review before implementation (2026-11-22).
It reuses the approval page, relay and passkey of DESIGN.md, so read that first.

## Goal

An agent running in the cluster (its own ServiceAccount, here
`claude:claude-code`) may change Kubernetes objects in a list of namespaces, but only after the
owner approves the exact change with the same passkey as for sudo. That
includes the workloads it may never touch directly: the ones with host
access, such as a home-automation server on the host network or a
node exporter.

Everything fails closed, as for sudo. A relay that's down, a bad or late
signature, a cluster that changed since the diff, or any error all mean
nothing is applied.

Without it, the choice is no write access for the agent, or direct
write access limited by admission policies (no host access, no new Secret
references, only the default ServiceAccount). The applier replaces the
direct access, or leaves a small remainder (see "Decisions").

## Threat model

**The attacker** is the agent and anything it controls. Assume it:
- runs arbitrary code in its pod, holds its ServiceAccount token, and can
  read most of the cluster (not Secrets);
- may have the policy-limited direct write access above, can push to the
  config repos, and holds tokens for other home services;
- can reach the applier and the relay;
- can read this design and the applier's code.

The scope is the same as for sudo: probably well-behaved, but it could go
wrong and start trying things.

**Trusted:**
1. The passkey and the devices holding it.
2. The approval server: page, relay and their deployment (as in DESIGN.md).
3. The applier: its image, ServiceAccount, config and namespace.
4. The Kubernetes API server, etcd and admission, and whoever is cluster-admin
   (the owner).

**Goals:**
- A1. No change the applier makes was unapproved. Each object, and each
  deletion, is covered by a passkey signature, made after user
  verification, over a complete description of that change.
- A2. What the owner sees is what is applied. The page shows the full diff
  of every object against the live cluster, and the applier applies exactly
  the signed manifests. If the live object changed in between, it applies
  nothing.
- A3. One signature covers one change, once, for a short time.
- A4. The relay can deny, never approve (as G4).
- A5. The agent can't widen this through the applier. The applier's own
  namespace, RBAC, admission policies and config, and anything
  cluster-scoped, are outside what it can be asked to change.

## Components

```
 agent pod                      applier (ns applier)              approval server     phone
 ┌──────────────────┐  HTTPS   ┌──────────────────────────┐ HTTPS ┌──────────────┐ push ┌──────┐
 │ kube-approve CLI │─────────▶│ parse, check, dry-run,   │──────▶│ /v1/ relay   │─────▶│ page │
 │  (manifests in,  │◀─────────│ diff, warnings → R       │◀──────│ / page       │◀─────│ +key │
 │   result out)    │          │ verify assertion → apply │       └──────────────┘      └──────┘
 └──────────────────┘          └───────────┬──────────────┘
                                           │ server-side apply (its own ServiceAccount)
                                           ▼
                                   kube-apiserver
```

1. **`kube-approve`**: a small client in the agent's pod.
   `kube-approve apply -f dir/` or `-f file.yaml`, and
   `kube-approve delete <kind>/<name> -n <ns>`.
   - It sends the YAML text as it is (uncommitted files are fine) and
     prints the approval link.
   - It waits, then prints what was applied or why nothing was.
   - Kustomize, Helm and so on are rendered by the agent first: the applier
     accepts plain objects only.
2. **The applier** (Rust, in the remote-sudo-approve workspace, reusing
   `verify`'s WebAuthn, relay and canonical-JSON code). It runs in its own
   namespace with its own ServiceAccount, and it is the only thing that
   writes on the agent's behalf.
3. **The approval server and page** (existing). The page gets one new
   renderer, for requests of type `kube-apply`. The relay is unchanged.

## A request, step by step

1. **Who is asking.**
   - The client sends its projected ServiceAccount token, with audience
     `applier`.
   - The applier checks it with a TokenReview and accepts only
     `system:serviceaccount:claude:claude-code`. It is rate-limited.
2. **Parse.**
   - The applier parses the YAML strictly: no anchors or aliases, no
     duplicate keys, no tags, UTF-8 only.
   - Limits: at most 50 objects and 1 MiB.
   - It turns each object into canonical JSON (DESIGN.md's canonical form).
     That JSON is what the owner sees and what gets applied, never the
     client's text.
3. **Scope.** Every object must pass all of these, else the whole request is
   refused:
   - its namespace is on the list in the applier's config;
   - its kind is on the kind list: Deployment, StatefulSet, DaemonSet, Job,
     CronJob, ConfigMap, Service, Ingress, PersistentVolumeClaim,
     NetworkPolicy, HorizontalPodAutoscaler, PodDisruptionBudget;
   - it is not a Secret, ServiceAccount, Role/RoleBinding, anything
     cluster-scoped, or anything in the applier's own namespace.
4. **Dry run.**
   - A server-side apply with `dryRun=All`, as the applier (field manager
     `applier`). Admission (Pod Security, policies, webhooks) runs, so a
     change the cluster would reject fails here, before anyone is asked.
   - It notes each live object's `resourceVersion`, or that the object
     doesn't exist yet.
5. **Diff.**
   - For each object: the live object against the dry-run result, with
     status, managedFields, resourceVersion, generation, uid and timestamps
     left out.
   - It is shown as a unified diff of canonical YAML, and in full for a new
     object.
   - A deletion shows the whole live object being removed.
6. **Warnings.** These are computed by the applier, shown in red, and part
   of what's signed:
   - host access in the result: privileged, added capabilities, host
     network/PID/IPC, host ports, hostPath, unconfined seccomp or AppArmor;
   - the object already has host access;
   - a service account change, or anything but `default`;
   - Secret references added or changed (env, envFrom, volumes, projected);
   - a new image, or new command/args, on a workload that reads Secrets:
     "new code with access to Secrets: app-db, app-session";
   - an image by tag rather than digest ("what runs can change after
     approval");
   - a deletion; a PVC change (size, class, access modes);
   - a Service turned into NodePort or LoadBalancer, or given externalIPs;
   - a NetworkPolicy change;
   - **not in git**: the object isn't in the config repo's `main`, or
     differs from it. The applier fetches `main` itself (read-only deploy key) and
     compares canonical forms, so approved-but-uncommitted changes are
     visible and drift doesn't pile up unnoticed.
7. **The request `R`** (ASCII JSON, fields in fixed order as in DESIGN.md):

   ```json
   {"v":1,"type":"kube-apply","id":"<128 random bits>",
    "cluster":"home","requester":"system:serviceaccount:claude:claude-code",
    "changes":[
      {"op":"apply","apiVersion":"apps/v1","kind":"Deployment",
       "namespace":"home","name":"home-server",
       "live":"12345678","manifest":{…canonical…},"diff":"--- live\n+++ new\n…",
       "warnings":["Already has host access (privileged, hostNetwork)", "Not in git main"]}],
    "git":{"repo":"owner/cluster-config","main":"<sha>"},
    "created":1795400000,"expires":1795400300,
    "warnings":[]}
   ```

   - `C = SHA-256(R)` is the WebAuthn challenge.
   - `type` keeps sudo and kube requests apart. Each verifier also only
     accepts a signature over the `R` it built itself, so one can never be
     used for the other.
   - The expiry is 5 minutes (sudo's is 2): a diff takes longer to read.
8. **Approval** works exactly as in DESIGN.md "Approval":
   - the relay stores `R` and sends the push;
   - the page fetches `R`, re-serialises it, computes `C` and renders it
     with `textContent` only;
   - the passkey signs, the relay keeps every assertion, and the applier
     long-polls.

   The page shows, per object, the op, kind, namespace/name, warnings in red
   and the diff, in full, never truncated. Approve is at the bottom.
9. **Verification**: DESIGN.md "Verification", items 1–5, with the same
   pinned credentials.
10. **Apply.** Only after verification, in the order listed:
    - an existing object: a server-side apply of the signed manifest
      (field manager `applier`, `force=true`) with `metadata.resourceVersion`
      set to the `live` value. If anything changed it since the diff, the
      API server refuses with a conflict;
    - a new object: a create (refused if it now exists);
    - a delete: with `preconditions.resourceVersion`.

    If any step fails it stops there and reports which objects were applied.
    There is no rollback, but the report says exactly where it stopped.
11. **Record.**
    - It logs `R`, the assertion and the result as one JSON line, which
      Vector or otel picks up into Loki.
    - It also appends the same line to a file on the applier's volume.
    - The client prints the result.

## The applier's own setup

These are what make A5 hold:
- **Namespace `applier`:** Pod Security `restricted`, and never on any
  agent's list.
- **NetworkPolicy:**
  - ingress only from the `claude` namespace;
  - egress only to the API server, the approval server and GitHub
    (for `main`).
- **Image:** built with Nix, deployed by digest, read-only root filesystem,
  no shell.
- **ServiceAccount:**
  - write on the kind list in the listed namespaces only (RoleBindings
    there; none cluster-wide);
  - read for the diff;
  - `create tokenreviews`;
  - no Secrets anywhere.
  It can make host-access changes, because that's the point, but only
  with a signature.
- **Config** (the pinned credentials, namespace list, relay URL and token,
  page origin) lives in a ConfigMap and Secret in `applier`. Only the owner
  can change them.
- **The diff and apply use the applier's own identity**, not the agent's:
  admission policies aimed at `claude:claude-code` don't apply to approved
  changes. Pod Security and other policies still do.

## Known limits (accepted)

- **The owner judges each diff.** A large diff on a phone is hard to read.
  The warnings are the real signal: approve a red change only knowing what
  it does.
- **An image by tag can change after approval.** It's flagged; pinning
  digests is the fix, and could become a requirement for images on workloads
  that read Secrets or have host access.
- **Indirect effects aren't covered:**
  - a ConfigMap read by a running program at runtime;
  - a controller that acts on an approved object;
  - an app that pulls its own config from a PVC.
- **A compromised applier can write in its namespaces**, host-access
  workloads included. Hence the hardening above. It cannot change RBAC or
  anything cluster-scoped.
- **Server-side apply with `force=true` takes field ownership** from other
  managers, for example a human's `kubectl apply`. The diff shows the
  resulting object, so nothing changes unseen, but later client-side
  applies may conflict.

## Decisions needed

1. **The applier's namespaces:**
   - the same ones as any direct access;
   - plus which others?
   - Never: kube-system, storage, cert-manager, CI runners, the agent's own
     namespace, applier.
2. **The agent's direct access once the applier works:**
   - remove it, so everything goes through approval;
   - keep a remainder, e.g. restarts (pod delete) and ConfigMap edits for
     workloads without host access.

   Recommendation: keep pod delete for restarts, remove the rest.
3. **Digest-pinned images:** required or only warned? Recommendation:
   required for host-access workloads, warned otherwise.
4. **NetworkPolicy on the kind list:** policies in these namespaces control
   what those workloads can reach. Recommendation: allowed, with a warning.

## Plan

1. The applier binary (scope, dry run, diff, warnings, `R`, verification
   reused, apply, record), with tests against a kind/k3s cluster in the
   NixOS VM test.
2. The page renderer for `type: kube-apply`, with tests that what's shown
   equals what's signed (as for sudo).
3. Deploy (namespace, RBAC, NetworkPolicy, ConfigMap), then
   `kube-approve` in the claude-code image.
4. The "not in git" comparison.
5. Narrow the agent's direct access as decided.
