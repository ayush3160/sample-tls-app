# sample-tls-app

A 100-line Go server with two routes that each issue an outbound **HTTPS**
call to a public API. Useful for exercising keploy's `--capture-packets`
flag — every request flowing through keploy's proxy hits the upstream
over TLS, so the resulting pcap is encrypted and the matching
`sslkeys.log` is what makes it readable in Wireshark.

## Routes

| Route                | Upstream                          | Why it's here                                         |
| -------------------- | --------------------------------- | ----------------------------------------------------- |
| `GET /`              | —                                 | Health probe, no outbound call.                       |
| `GET /quote`         | `https://api.github.com/zen`      | Returns a one-liner; small TLS body, easy to read.    |
| `GET /echo?msg=...`  | `https://httpbin.org/anything`    | Echoes JSON back; verifies query-string round-trip.   |

## Run it standalone

```bash
go run .
# in another shell:
curl http://localhost:8080/quote
curl 'http://localhost:8080/echo?msg=hi'
```

## Record with keploy + capture pcap + decrypt in Wireshark

```bash
# from this directory
sudo -E env PATH="$PATH" keploy record \
  -c "go run ." \
  --capture-packets

# in another shell, drive a couple of requests:
curl http://localhost:8080/quote
curl 'http://localhost:8080/echo?msg=hello-pcap'
# Ctrl-C the keploy process when done
```

After Ctrl-C, look inside the freshly created test-set directory:

```
keploy/
└── test-set-0/
    ├── tests/
    │   ├── test-1.yaml
    │   └── test-2.yaml
    ├── mocks.yaml
    ├── traffic.pcap     ← encrypted bytes from the proxy ports
    └── sslkeys.log      ← NSS keylog
```

Open `traffic.pcap` in Wireshark, then:

> Edit → Preferences → Protocols → TLS → **(Pre)-Master-Secret log filename** → point at `sslkeys.log`.

Wireshark decrypts the captured TLS sessions in-place — the `/quote` and
`/echo` calls show up as plain HTTP requests with their JSON bodies.

## Run on Kubernetes (test the Global Passthrough toggle)

The k8s manifests under `k8s/` deploy this app into its own namespace so
the cluster-proxy UI can target it. The whole point is to start a
recording, **enable Global Passthrough in step 2 of the dialog**, and
verify the recorded mocks reflect passthrough behaviour (every outbound
call goes live to GitHub / httpbin instead of being captured as a mock).

### 1. Build & load the image

```bash
docker build -t sample-tls-app:dev .

# kind:
kind load docker-image sample-tls-app:dev
# minikube:
# minikube image load sample-tls-app:dev
# k3d:
# k3d image import sample-tls-app:dev -c <cluster-name>
```

### 2. Apply the manifests

```bash
kubectl apply -k k8s/
kubectl -n sample-tls-app rollout status deploy/sample-tls-app
```

### 3. Drive a recording from the enterprise UI

1. Open the cluster in the enterprise UI, find **`sample-tls-app`** under
   the `sample-tls-app` namespace, click **Start Recording**.
2. **Step 2 — Record Config**: turn the new **Global Passthrough**
   switch ON. Leave the rest at defaults.
3. Start. Drive traffic — easiest way is to port-forward or curl from a
   debug pod:

   ```bash
   kubectl -n sample-tls-app port-forward svc/sample-tls-app 8080:8080
   curl http://localhost:8080/quote
   curl 'http://localhost:8080/echo?msg=hello-passthrough'
   ```
4. Stop the recording in the UI. Inspect the resulting test-set —
   `mocks.yaml` should be near-empty (or carry only DNS/health-probe
   noise) because every outbound call was forwarded live instead of
   recorded. The same recording with the toggle OFF will produce mocks
   for both `api.github.com:443` and `httpbin.org:443`. That before/after
   diff is the regression test for the passthrough toggle.

### 4. Where the pcap + keylog live

Cluster recordings turn `--capture-packets` on unconditionally
([k8s-proxy#338](https://github.com/keploy/k8s-proxy/pull/338)), so the
test-set on the recording PVC ends up with `traffic.pcap` and
`sslkeys.log` next to `tests/` and `mocks.yaml`. Pull the **debug
bundle** from the UI to download them — the bundle layout is:

```
testset/
  tests/...
  mocks.yaml
  mocks.gob
  traffic.pcap
  sslkeys.log
```

Open the pcap in Wireshark and point its TLS keylog setting at
`sslkeys.log` to decrypt the captured frames.

### 5. Tear down

```bash
kubectl delete -k k8s/
```

## Notes

- `sslkeys.log` is keying material. Anyone with both files can decrypt
  every TLS session in the pcap. Treat the debug bundle as a
  credential-equivalent artefact when sharing externally.
- Capture is Linux-only (uses `afpacket`). On macOS / Windows the keploy
  agent prints a "feature unavailable" warning and skips it.
- The flag is opt-in on OSS. Cluster recordings via k8s-proxy turn it on
  unconditionally so support bundles always include the pair.
