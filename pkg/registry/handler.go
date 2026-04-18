package registry

import (
"encoding/json"
"html/template"
"net/http"
"strings"

"go.uber.org/zap"
)

type Handler struct {
registry  *Registry
authToken string
logger    *zap.Logger
}

func NewHandler(reg *Registry, authToken string, logger *zap.Logger) http.Handler {
h := &Handler{registry: reg, authToken: authToken, logger: logger}
mux := http.NewServeMux()
mux.HandleFunc("POST /register", h.authMiddleware(h.handleRegister))
mux.HandleFunc("DELETE /keys/{kid}", h.authMiddleware(h.handleDeleteKey))
mux.HandleFunc("POST /reissue/{kid}", h.authMiddleware(h.handleReissue))
mux.HandleFunc("GET /.well-known/openid-configuration", h.handleDiscovery)
mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)
mux.HandleFunc("GET /healthz", h.handleHealthz)
mux.HandleFunc("GET /ui", h.handleUI)
mux.HandleFunc("GET /", h.handleRoot)
return mux
}

func (h *Handler) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
auth := r.Header.Get("Authorization")
token := strings.TrimPrefix(auth, "Bearer ")
if token == "" || token != h.authToken {
http.Error(w, "unauthorized", http.StatusUnauthorized)
return
}
next(w, r)
}
}

type registerRequest struct {
KID string          `json:"kid"`
JWK json.RawMessage `json:"jwk"`
}

type registerResponse struct {
UploadURL string `json:"upload_url"`
}

type reissueResponse struct {
UploadURL string `json:"upload_url"`
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
var req registerRequest
if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
http.Error(w, "bad request", http.StatusBadRequest)
return
}
if req.KID == "" {
http.Error(w, "missing kid", http.StatusBadRequest)
return
}
url, err := h.registry.Register(r.Context(), req.KID, req.JWK)
if err != nil {
h.logger.Error("register failed", zap.Error(err))
http.Error(w, "internal error", http.StatusInternalServerError)
return
}
if len(req.JWK) > 0 {
if err := h.registry.StoreKey(r.Context(), req.KID, req.JWK); err != nil {
h.logger.Warn("failed to pre-store key", zap.Error(err))
}
}
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(registerResponse{UploadURL: url})
}

func (h *Handler) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
kid := r.PathValue("kid")
if kid == "" {
http.Error(w, "missing kid", http.StatusBadRequest)
return
}
if err := h.registry.DeleteKey(r.Context(), kid); err != nil {
h.logger.Error("delete key failed", zap.String("kid", kid), zap.Error(err))
http.Error(w, "internal error", http.StatusInternalServerError)
return
}
w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleReissue(w http.ResponseWriter, r *http.Request) {
kid := r.PathValue("kid")
if kid == "" {
http.Error(w, "missing kid", http.StatusBadRequest)
return
}
url, err := h.registry.ReissuePresignedURL(r.Context(), kid)
if err != nil {
h.logger.Error("reissue failed", zap.String("kid", kid), zap.Error(err))
http.Error(w, "not found", http.StatusNotFound)
return
}
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(reissueResponse{UploadURL: url})
}

func (h *Handler) handleDiscovery(w http.ResponseWriter, r *http.Request) {
data, err := h.registry.store.GetDiscovery(r.Context())
if err != nil || len(data) == 0 {
http.Error(w, "not found", http.StatusNotFound)
return
}
w.Header().Set("Content-Type", "application/json")
w.Write(data)
}

func (h *Handler) handleJWKS(w http.ResponseWriter, r *http.Request) {
data, err := h.registry.store.GetJWKS(r.Context())
if err != nil || len(data) == 0 {
http.Error(w, "not found", http.StatusNotFound)
return
}
w.Header().Set("Content-Type", "application/json")
w.Write(data)
}

func (h *Handler) handleHealthz(w http.ResponseWriter, r *http.Request) {
w.WriteHeader(http.StatusOK)
w.Write([]byte("ok"))
}

func (h *Handler) handleRoot(w http.ResponseWriter, r *http.Request) {
if r.URL.Path != "/" {
http.NotFound(w, r)
return
}
http.Redirect(w, r, "/ui", http.StatusFound)
}

var uiTemplate = template.Must(template.New("ui").Parse(`<!DOCTYPE html>
<html>
<head><title>kube-oidc-fed-registry</title></head>
<body>
<h1>kube-oidc-fed-registry</h1>
<h2>OIDC Endpoints</h2>
<ul>
  <li><a href="/.well-known/openid-configuration">OIDC Discovery</a></li>
  <li><a href="/.well-known/jwks.json">JWKS</a></li>
</ul>
<h2>Registered Keys ({{len .Keys}})</h2>
<table border="1" cellpadding="4">
  <tr><th>KID</th><th>Actions</th></tr>
  {{range .Keys}}
  <tr><td>{{.}}</td><td>
    <button onclick="deleteKey('{{.}}')">Delete</button>
    <button onclick="reissueURL('{{.}}')">Reissue URL</button>
  </td></tr>
  {{end}}
</table>
<div id="result" style="margin-top:10px;font-family:monospace;white-space:pre-wrap;"></div>
<script>
const token = prompt("Auth token (leave empty for public ops):", "");
function result(msg) { document.getElementById("result").textContent = msg; }
function deleteKey(kid) {
  fetch("/keys/" + kid, {method: "DELETE", headers: {"Authorization": "Bearer " + token}})
    .then(r => { result(r.status === 204 ? "Deleted " + kid : "Error: " + r.status); })
    .catch(e => result("Error: " + e));
}
function reissueURL(kid) {
  fetch("/reissue/" + kid, {method: "POST", headers: {"Authorization": "Bearer " + token}})
    .then(r => r.json())
    .then(d => result("Upload URL: " + (d.upload_url || JSON.stringify(d))))
    .catch(e => result("Error: " + e));
}
</script>
</body>
</html>`))

func (h *Handler) handleUI(w http.ResponseWriter, r *http.Request) {
kids, err := h.registry.store.ListKeys(r.Context())
if err != nil {
h.logger.Error("list keys failed", zap.Error(err))
http.Error(w, "internal error", http.StatusInternalServerError)
return
}
if kids == nil {
kids = []string{}
}
data := struct{ Keys []string }{Keys: kids}
w.Header().Set("Content-Type", "text/html; charset=utf-8")
if err := uiTemplate.Execute(w, data); err != nil {
h.logger.Error("render UI failed", zap.Error(err))
}
}
