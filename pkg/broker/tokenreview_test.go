package broker

import (
"context"
"testing"

authv1 "k8s.io/api/authentication/v1"
metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
"k8s.io/apimachinery/pkg/runtime"
"k8s.io/client-go/kubernetes/fake"
k8stesting "k8s.io/client-go/testing"
)

func makeTokenReview(authenticated bool, username, uid, errMsg string) *authv1.TokenReview {
return &authv1.TokenReview{
TypeMeta: metav1.TypeMeta{
Kind:       "TokenReview",
APIVersion: "authentication.k8s.io/v1",
},
Status: authv1.TokenReviewStatus{
Authenticated: authenticated,
User: authv1.UserInfo{
Username: username,
UID:      uid,
},
Error: errMsg,
},
}
}

func TestValidateToken_Authenticated(t *testing.T) {
client := fake.NewClientset()
client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
return true, makeTokenReview(true, "system:serviceaccount:default:my-sa", "uid-1", ""), nil
})

info, err := ValidateToken(context.Background(), client, "fake-token", []string{"test-audience"})
if err != nil {
t.Fatalf("unexpected error: %v", err)
}
if info.Namespace != "default" {
t.Errorf("expected namespace 'default', got %q", info.Namespace)
}
if info.ServiceAccount != "my-sa" {
t.Errorf("expected SA 'my-sa', got %q", info.ServiceAccount)
}
if info.UID != "uid-1" {
t.Errorf("expected UID 'uid-1', got %q", info.UID)
}
}

func TestValidateToken_NotAuthenticated(t *testing.T) {
client := fake.NewClientset()
client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
return true, makeTokenReview(false, "", "", "invalid token"), nil
})

_, err := ValidateToken(context.Background(), client, "bad-token", nil)
if err == nil {
t.Fatal("expected error for unauthenticated token")
}
}

func TestValidateToken_NonStandardUsername(t *testing.T) {
client := fake.NewClientset()
client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
return true, makeTokenReview(true, "admin", "uid-2", ""), nil
})

info, err := ValidateToken(context.Background(), client, "admin-token", nil)
if err != nil {
t.Fatalf("unexpected error: %v", err)
}
if info.ServiceAccount != "admin" {
t.Errorf("expected SA 'admin', got %q", info.ServiceAccount)
}
if info.Namespace != "" {
t.Errorf("expected empty namespace, got %q", info.Namespace)
}
}
