package agent

import (
	"context"
	"fmt"
	"strings"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type TokenInfo struct {
	Namespace      string
	ServiceAccount string
	UID            string
}

func ValidateToken(ctx context.Context, client kubernetes.Interface, token string, audiences []string) (*TokenInfo, error) {
	tr := &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     token,
			Audiences: audiences,
		},
	}
	result, err := client.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("token review: %w", err)
	}
	if !result.Status.Authenticated {
		return nil, fmt.Errorf("token not authenticated: %s", result.Status.Error)
	}
	// username is "system:serviceaccount:NAMESPACE:NAME"
	parts := strings.Split(result.Status.User.Username, ":")
	var ns, saName string
	if len(parts) == 4 {
		ns = parts[2]
		saName = parts[3]
	} else {
		saName = result.Status.User.Username
	}
	return &TokenInfo{
		Namespace:      ns,
		ServiceAccount: saName,
		UID:            result.Status.User.UID,
	}, nil
}
