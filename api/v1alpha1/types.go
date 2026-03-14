package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Host",type=string,JSONPath=`.spec.host`
// +kubebuilder:printcolumn:name="Project",type=string,JSONPath=`.spec.access.project`
// +kubebuilder:printcolumn:name="Client ID",type=string,JSONPath=`.status.clientId`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SecuredApplication registers an OIDC application in Zitadel, protects it
// with a Cloudflare Access policy based on Zitadel roles, and routes traffic
// through a Cloudflare Tunnel Ingress.
type SecuredApplication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecuredApplicationSpec   `json:"spec,omitempty"`
	Status SecuredApplicationStatus `json:"status,omitempty"`
}

type SecuredApplicationSpec struct {
	// Host is the public hostname for this application.
	Host string `json:"host"`

	// Access defines the Zitadel project and roles required to access this application.
	Access Access `json:"access"`

	// Backend defines the Kubernetes Service to route traffic to.
	Backend Backend `json:"backend"`

	// NativeOIDC customizes the Zitadel OIDC application and optionally
	// creates a second Ingress for native OIDC access.
	//
	// Every SecuredApplication gets a Zitadel OIDC app (for registration)
	// and a Cloudflare Tunnel Ingress (with CF Access enforcing roles at
	// the edge). The nativeOIDC section is for apps like Grafana that also
	// handle OIDC authentication themselves — it lets you customize the
	// Zitadel app settings (redirect URIs, token assertions) and optionally
	// expose a second Ingress where the app authenticates users directly
	// against Zitadel, bypassing Cloudflare Access.
	//
	// Two access paths:
	//   spec.host → CF Tunnel Ingress → CF Access enforces custom:roles → backend
	//   nativeOIDC.ingress.host → direct Ingress → app does its own OIDC with Zitadel
	// +optional
	NativeOIDC *NativeOIDCConfig `json:"nativeOIDC,omitempty"`

	// Ingress allows overriding generated Ingress settings.
	// +optional
	Ingress *IngressConfig `json:"ingress,omitempty"`

	// DeleteProtection prevents the operator from deleting external resources
	// (Zitadel OIDC app, Cloudflare Access Application) when the CR is removed.
	// Defaults to false.
	// +optional
	DeleteProtection bool `json:"deleteProtection,omitempty"`
}

type Access struct {
	// Project is the Zitadel project name. The operator resolves this to a project ID.
	Project string `json:"project"`

	// Roles lists the Zitadel project roles allowed to access this application.
	// These are checked against the custom:roles OIDC claim in the CF Access policy.
	// +optional
	Roles []string `json:"roles,omitempty"`

	// Claims defines additional OIDC claim checks for the CF Access policy.
	// Each claim is checked against the specified value.
	// +optional
	Claims []ClaimCheck `json:"claims,omitempty"`

	// BypassPaths lists path prefixes that should bypass Cloudflare Access
	// authentication. For each path, a separate CF Access Application is
	// created with a "bypass" policy allowing unauthenticated access.
	// Useful for webhook endpoints that receive callbacks from external
	// services (e.g. Telegram, Stripe).
	// +optional
	BypassPaths []string `json:"bypassPaths,omitempty"`
}

// ClaimCheck defines an OIDC claim name/value pair for a Cloudflare Access policy rule.
// At least one of roles or claims must be set on the parent Access struct.
type ClaimCheck struct {
	// Name is the OIDC claim name (e.g. "custom:department").
	Name string `json:"name"`

	// Value is the required claim value.
	Value string `json:"value"`
}

type Backend struct {
	// ServiceName is the name of the Kubernetes Service.
	ServiceName string `json:"serviceName"`

	// ServicePort is the port number on the Service.
	ServicePort int32 `json:"servicePort"`

	// Protocol overrides the backend protocol (e.g. "https").
	// +optional
	Protocol string `json:"protocol,omitempty"`
}

type NativeOIDCConfig struct {
	// RedirectPath is the path portion of the OIDC redirect URI.
	// The operator constructs the full URI as https://{nativeOIDC.ingress.host}{redirectPath}
	// when an OIDC ingress is configured, or https://{spec.host}{redirectPath} otherwise.
	// Defaults to "/callback".
	// +optional
	RedirectPath string `json:"redirectPath,omitempty"`

	// PostLogoutRedirectPath is the path portion of the post-logout redirect URI.
	// Constructed the same way as redirectPath.
	// +optional
	PostLogoutRedirectPath string `json:"postLogoutRedirectPath,omitempty"`

	// ResponseTypes defaults to ["OIDC_RESPONSE_TYPE_CODE"].
	// +optional
	ResponseTypes []string `json:"responseTypes,omitempty"`

	// GrantTypes defaults to ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE"].
	// +optional
	GrantTypes []string `json:"grantTypes,omitempty"`

	// AppType defaults to "OIDC_APP_TYPE_WEB".
	// +optional
	AppType string `json:"appType,omitempty"`

	// AuthMethodType defaults to "OIDC_AUTH_METHOD_TYPE_BASIC".
	// +optional
	AuthMethodType string `json:"authMethodType,omitempty"`

	// AccessTokenType defaults to "OIDC_TOKEN_TYPE_BEARER".
	// +optional
	AccessTokenType string `json:"accessTokenType,omitempty"`

	// DevMode enables development mode (allows http redirect URIs).
	// +optional
	DevMode bool `json:"devMode,omitempty"`

	// IDTokenRoleAssertion includes roles in the ID token.
	// +optional
	IDTokenRoleAssertion bool `json:"idTokenRoleAssertion,omitempty"`

	// IDTokenUserinfoAssertion includes userinfo in the ID token.
	// +optional
	IDTokenUserinfoAssertion bool `json:"idTokenUserinfoAssertion,omitempty"`

	// AccessTokenRoleAssertion includes roles in the access token.
	// +optional
	AccessTokenRoleAssertion bool `json:"accessTokenRoleAssertion,omitempty"`

	// ClientSecretRef is the name of the Kubernetes Secret to write OIDC
	// credentials to. Defaults to "{name}-oidc". The secret will contain
	// "clientId" and "clientSecret" keys.
	// +optional
	ClientSecretRef string `json:"clientSecretRef,omitempty"`

	// Ingress creates a second Ingress that bypasses Cloudflare Access,
	// allowing the app to handle authentication directly via its Zitadel
	// OIDC credentials. Requires a host different from spec.host.
	// +optional
	Ingress *OIDCIngressConfig `json:"ingress,omitempty"`
}

type OIDCIngressConfig struct {
	// Host is the hostname for direct OIDC access (e.g. "grafana-internal.example.com").
	Host string `json:"host"`

	// ClassName for the direct Ingress (e.g. "nginx"). No default.
	ClassName string `json:"className"`

	// Annotations to add to the generated Ingress.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Path defaults to "/".
	// +optional
	Path string `json:"path,omitempty"`

	// PathType defaults to "Prefix".
	// +optional
	PathType string `json:"pathType,omitempty"`
}

type IngressConfig struct {
	// ClassName overrides the default Ingress class (defaults to "cloudflare-tunnel").
	// +optional
	ClassName string `json:"className,omitempty"`

	// Annotations to add to the generated Ingress.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Path defaults to "/".
	// +optional
	Path string `json:"path,omitempty"`

	// PathType defaults to "Prefix".
	// +optional
	PathType string `json:"pathType,omitempty"`
}

type SecuredApplicationStatus struct {
	// ProjectID is the resolved Zitadel project ID.
	ProjectID string `json:"projectId,omitempty"`

	// ZitadelAppID is the Zitadel OIDC application ID.
	ZitadelAppID string `json:"zitadelAppId,omitempty"`

	// ClientID is the OIDC client ID.
	ClientID string `json:"clientId,omitempty"`

	// AccessApplicationID is the Cloudflare Access Application ID.
	AccessApplicationID string `json:"accessApplicationId,omitempty"`

	// AccessPolicyID is the Cloudflare Access Policy ID.
	AccessPolicyID string `json:"accessPolicyId,omitempty"`

	// BypassApplicationIDs maps bypass path → CF Access Application ID.
	BypassApplicationIDs map[string]string `json:"bypassApplicationIds,omitempty"`

	// Ready indicates the application is fully reconciled.
	Ready bool `json:"ready"`

	// Conditions represent the latest available observations.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// SecuredApplicationList contains a list of SecuredApplication.
type SecuredApplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecuredApplication `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecuredApplication{}, &SecuredApplicationList{})
}
