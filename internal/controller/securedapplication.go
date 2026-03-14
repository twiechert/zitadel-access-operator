package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	accessv1alpha1 "github.com/twiechert/cf-zitadel-access-operator/api/v1alpha1"
	cfclient "github.com/twiechert/cf-zitadel-access-operator/internal/cloudflare"
	"github.com/twiechert/cf-zitadel-access-operator/internal/zitadel"
)

const (
	finalizerName = "access.twiechert.de/finalizer"

	// The custom:roles claim is a flat array produced by a Zitadel Action (flatRoles).
	// Cloudflare Access can't match Zitadel's default nested role claim format.
	roleClaimName = "custom:roles"

	cfBackendProtocolAnnotation = "cloudflare-tunnel-ingress-controller.strrl.dev/backend-protocol"
)

// Config holds operator-level configuration.
type Config struct {
	// CloudflareIdPID is the Cloudflare Access Identity Provider ID for Zitadel.
	CloudflareIdPID string

	// SessionDuration is the Cloudflare Access session duration (e.g. "24h").
	SessionDuration string
}

type SecuredApplicationReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	Zitadel    zitadel.Client
	Cloudflare cfclient.Client
	Config     Config
}

// +kubebuilder:rbac:groups=access.twiechert.de,resources=securedapplications,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=access.twiechert.de,resources=securedapplications/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=access.twiechert.de,resources=securedapplications/finalizers,verbs=update
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch

func (r *SecuredApplicationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var app accessv1alpha1.SecuredApplication
	if err := r.Get(ctx, req.NamespacedName, &app); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion.
	if !app.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&app, finalizerName) {
			if !app.Spec.DeleteProtection {
				if app.Status.ZitadelAppID != "" && app.Status.ProjectID != "" {
					logger.Info("deleting Zitadel OIDC app", "appId", app.Status.ZitadelAppID)
					if err := r.Zitadel.DeleteApp(ctx, app.Status.ProjectID, app.Status.ZitadelAppID); err != nil {
						logger.Error(err, "failed to delete Zitadel app, will retry")
						return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
					}
				}
				if app.Status.AccessApplicationID != "" {
					logger.Info("deleting Cloudflare Access Application", "appId", app.Status.AccessApplicationID)
					if err := r.Cloudflare.DeleteAccessApp(ctx, app.Status.AccessApplicationID); err != nil {
						logger.Error(err, "failed to delete Access Application, will retry")
						return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
					}
				}
				for path, appID := range app.Status.BypassApplicationIDs {
					logger.Info("deleting bypass Access Application", "path", path, "appId", appID)
					if err := r.Cloudflare.DeleteAccessApp(ctx, appID); err != nil {
						logger.Error(err, "failed to delete bypass Access Application, will retry")
						return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
					}
				}
			} else {
				logger.Info("delete protection enabled, keeping external resources")
			}
			// Ingress + Secret cleaned up via ownerReference GC.
			controllerutil.RemoveFinalizer(&app, finalizerName)
			if err := r.Update(ctx, &app); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer.
	if !controllerutil.ContainsFinalizer(&app, finalizerName) {
		controllerutil.AddFinalizer(&app, finalizerName)
		if err := r.Update(ctx, &app); err != nil {
			return ctrl.Result{}, err
		}
	}

	// 1. Resolve Zitadel project name → ID.
	project, err := r.Zitadel.GetProjectByName(ctx, app.Spec.Access.Project)
	if err != nil {
		return r.setCondition(ctx, &app, metav1.ConditionFalse, "ProjectLookupFailed", err.Error())
	}
	if project == nil {
		return r.setCondition(ctx, &app, metav1.ConditionFalse, "ProjectNotFound",
			fmt.Sprintf("Zitadel project %q not found", app.Spec.Access.Project))
	}

	// 2. Validate that all requested roles exist (only if roles are specified).
	if len(app.Spec.Access.Roles) > 0 {
		existingRoles, err := r.Zitadel.ListProjectRoles(ctx, project.ID)
		if err != nil {
			return r.setCondition(ctx, &app, metav1.ConditionFalse, "RoleLookupFailed", err.Error())
		}
		roleSet := make(map[string]bool, len(existingRoles))
		for _, role := range existingRoles {
			roleSet[role.Key] = true
		}
		for _, requested := range app.Spec.Access.Roles {
			if !roleSet[requested] {
				return r.setCondition(ctx, &app, metav1.ConditionFalse, "RoleNotFound",
					fmt.Sprintf("role %q does not exist in Zitadel project %q", requested, app.Spec.Access.Project))
			}
		}
	}

	// Validate that at least one of roles or claims is specified.
	if len(app.Spec.Access.Roles) == 0 && len(app.Spec.Access.Claims) == 0 {
		return r.setCondition(ctx, &app, metav1.ConditionFalse, "InvalidAccess",
			"at least one of roles or claims must be specified")
	}

	// 3. Reconcile Zitadel OIDC application.
	oidcApp, clientSecret, err := r.reconcileZitadelApp(ctx, &app, project.ID)
	if err != nil {
		return r.setCondition(ctx, &app, metav1.ConditionFalse, "ZitadelAppFailed", err.Error())
	}
	logger.Info("reconciled Zitadel OIDC app", "appId", oidcApp.ID, "clientId", oidcApp.ClientID)

	// Write credentials to K8s Secret (only on initial creation when we have the client secret).
	if clientSecret != "" {
		if err := r.writeCredentialSecret(ctx, &app, oidcApp.ClientID, clientSecret); err != nil {
			return r.setCondition(ctx, &app, metav1.ConditionFalse, "SecretFailed", err.Error())
		}
	}

	// 4. Reconcile Cloudflare Access Application with OIDC claim policy.
	accessAppID := app.Status.AccessApplicationID
	if accessAppID == "" {
		existing, err := r.Cloudflare.FindAccessAppByDomain(ctx, app.Spec.Host)
		if err != nil {
			return r.setCondition(ctx, &app, metav1.ConditionFalse, "CloudflareLookupFailed", err.Error())
		}
		if existing != nil {
			logger.Info("adopting existing Access Application", "appId", existing.ID)
			accessAppID = existing.ID
		}
	}

	if accessAppID != "" {
		if err := r.Cloudflare.UpdateAccessApp(ctx, accessAppID, app.Name, app.Spec.Host, r.Config.SessionDuration); err != nil {
			return r.setCondition(ctx, &app, metav1.ConditionFalse, "CloudflareUpdateFailed", err.Error())
		}
	} else {
		created, err := r.Cloudflare.CreateAccessApp(ctx, app.Name, app.Spec.Host, r.Config.SessionDuration)
		if err != nil {
			return r.setCondition(ctx, &app, metav1.ConditionFalse, "CloudflareCreateFailed", err.Error())
		}
		accessAppID = created.ID
		logger.Info("created Access Application", "appId", accessAppID)
	}

	// Build CF Access policy rules from both roles and claims.
	var rules []cfclient.OIDCClaimRule
	for _, role := range app.Spec.Access.Roles {
		rules = append(rules, cfclient.OIDCClaimRule{
			IdentityProviderID: r.Config.CloudflareIdPID,
			ClaimName:          roleClaimName,
			ClaimValue:         role,
		})
	}
	for _, claim := range app.Spec.Access.Claims {
		rules = append(rules, cfclient.OIDCClaimRule{
			IdentityProviderID: r.Config.CloudflareIdPID,
			ClaimName:          claim.Name,
			ClaimValue:         claim.Value,
		})
	}

	policy, err := r.Cloudflare.UpsertAccessPolicy(ctx, accessAppID, app.Status.AccessPolicyID, rules)
	if err != nil {
		return r.setCondition(ctx, &app, metav1.ConditionFalse, "PolicyFailed", err.Error())
	}

	// 5. Reconcile bypass Access Applications for unauthenticated paths.
	bypassIDs, err := r.reconcileBypassApps(ctx, &app)
	if err != nil {
		return r.setCondition(ctx, &app, metav1.ConditionFalse, "BypassAppFailed", err.Error())
	}

	// 6. Reconcile Cloudflare Tunnel Ingress.
	if err := r.reconcileIngress(ctx, &app); err != nil {
		return r.setCondition(ctx, &app, metav1.ConditionFalse, "IngressFailed", err.Error())
	}
	logger.Info("reconciled tunnel ingress", "name", app.Name)

	// 7. Reconcile direct OIDC Ingress (bypasses CF Access, app handles auth).
	if app.Spec.NativeOIDC != nil && app.Spec.NativeOIDC.Ingress != nil {
		if err := r.reconcileOIDCIngress(ctx, &app); err != nil {
			return r.setCondition(ctx, &app, metav1.ConditionFalse, "OIDCIngressFailed", err.Error())
		}
		logger.Info("reconciled OIDC ingress", "name", app.Name+"-oidc")
	}

	// 8. Update status.
	app.Status.ProjectID = project.ID
	app.Status.ZitadelAppID = oidcApp.ID
	app.Status.ClientID = oidcApp.ClientID
	app.Status.AccessApplicationID = accessAppID
	app.Status.AccessPolicyID = policy.ID
	app.Status.BypassApplicationIDs = bypassIDs
	app.Status.Ready = true
	return r.setCondition(ctx, &app, metav1.ConditionTrue, "Reconciled", "All resources are up to date")
}

func (r *SecuredApplicationReconciler) reconcileZitadelApp(ctx context.Context, app *accessv1alpha1.SecuredApplication, projectID string) (*zitadel.App, string, error) {
	// Construct redirect URI from host + path.
	redirectHost := app.Spec.Host
	redirectPath := "/callback"

	config := zitadel.AppConfig{
		Name:            app.Name,
		ResponseTypes:   []string{"OIDC_RESPONSE_TYPE_CODE"},
		GrantTypes:      []string{"OIDC_GRANT_TYPE_AUTHORIZATION_CODE"},
		AppType:         "OIDC_APP_TYPE_WEB",
		AuthMethodType:  "OIDC_AUTH_METHOD_TYPE_BASIC",
		AccessTokenType: "OIDC_TOKEN_TYPE_BEARER",
	}

	if app.Spec.NativeOIDC != nil {
		if app.Spec.NativeOIDC.Ingress != nil {
			redirectHost = app.Spec.NativeOIDC.Ingress.Host
		}
		if app.Spec.NativeOIDC.RedirectPath != "" {
			redirectPath = app.Spec.NativeOIDC.RedirectPath
		}
		if app.Spec.NativeOIDC.PostLogoutRedirectPath != "" {
			config.PostLogoutRedirectURIs = []string{fmt.Sprintf("https://%s%s", redirectHost, app.Spec.NativeOIDC.PostLogoutRedirectPath)}
		}
		if len(app.Spec.NativeOIDC.ResponseTypes) > 0 {
			config.ResponseTypes = app.Spec.NativeOIDC.ResponseTypes
		}
		if len(app.Spec.NativeOIDC.GrantTypes) > 0 {
			config.GrantTypes = app.Spec.NativeOIDC.GrantTypes
		}
		if app.Spec.NativeOIDC.AppType != "" {
			config.AppType = app.Spec.NativeOIDC.AppType
		}
		if app.Spec.NativeOIDC.AuthMethodType != "" {
			config.AuthMethodType = app.Spec.NativeOIDC.AuthMethodType
		}
		if app.Spec.NativeOIDC.AccessTokenType != "" {
			config.AccessTokenType = app.Spec.NativeOIDC.AccessTokenType
		}
		config.DevMode = app.Spec.NativeOIDC.DevMode
		config.IDTokenRoleAssertion = app.Spec.NativeOIDC.IDTokenRoleAssertion
		config.IDTokenUserinfoAssertion = app.Spec.NativeOIDC.IDTokenUserinfoAssertion
		config.AccessTokenRoleAssertion = app.Spec.NativeOIDC.AccessTokenRoleAssertion
	}

	config.RedirectURIs = []string{fmt.Sprintf("https://%s%s", redirectHost, redirectPath)}

	// Update existing app.
	if app.Status.ZitadelAppID != "" {
		if err := r.Zitadel.UpdateApp(ctx, projectID, app.Status.ZitadelAppID, config); err != nil {
			return nil, "", err
		}
		return &zitadel.App{
			ID:       app.Status.ZitadelAppID,
			ClientID: app.Status.ClientID,
		}, "", nil
	}

	// Try to find by name (re-adoption).
	existing, err := r.Zitadel.GetAppByName(ctx, projectID, app.Name)
	if err != nil {
		return nil, "", err
	}
	if existing != nil {
		if err := r.Zitadel.UpdateApp(ctx, projectID, existing.ID, config); err != nil {
			return nil, "", err
		}
		return existing, "", nil
	}

	// Create new app — this is the only time we get the client secret.
	created, err := r.Zitadel.CreateApp(ctx, projectID, config)
	if err != nil {
		return nil, "", err
	}
	return created, created.ClientSecret, nil
}

func (r *SecuredApplicationReconciler) writeCredentialSecret(ctx context.Context, app *accessv1alpha1.SecuredApplication, clientID, clientSecret string) error {
	secretName := app.Name + "-oidc"
	if app.Spec.NativeOIDC != nil && app.Spec.NativeOIDC.ClientSecretRef != "" {
		secretName = app.Spec.NativeOIDC.ClientSecretRef
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: app.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if err := controllerutil.SetControllerReference(app, secret, r.Scheme); err != nil {
			return err
		}
		secret.StringData = map[string]string{
			"clientId":     clientID,
			"clientSecret": clientSecret,
		}
		return nil
	})
	return err
}

func (r *SecuredApplicationReconciler) reconcileIngress(ctx context.Context, app *accessv1alpha1.SecuredApplication) error {
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      app.Name,
			Namespace: app.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, ingress, func() error {
		if err := controllerutil.SetControllerReference(app, ingress, r.Scheme); err != nil {
			return err
		}

		className := "cloudflare-tunnel"
		if app.Spec.Ingress != nil && app.Spec.Ingress.ClassName != "" {
			className = app.Spec.Ingress.ClassName
		}
		ingress.Spec.IngressClassName = &className

		annotations := make(map[string]string)
		if app.Spec.Ingress != nil {
			for k, v := range app.Spec.Ingress.Annotations {
				annotations[k] = v
			}
		}
		if app.Spec.Backend.Protocol != "" {
			annotations[cfBackendProtocolAnnotation] = app.Spec.Backend.Protocol
		}
		ingress.Annotations = annotations

		pathType := networkingv1.PathTypePrefix
		if app.Spec.Ingress != nil && app.Spec.Ingress.PathType != "" {
			pathType = networkingv1.PathType(app.Spec.Ingress.PathType)
		}
		path := "/"
		if app.Spec.Ingress != nil && app.Spec.Ingress.Path != "" {
			path = app.Spec.Ingress.Path
		}

		ingress.Spec.Rules = []networkingv1.IngressRule{
			{
				Host: app.Spec.Host,
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path:     path,
								PathType: &pathType,
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: app.Spec.Backend.ServiceName,
										Port: networkingv1.ServiceBackendPort{
											Number: app.Spec.Backend.ServicePort,
										},
									},
								},
							},
						},
					},
				},
			},
		}

		return nil
	})

	return err
}

func (r *SecuredApplicationReconciler) reconcileOIDCIngress(ctx context.Context, app *accessv1alpha1.SecuredApplication) error {
	oidcIngress := app.Spec.NativeOIDC.Ingress

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      app.Name + "-oidc",
			Namespace: app.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, ingress, func() error {
		if err := controllerutil.SetControllerReference(app, ingress, r.Scheme); err != nil {
			return err
		}

		ingress.Spec.IngressClassName = &oidcIngress.ClassName

		annotations := make(map[string]string)
		for k, v := range oidcIngress.Annotations {
			annotations[k] = v
		}
		ingress.Annotations = annotations

		pathType := networkingv1.PathTypePrefix
		if oidcIngress.PathType != "" {
			pathType = networkingv1.PathType(oidcIngress.PathType)
		}
		path := "/"
		if oidcIngress.Path != "" {
			path = oidcIngress.Path
		}

		ingress.Spec.Rules = []networkingv1.IngressRule{
			{
				Host: oidcIngress.Host,
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{
								Path:     path,
								PathType: &pathType,
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: app.Spec.Backend.ServiceName,
										Port: networkingv1.ServiceBackendPort{
											Number: app.Spec.Backend.ServicePort,
										},
									},
								},
							},
						},
					},
				},
			},
		}

		return nil
	})

	return err
}

func (r *SecuredApplicationReconciler) reconcileBypassApps(ctx context.Context, app *accessv1alpha1.SecuredApplication) (map[string]string, error) {
	logger := log.FromContext(ctx)
	desired := make(map[string]bool, len(app.Spec.Access.BypassPaths))
	for _, p := range app.Spec.Access.BypassPaths {
		desired[p] = true
	}

	result := make(map[string]string, len(app.Spec.Access.BypassPaths))

	// Delete bypass apps for paths that are no longer in the spec.
	for path, appID := range app.Status.BypassApplicationIDs {
		if !desired[path] {
			logger.Info("removing stale bypass Access Application", "path", path, "appId", appID)
			if err := r.Cloudflare.DeleteAccessApp(ctx, appID); err != nil {
				return nil, fmt.Errorf("delete stale bypass app for %q: %w", path, err)
			}
		}
	}

	// Create or keep bypass apps for desired paths.
	for _, path := range app.Spec.Access.BypassPaths {
		if existingID, ok := app.Status.BypassApplicationIDs[path]; ok {
			result[path] = existingID
			continue
		}

		domain := app.Spec.Host + path
		name := fmt.Sprintf("%s-bypass-%s", app.Name, path)
		logger.Info("creating bypass Access Application", "domain", domain)
		created, err := r.Cloudflare.CreateBypassApp(ctx, name, domain)
		if err != nil {
			return nil, fmt.Errorf("create bypass app for %q: %w", path, err)
		}
		result[path] = created.ID
	}

	return result, nil
}

func (r *SecuredApplicationReconciler) setCondition(ctx context.Context, app *accessv1alpha1.SecuredApplication, status metav1.ConditionStatus, reason, message string) (ctrl.Result, error) {
	meta.SetStatusCondition(&app.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
	if status != metav1.ConditionTrue {
		app.Status.Ready = false
	}
	if err := r.Status().Update(ctx, app); err != nil {
		return ctrl.Result{}, err
	}
	if status != metav1.ConditionTrue {
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}
	return ctrl.Result{}, nil
}

func (r *SecuredApplicationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&accessv1alpha1.SecuredApplication{}).
		Owns(&networkingv1.Ingress{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
