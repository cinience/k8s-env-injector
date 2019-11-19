package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)


func TestLoadConfig(t *testing.T) {
	files := []struct {
		name string
		env *Config
	}{
		{"test/env_test_1.yaml",
			&Config{
				[]corev1.EnvVar{{Name: "CLUSTER_NAME", Value: "aks-test-01", ValueFrom: nil}}},
		},
		{"test/env_test_2.yaml",
			&Config{[]corev1.EnvVar{{Name: "CLUSTER_NAME", Value: "aks-test-01", ValueFrom: nil},
												{Name: "SUBSCRIPTION", Value: "subscription-00", ValueFrom: nil}}},
		},
	}

	for _, f := range files {
		config, err := loadConfig(f.name)
		if err != nil {
			t.Errorf("Error loading file %s", f.name)
			t.Fatal(err)
		}
		if !cmp.Equal(config, f.env) {
			t.Errorf("loadConfig was incorrect, got: %v, want: %v.", config, f.env)
		}
	}
}

func TestMutationRequired(t *testing.T) {
	metas := []struct {
		ignoredList []string
		metadata *metav1.ObjectMeta
		required bool
	}{
		{[]string{"admin","kube-system"},
			&metav1.ObjectMeta{Namespace: "admin", Annotations: map[string]string{}},
			false},
		{[]string{"admin","kube-system"},
			&metav1.ObjectMeta{Namespace: "rpe", Annotations: map[string]string{"some-other-annotation/inject":"false"}},
			true},
		{[]string{"admin","kube-system"},
			&metav1.ObjectMeta{Namespace: "rpe", Annotations: map[string]string{admissionWebhookAnnotationStatusKey:"injected"}},
			false},
		{[]string{"admin","kube-system"},
			&metav1.ObjectMeta{Namespace: "rpe", Annotations: map[string]string{admissionWebhookAnnotationInjectKey:"false"}},
			false},
		{[]string{"admin","kube-system"},
			&metav1.ObjectMeta{Namespace: "rpe", Annotations: map[string]string{}},
			true},
		{[]string{"admin","kube-system"},
			&metav1.ObjectMeta{Namespace: "rpe", Annotations: map[string]string{admissionWebhookAnnotationInjectKey:"true"}},
			true},
	}

	for _, m := range metas {
		required := mutationRequired(m.ignoredList, m.metadata)
		if required != m.required {
			t.Errorf("mutationRequired was incorrect, for %v, got: %t, want: %t.", m, required, m.required)
		}
	}
}

func TestAddEnv(t *testing.T) {
	envs := []struct {
		targetEnv []corev1.EnvVar
		sourceEnv []corev1.EnvVar
		path string
		patch []patchOperation
	}{
		{targetEnv: []corev1.EnvVar{{Name: "ENV_TEST_NAME", Value: "env-test-value", ValueFrom: nil}},
		sourceEnv: []corev1.EnvVar{{Name: "CLUSTER_NAME", Value: "aks-test-01", ValueFrom: nil}},
		path: "/spec/containers/nginx/env",
		patch: []patchOperation{{Op: "add", Path: "/spec/containers/nginx/env/-", Value: corev1.EnvVar{Name: "CLUSTER_NAME", Value: "aks-test-01", ValueFrom: nil}}},
		},
		{targetEnv: []corev1.EnvVar{},
			sourceEnv: []corev1.EnvVar{{Name: "CLUSTER_NAME",Value: "aks-test-01", ValueFrom: nil}},
			path: "/spec/containers/nginx/env",
			patch: []patchOperation{{Op:"add", Path: "/spec/containers/nginx/env", Value: []corev1.EnvVar{{Name: "CLUSTER_NAME", Value: "aks-test-01", ValueFrom: nil}}}},
		},
		{targetEnv: []corev1.EnvVar{{Name: "ENV_TEST_NAME", Value: "env-test-value", ValueFrom: nil}},
			sourceEnv: []corev1.EnvVar{{Name: "CLUSTER_NAME", Value: "aks-test-01", ValueFrom: nil},{Name: "SUBSCRIPTION", Value: "subscription-01", ValueFrom: nil}},
			path: "/spec/containers/nginx/env",
			patch: []patchOperation{
				{Op: "add", Path: "/spec/containers/nginx/env/-", Value: corev1.EnvVar{Name: "CLUSTER_NAME", Value: "aks-test-01", ValueFrom: nil}},
				{Op:"add", Path: "/spec/containers/nginx/env/-", Value: corev1.EnvVar{Name: "SUBSCRIPTION", Value: "subscription-01", ValueFrom: nil}},
			},
		},
		{targetEnv: nil,
			sourceEnv: []corev1.EnvVar{{Name: "CLUSTER_NAME", Value: "aks-test-01", ValueFrom: nil},{Name: "SUBSCRIPTION", Value: "subscription-01", ValueFrom: nil}},
			path: "/spec/containers/nginx/env",
			patch: []patchOperation{
				{Op: "add", Path: "/spec/containers/nginx/env", Value: []corev1.EnvVar{{Name: "CLUSTER_NAME", Value: "aks-test-01", ValueFrom: nil}}},
				{Op: "add", Path: "/spec/containers/nginx/env/-", Value: corev1.EnvVar{Name: "SUBSCRIPTION", Value: "subscription-01", ValueFrom: nil}},
			},
		},
	}

	for _, e := range envs {
		patch := addEnv(e.targetEnv, e.sourceEnv, e.path)
		if !cmp.Equal(patch, e.patch) {
			t.Errorf("addEnv was incorrect, for %v, got: %v, want: %v.", e.targetEnv, patch, e.patch)
		}
	}

}

func TestUpdateAnnotations(t *testing.T) {
	annos := []struct {
		targetAnno map[string]string
		sourceAnno map[string]string
		patch     []patchOperation
	}{
		{map[string]string{"some-other-annotation":"some_value"},
			map[string]string{admissionWebhookAnnotationStatusKey:"injected"},
			[]patchOperation{{"add", "/metadata/annotations/" + admissionWebhookAnnotationStatusKey, "injected"}},
		},
		{nil,
			map[string]string{admissionWebhookAnnotationStatusKey:"injected"},
			[]patchOperation{{"add", "/metadata/annotations", map[string]string{admissionWebhookAnnotationStatusKey:"injected"}}},
		},
		{map[string]string{admissionWebhookAnnotationStatusKey:"some_value"},
			map[string]string{admissionWebhookAnnotationStatusKey:"injected"},
			[]patchOperation{{"replace", "/metadata/annotations/" + admissionWebhookAnnotationStatusKey, "injected"}},
		},
	}

	for _, a := range annos {
		patch := updateAnnotation(a.targetAnno, a.sourceAnno)
		if !cmp.Equal(patch, a.patch) {
			t.Errorf("updateAnnotations was incorrect, for %v, got: %v, want: %v.", a.targetAnno, patch, a.patch)
		}
	}
}