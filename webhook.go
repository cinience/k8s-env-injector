package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/api/resource"
	"net/http"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"k8s.io/api/admission/v1beta1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

var ignoredNamespaces = []string{
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
}

const (
	admissionWebhookAnnotationInjectKey = "env-injector-webhook-inject"
	admissionWebhookAnnotationStatusKey = "env-injector-webhook-status"
)

type WebhookServer struct {
	envConfig *Config
	server    *http.Server
}

// Webhook Server parameters
type WhSvrParameters struct {
	port       int    // webhook server port
	certFile   string // path to the x509 certificate for https
	keyFile    string // path to the x509 private key matching `CertFile`
	envCfgFile string // path to env injector configuration file
}

type Config struct {
	ImagePullSecrets string          `yaml:"imagePullSecrets,omitempty"`
	HostNetwork      bool            `yaml:"hostNetwork"`
	Env              []corev1.EnvVar `yaml:"env"`

	DnsPolicy  string                      `yaml:"dnsPolicy,omitempty"`
	DnsConfig  *corev1.PodDNSConfig        `yaml:"dnsConfig,omitempty"`
	DnsOptions []corev1.PodDNSConfigOption `yaml:"dnsOptions,omitempty"`

	NodeAffinityTerms []corev1.NodeSelectorTerm `yaml:"nodeAffinityTerms,omitempty"`
	Annotations       map[string]string         `yaml:"annotations,omitempty"`
	Labels            map[string]string         `yaml:"labels,omitempty"`
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionregistrationv1beta1.AddToScheme(runtimeScheme)
}

func loadConfig(configFile string) (*Config, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	glog.Infof("New configuration: sha256sum %x", sha256.Sum256(data))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	glog.Infof("Configuration data: %+v", &cfg)

	return &cfg, nil
}

// mutationRequired checks whether the target resource needs to be mutated.
// Mutation is enabled by default unless explicitly disabled.
func mutationRequired(ignoredList []string, metadata *metav1.ObjectMeta) bool {
	// skip excluded kubernetes system namespaces
	for _, namespace := range ignoredList {
		if metadata.Namespace == namespace {
			glog.Infof("Skip mutation for %v in namespace: %v", metadata.Name, metadata.Namespace)
			return false
		}
	}

	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	status := annotations[admissionWebhookAnnotationStatusKey]

	// determine whether to perform mutation based on annotation for the target resource
	var required bool
	if strings.ToLower(status) == "injected" {
		required = false
	} else {
		switch strings.ToLower(annotations[admissionWebhookAnnotationInjectKey]) {
		default:
			required = true
		case "n", "no", "false", "off":
			required = false
		}
	}

	glog.Infof("Mutation policy for %v/%v: status: %q required:%v", metadata.Namespace, metadata.Name, status, required)
	return required
}

// addEnv performs the mutation(s) needed to add the extra environment variables to the target
// resource
func addEnv(target, envVars []corev1.EnvVar, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, envVar := range envVars {
		value = envVar
		path := basePath
		if first {
			first = false
			value = []corev1.EnvVar{envVar}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

// addResourcesLimits performs the mutation(s) needed to add the extra environment variables to the target
// resource
func addNvidiaGpuResourcesLimits(envVars []corev1.EnvVar, basePath string) (patch []patchOperation) {
	var num string
	var exists bool
	for _, envVar := range envVars {
		if strings.Contains(envVar.Name, "nvidia_gpu") {
			num = envVar.Value
			exists = true
			break
		}
	}

	if !exists {
		return
	}
	glog.Infoln("try add nvidia.com/gpu support...")
	patch = append(patch, patchOperation{
		Op:    "add",
		Path:  basePath + "/" + strings.ReplaceAll("nvidia.com/gpu", "/", "~1"),
		Value: resource.MustParse(num),
	})
	return patch
}

// addDnsOptions performs the mutation(s) needed to add the extra dnsOptions to the target
// resource
func addDnsOptions(target, dnsOptions []corev1.PodDNSConfigOption, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, dnsOpt := range dnsOptions {
		value = dnsOpt
		path := basePath
		op := "add"
		if first {
			first = false
			value = []corev1.PodDNSConfigOption{dnsOpt}
		} else {
			optExists := false
			for idx, targetOpt := range target {
				if targetOpt.Name == dnsOpt.Name {
					optExists = true
					op = "replace"
					path = fmt.Sprintf("%s/%d", path, idx)
					break
				}
			}
			if !optExists {
				path = path + "/-"
			}
		}
		patch = append(patch, patchOperation{
			Op:    op,
			Path:  path,
			Value: value,
		})
	}
	return patch
}

// addNodeAffinityTerms performs the mutation(s) needed to add selector terms to the node affinity
// RequiredDuringSchedulingIgnoredDuringExecution section of to the target resource
func addNodeAffinityTerms(target, nodeAffinityTerms []corev1.NodeSelectorTerm, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, nst := range nodeAffinityTerms {
		value = nst
		path := basePath
		if first {
			first = false
			value = []corev1.NodeSelectorTerm{nst}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func updateAnnotation(target map[string]string, annotations map[string]string) (patch []patchOperation, err error) {
	for k, v := range annotations {
		oldValue := v
		if target != nil && strings.HasPrefix(v, "$") {
			v = target[strings.TrimPrefix(v, "$")]
		}
		if v == "" {
			return nil, fmt.Errorf("parse annotation %s:%s failed", k, oldValue)
		}
		if target == nil {
			target = map[string]string{}
			patch = append(patch, patchOperation{
				Op:   "add",
				Path: "/metadata/annotations",
				Value: map[string]string{
					k: v,
				},
			})
		} else if target[k] == "" {
			target = map[string]string{}
			patch = append(patch, patchOperation{
				Op: "add",
				// "~"(tilde) is encoded as "~0" and "/"(forward slash) is encoded as "~1".
				// https://www.rfc-editor.org/rfc/rfc6901#section-3
				Path:  "/metadata/annotations/" + strings.ReplaceAll(k, "/", "~1"),
				Value: v,
			})
		} else {
			patch = append(patch, patchOperation{
				Op:    "replace",
				Path:  "/metadata/annotations/" + strings.ReplaceAll(k, "/", "~1"),
				Value: v,
			})
		}
	}
	return patch, nil
}

func updateLabels(target map[string]string, labels map[string]string) (patch []patchOperation, err error) {
	glog.Infof("updateLabels %v \n", target)
	for k, v := range labels {
		oldValue := v
		if target != nil && strings.HasPrefix(v, "$") {
			v = target[strings.TrimPrefix(v, "$")]
		}
		if v == "" {
			return nil, fmt.Errorf("parse label %s:%s failed", k, oldValue)
		}
		if target == nil {
			target = map[string]string{}
			patch = append(patch, patchOperation{
				Op:   "add",
				Path: "/metadata/labels",
				Value: map[string]string{
					k: v,
				},
			})
		} else if target[k] == "" {
			target = map[string]string{}
			patch = append(patch, patchOperation{
				Op:    "add",
				Path:  "/metadata/labels/" + strings.ReplaceAll(k, "/", "~1"),
				Value: v,
			})
		} else {
			patch = append(patch, patchOperation{
				Op:    "replace",
				Path:  "/metadata/labels/" + strings.ReplaceAll(k, "/", "~1"),
				Value: v,
			})
		}
	}
	return patch, nil
}

// createPatch creates a mutation patch for resources
func createPatch(pod *corev1.Pod, envConfig *Config, annotations map[string]string) ([]byte, error) {
	var patches []patchOperation

	for idx, container := range pod.Spec.Containers {
		patches = append(patches, addEnv(container.Env, envConfig.Env, fmt.Sprintf("/spec/containers/%d/env", idx))...)
		patches = append(patches, addNvidiaGpuResourcesLimits(container.Env, fmt.Sprintf("/spec/containers/%d/resources/limits", idx))...)
	}

	if envConfig.DnsPolicy != "" {
		vaild := true
		if envConfig.DnsPolicy == "None" {
			if envConfig.DnsConfig == nil || len(envConfig.DnsConfig.Nameservers) == 0 {
				vaild = false
				glog.Errorf("DnsPolicy is None ,you must config dnsConfig.nameservers")
			}
		}
		if vaild {
			if pod.Spec.DNSPolicy == "" {
				patches = append(patches, patchOperation{Op: "add", Path: "/spec/dnsPolicy", Value: envConfig.DnsPolicy})
			} else {
				patches = append(patches, patchOperation{Op: "replace", Path: "/spec/dnsPolicy", Value: envConfig.DnsPolicy})
			}
		}
	}

	if envConfig.DnsConfig != nil {
		if pod.Spec.DNSConfig == nil {
			pod.Spec.DNSConfig = &corev1.PodDNSConfig{}
			patches = append(patches, patchOperation{Op: "add", Path: "/spec/dnsConfig", Value: envConfig.DnsConfig})
		} else {
			patches = append(patches, patchOperation{Op: "replace", Path: "/spec/dnsConfig", Value: envConfig.DnsConfig})
		}
	}

	//if len(envConfig.DnsOptions) > 0 {
	//	if pod.Spec.DNSConfig == nil {
	//		pod.Spec.DNSConfig = &corev1.PodDNSConfig{}
	//		patches = append(patches, patchOperation{Op: "add", Path: "/spec/dnsConfig", Value: corev1.PodDNSConfig{}})
	//	}
	//	patches = append(patches, addDnsOptions(pod.Spec.DNSConfig.Options, envConfig.DnsOptions, fmt.Sprintf("/spec/dnsConfig/options"))...)
	//}

	if len(envConfig.NodeAffinityTerms) > 0 {
		if pod.Spec.Affinity == nil {
			pod.Spec.Affinity = &corev1.Affinity{}
			patches = append(patches, patchOperation{Op: "add", Path: "/spec/affinity", Value: corev1.Affinity{}})
		}
		if pod.Spec.Affinity.NodeAffinity == nil {
			pod.Spec.Affinity.NodeAffinity = &corev1.NodeAffinity{}
			patches = append(patches, patchOperation{Op: "add", Path: "/spec/affinity/nodeAffinity", Value: corev1.NodeAffinity{}})
		}
		if pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
			pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution = &corev1.NodeSelector{}
			patches = append(patches, patchOperation{Op: "add", Path: "/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution", Value: corev1.NodeSelector{}})
		}
		patches = append(patches, addNodeAffinityTerms(pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms,
			envConfig.NodeAffinityTerms, fmt.Sprintf("/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms"))...)
	}

	//Patch(podName, types.StrategicMergePatchType, playLoadBytes)
	//if _, exists := pod.Labels["nvidia.com/gpu"]; !exists {
	//	// Strategic Merge Patch golang
	//	// https://developer.aliyun.com/article/703438
	//	// Add Gpus support
	//	pod.Spec.Containers[0].Resources.Limits[corev1.ResourceName("nvidia.com/gpu")] = resource.MustParse("1")
	//}
	if len(envConfig.Labels) > 0 {
		patchLabes, err := updateLabels(pod.Labels, envConfig.Labels)
		if err != nil {
			glog.Errorf("")
			return nil, err
		}
		patches = append(patches, patchLabes...)
	}

	if len(envConfig.Annotations) > 0 {
		for k, v := range envConfig.Annotations {
			annotations[k] = v
		}
	}

	if envConfig.HostNetwork {
		patches = append(patches, patchOperation{Op: "add", Path: "/spec/hostNetwork", Value: envConfig.HostNetwork})
	}

	if envConfig.ImagePullSecrets != "" {
		patches = append(patches, patchOperation{Op: "add", Path: "/spec/imagePullSecrets", Value: []corev1.LocalObjectReference{{Name: envConfig.ImagePullSecrets}}})
	}

	patchAnnotations, err := updateAnnotation(pod.Annotations, annotations)
	if err != nil {
		return nil, err
	}
	patches = append(patches, patchAnnotations...)
	return json.Marshal(patches)
}

// main mutation process
func (whsvr *WebhookServer) mutate(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := ar.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		glog.Errorf("Could not unmarshal raw object: %v", err)
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo)

	// determine whether to perform mutation
	if !mutationRequired(ignoredNamespaces, &pod.ObjectMeta) {
		glog.Infof("Skipping mutation for %s/%s due to policy check", pod.Namespace, pod.Name)
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	annotations := map[string]string{admissionWebhookAnnotationStatusKey: "injected"}
	patchBytes, err := createPatch(&pod, whsvr.envConfig, annotations)
	if err != nil {
		glog.Errorf("createPatch failed, err:%v\n", err.Error())
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	// 	_, err = client.CoreV1().Nodes().Patch(name, types.StrategicMergePatchType, patchBytes)
	glog.Infof("AdmissionResponse: patch=%v\n", string(patchBytes))
	return &v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

// serve manages requests to the webhook server
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		glog.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		glog.Errorf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		glog.Errorf("Can't decode body: %v", err)
		admissionResponse = &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = whsvr.mutate(&ar)
	}

	admissionReview := v1beta1.AdmissionReview{}
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		glog.Errorf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	glog.Infof("Ready to write reponse ...")
	if _, err := w.Write(resp); err != nil {
		glog.Errorf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}
