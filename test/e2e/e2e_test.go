//go:build e2e
// +build e2e

/*
Copyright 2024-2026 Graham Dumpleton.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/advok8s/advok8s-secrets-manager/test/utils"
)

// namespace where the project is deployed in
const namespace = "advok8s-secrets-manager-system"

// serviceAccountName created for the project
const serviceAccountName = "advok8s-secrets-manager-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "advok8s-secrets-manager-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "advok8s-secrets-manager-metrics-binding"

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", managerImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				By("getting the name of the controller-manager pod")
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				By("validating the pod's status")
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=advok8s-secrets-manager-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
			)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("ensuring the controller pod is ready")
			verifyControllerPodReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", controllerPodName, "-n", namespace,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "Controller pod not ready")
			}
			Eventually(verifyControllerPodReady, 3*time.Minute, time.Second).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("Serving metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted, 3*time.Minute, time.Second).Should(Succeed())

			// +kubebuilder:scaffold:e2e-metrics-webhooks-readiness

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": [
								"for i in $(seq 1 30); do curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics && exit 0 || sleep 2; done; exit 1"
							],
							"securityContext": {
								"readOnlyRootFilesystem": true,
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccountName": "%s"
					}
				}`, token, metricsServiceName, namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			verifyMetricsAvailable := func(g Gomega) {
				metricsOutput, err := getMetricsOutput()
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
				g.Expect(metricsOutput).NotTo(BeEmpty())
				g.Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
			}
			Eventually(verifyMetricsAvailable, 2*time.Minute).Should(Succeed())
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks

		// These specs exercise behaviour that only a real cluster provides and
		// that the in-process (envtest) controller tests cannot: the garbage
		// collector acting on owner references, RBAC enforcement against the
		// deployed operator's service account (every operation below fails if a
		// permission is missing), and the auto-created default service account.
		Context("distributing secrets across namespaces", func() {
			It("copies a secret and garbage-collects it when the SecretCopier is deleted", func() {
				DeferCleanup(func() {
					_, _ = utils.Run(exec.Command("kubectl", "delete", "secretcopier", "e2e-copier", "--ignore-not-found"))
					_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", "e2e-copy-src", "e2e-copy-tgt", "--ignore-not-found"))
				})

				By("applying a source secret and a SecretCopier with reclaimPolicy Delete")
				applyYAML(`
apiVersion: v1
kind: Namespace
metadata: {name: e2e-copy-src}
---
apiVersion: v1
kind: Namespace
metadata: {name: e2e-copy-tgt}
---
apiVersion: v1
kind: Secret
metadata: {name: e2e-cred, namespace: e2e-copy-src}
type: Opaque
stringData: {token: secret-value}
---
apiVersion: secrets.advok8s.io/v1beta1
kind: SecretCopier
metadata: {name: e2e-copier}
spec:
  rules:
  - sourceSecret: {name: e2e-cred, namespace: e2e-copy-src}
    targetNamespaces:
      nameSelector: {matchNames: ["e2e-copy-tgt"]}
    reclaimPolicy: Delete
`)

				By("waiting for the copy to appear in the target namespace")
				Eventually(func(g Gomega) {
					out, err := kubectlGet("secret", "e2e-cred", "-n", "e2e-copy-tgt", "-o", "jsonpath={.metadata.name}")
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(out).To(Equal("e2e-cred"))
				}).Should(Succeed())

				By("deleting the SecretCopier and expecting the garbage collector to remove the copy")
				_, err := utils.Run(exec.Command("kubectl", "delete", "secretcopier", "e2e-copier"))
				Expect(err).NotTo(HaveOccurred())
				Eventually(func(g Gomega) {
					_, err := kubectlGet("secret", "e2e-cred", "-n", "e2e-copy-tgt", "-o", "name")
					g.Expect(err).To(HaveOccurred(), "copy should have been garbage-collected")
				}).Should(Succeed())
			})

			It("retains the copy when the SecretCopier is deleted with reclaimPolicy Retain", func() {
				DeferCleanup(func() {
					_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", "e2e-retain-src", "e2e-retain-tgt", "--ignore-not-found"))
				})

				By("applying a source secret and a SecretCopier with reclaimPolicy Retain")
				applyYAML(`
apiVersion: v1
kind: Namespace
metadata: {name: e2e-retain-src}
---
apiVersion: v1
kind: Namespace
metadata: {name: e2e-retain-tgt}
---
apiVersion: v1
kind: Secret
metadata: {name: e2e-keep, namespace: e2e-retain-src}
type: Opaque
stringData: {token: secret-value}
---
apiVersion: secrets.advok8s.io/v1beta1
kind: SecretCopier
metadata: {name: e2e-retain-copier}
spec:
  rules:
  - sourceSecret: {name: e2e-keep, namespace: e2e-retain-src}
    targetNamespaces:
      nameSelector: {matchNames: ["e2e-retain-tgt"]}
    reclaimPolicy: Retain
`)

				Eventually(func(g Gomega) {
					out, err := kubectlGet("secret", "e2e-keep", "-n", "e2e-retain-tgt", "-o", "jsonpath={.metadata.name}")
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(out).To(Equal("e2e-keep"))
				}).Should(Succeed())

				By("deleting the SecretCopier and confirming the copy survives")
				_, err := utils.Run(exec.Command("kubectl", "delete", "secretcopier", "e2e-retain-copier"))
				Expect(err).NotTo(HaveOccurred())
				Consistently(func(g Gomega) {
					out, err := kubectlGet("secret", "e2e-keep", "-n", "e2e-retain-tgt", "-o", "jsonpath={.metadata.name}")
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(out).To(Equal("e2e-keep"))
				}, 10*time.Second, time.Second).Should(Succeed())
			})

			It("injects a secret reference into the namespace's default service account", func() {
				DeferCleanup(func() {
					_, _ = utils.Run(exec.Command("kubectl", "delete", "secretinjector", "e2e-injector", "--ignore-not-found"))
					_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", "e2e-inject", "--ignore-not-found"))
				})

				By("applying a secret and a SecretInjector with no service account selector")
				applyYAML(`
apiVersion: v1
kind: Namespace
metadata: {name: e2e-inject}
---
apiVersion: v1
kind: Secret
metadata: {name: e2e-inject-cred, namespace: e2e-inject}
type: Opaque
stringData: {token: secret-value}
---
apiVersion: secrets.advok8s.io/v1beta1
kind: SecretInjector
metadata: {name: e2e-injector}
spec:
  rules:
  - sourceSecrets:
      nameSelector: {matchNames: ["e2e-inject-cred"]}
    targetNamespaces:
      nameSelector: {matchNames: ["e2e-inject"]}
`)

				By("waiting for the reference to be injected into the default service account")
				Eventually(func(g Gomega) {
					out, err := kubectlGet("serviceaccount", "default", "-n", "e2e-inject", "-o", "jsonpath={.secrets[*].name}")
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(out).To(ContainSubstring("e2e-inject-cred"))
				}).Should(Succeed())
			})

			It("exports a secret to an importer and garbage-collects it when the importer is deleted", func() {
				DeferCleanup(func() {
					_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", "e2e-exp-src", "e2e-exp-tgt", "--ignore-not-found"))
				})

				By("applying a source secret, a SecretImporter and a matching SecretExporter")
				applyYAML(`
apiVersion: v1
kind: Namespace
metadata: {name: e2e-exp-src}
---
apiVersion: v1
kind: Namespace
metadata: {name: e2e-exp-tgt}
---
apiVersion: v1
kind: Secret
metadata: {name: e2e-exported, namespace: e2e-exp-src}
type: Opaque
stringData: {token: secret-value}
---
apiVersion: secrets.advok8s.io/v1beta1
kind: SecretImporter
metadata: {name: e2e-exported, namespace: e2e-exp-tgt}
spec:
  copyAuthorization: {sharedSecret: e2e-shared}
---
apiVersion: secrets.advok8s.io/v1beta1
kind: SecretExporter
metadata: {name: e2e-exported, namespace: e2e-exp-src}
spec:
  rules:
  - targetNamespaces:
      nameSelector: {matchNames: ["e2e-exp-tgt"]}
    copyAuthorization: {sharedSecret: e2e-shared}
`)

				By("waiting for the copy to appear owned by the SecretImporter")
				Eventually(func(g Gomega) {
					out, err := kubectlGet("secret", "e2e-exported", "-n", "e2e-exp-tgt", "-o", "jsonpath={.metadata.ownerReferences[0].kind}")
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(out).To(Equal("SecretImporter"))
				}).Should(Succeed())

				By("deleting the SecretImporter and expecting the copy to be garbage-collected")
				_, err := utils.Run(exec.Command("kubectl", "delete", "secretimporter", "e2e-exported", "-n", "e2e-exp-tgt"))
				Expect(err).NotTo(HaveOccurred())
				Eventually(func(g Gomega) {
					_, err := kubectlGet("secret", "e2e-exported", "-n", "e2e-exp-tgt", "-o", "name")
					g.Expect(err).To(HaveOccurred(), "copy should have been garbage-collected with the importer")
				}).Should(Succeed())
			})
		})

		// TODO: Customize the e2e test suite with scenarios specific to your project.
		// Consider applying sample/CR(s) and check their status and/or verifying
		// the reconciliation by using the metrics, i.e.:
		// metricsOutput, err := getMetricsOutput()
		// Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
		// Expect(metricsOutput).To(ContainSubstring(
		//    fmt.Sprintf(`controller_runtime_reconcile_total{controller="%s",result="success"} 1`,
		//    strings.ToLower(<Kind>),
		// ))
	})
})

// applyYAML applies the given manifest(s) to the cluster via "kubectl apply -f -".
func applyYAML(manifest string) {
	GinkgoHelper()
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "kubectl apply failed")
}

// kubectlGet runs "kubectl get" with the given arguments and returns its output.
func kubectlGet(args ...string) (string, error) {
	return utils.Run(exec.Command("kubectl", append([]string{"get"}, args...)...))
}

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	By("creating temporary file to store the token request")
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		By("executing kubectl command to create the token")
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		By("parsing the JSON output to extract the token")
		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() (string, error) {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	return utils.Run(cmd)
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}
