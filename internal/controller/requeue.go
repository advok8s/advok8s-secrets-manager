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

package controller

import "time"

// backstopRequeue is how long after a reconcile the copy-side controllers
// (SecretCopier, SecretExporter, ConfigMapCopier) re-reconcile as a safety net.
// Convergence is primarily event-driven - watches cover source changes,
// namespace lifecycle, importer changes, and target deletion/tampering/conflict
// clearance - so this backstop only bounds the staleness caused by a missed or
// mis-mapped event. It is deliberately a fixed internal constant rather than a
// per-resource spec field: the requeue is per CR instance, phased by each
// instance's last reconcile, so backstop reconciles stagger naturally and any
// event-driven reconcile resets the instance's clock.
const backstopRequeue = 5 * time.Minute
