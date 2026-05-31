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

package builder

import (
	"fmt"
	"time"
)

// Result is what a generator engine produces: the Secret's data (decoded - the
// engine works in plaintext, the controller base64-encodes on write), plus any
// labels and the Secret type the script chose.
type Result struct {
	Data   map[string][]byte
	Labels map[string]string
	Type   string
}

// RetryError signals a script retry(): inputs exist but are not yet ready, so the
// controller should hold generation in AwaitingInput and requeue, optionally after
// the given delay. It is benign, not a failure.
type RetryError struct {
	Message string
	After   time.Duration
}

func (e *RetryError) Error() string {
	if e.After > 0 {
		return fmt.Sprintf("retry after %s: %s", e.After, e.Message)
	}
	return "retry: " + e.Message
}

// FailError signals a script fail(): the generator declared the configuration
// broken. The controller maps it to GeneratorError / Degraded.
type FailError struct {
	Message string
}

func (e *FailError) Error() string { return "fail: " + e.Message }

// Engine renders a generator (a Starlark script or a gotemplate template) against
// resolved inputs into a Result. A *RetryError or *FailError carries the script's
// retry()/fail() outcome; any other error is an ordinary generation failure
// (mapped to GeneratorError by the controller).
type Engine interface {
	Render(inputs *ResolvedInputs) (*Result, error)
}
