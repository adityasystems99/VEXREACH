// vexreach-operator executes offline reconciliation planning (CR -> least-privilege Job manifest
// or assessment report -> conservative CR status update) aligned with deploy/kubernetes/.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/adityasystems99/vexreach/operators/vexreach-operator/api/v1alpha1"
	"github.com/adityasystems99/vexreach/operators/vexreach-operator/internal/controller"
)

func main() {
	crPath := flag.String("cr", "", "Path to VulnerabilityAssessment JSON manifest")
	image := flag.String("image", "ghcr.io/adityasystems99/vexreach:latest", "Worker container image")
	reportPath := flag.String("reconcile-report", "", "Path to discovery-assessment.json to derive status")
	flag.Parse()

	if *reportPath != "" {
		b, err := os.ReadFile(*reportPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading report: %v\n", err)
			os.Exit(2)
		}
		st, err := controller.ReconcileAssessmentStatus(b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reconcile status error: %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(st, "", "  ")
		fmt.Println(string(out))
		return
	}

	if *crPath == "" {
		fmt.Fprintln(os.Stderr, "error: supply --cr <cr.json> or --reconcile-report <discovery-assessment.json>")
		os.Exit(2)
	}
	b, err := os.ReadFile(*crPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading CR: %v\n", err)
		os.Exit(2)
	}
	var cr v1alpha1.VulnerabilityAssessment
	if err := json.Unmarshal(b, &cr); err != nil {
		fmt.Fprintf(os.Stderr, "invalid CR JSON: %v\n", err)
		os.Exit(2)
	}
	job, err := controller.BuildK8sBatchJobManifest(cr, *image)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plan job error: %v\n", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(job, "", "  ")
	fmt.Println(string(out))
}
