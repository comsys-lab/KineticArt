package main

import (
	"os"

	"k8s.io/component-base/cli"
	"k8s.io/kubernetes/cmd/kube-scheduler/app"

	"cxlsched/pkg/plugin"
)

func main() {
	os.Exit(cli.Run(app.NewSchedulerCommand(app.WithPlugin(plugin.Name, plugin.New))))
}
