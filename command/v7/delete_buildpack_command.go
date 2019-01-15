package v7

import (
	"code.cloudfoundry.org/cli/actor/v7action"
	"code.cloudfoundry.org/cli/command"
	"code.cloudfoundry.org/cli/command/flag"
)

//go:generate counterfeiter . DeleteBuildpackActor

type DeleteBuildpackActor interface {
	DeleteBuildpack(buildpack string, stack string) (v7action.Warnings, error)
}

type DeleteBuildpackCommand struct {
	RequiredArgs    flag.BuildpackName `positional-args:"yes"`
	//Force           bool               `short:"f" description:"Force deletion without confirmation"`
	Stack           string             `short:"s" description:"Specify stack to disambiguate buildpacks with the same name. Required when buildpack name is ambiguous"`
	Actor DeleteBuildpackActor
}

func (cmd *DeleteBuildpackCommand) Setup(config command.Config, ui command.UI) error {
	return nil
}

func (cmd DeleteBuildpackCommand) Execute(args []string) error {
	cmd.Actor.DeleteBuildpack(cmd.RequiredArgs.Buildpack, cmd.Stack)

	return nil
}
