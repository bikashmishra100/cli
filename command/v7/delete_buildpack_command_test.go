package v7_test

import (
	"code.cloudfoundry.org/cli/actor/v7action"
	. "code.cloudfoundry.org/cli/command/v7"
	"code.cloudfoundry.org/cli/command/v7/v7fakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = FDescribe("delete-buildpack Command", func() {

	var (
		cmd DeleteBuildpackCommand
		//testUI          *ui.UI
		//fakeConfig      *commandfakes.FakeConfig
		//fakeSharedActor *commandfakes.FakeSharedActor
		fakeActor *v7fakes.FakeDeleteBuildpackActor
		//input           *Buffer
		//binaryName      string
		executeErr error
		//app             string
	)

	BeforeEach(func() {
		fakeActor = new(v7fakes.FakeDeleteBuildpackActor)

		cmd = DeleteBuildpackCommand{
			Actor: fakeActor,
		}
	})

	It("delegates to the actor", func() {
		cmd.RequiredArgs.Buildpack = "the-buildpack"
		cmd.Stack = "the-stack"
		fakeActor.DeleteBuildpackReturns( v7action.Warnings{"some-warning"}, nil)

		executeErr = cmd.Execute(nil)

		Expect(executeErr).ToNot(HaveOccurred())
		actualBuildpack, actualStack := fakeActor.DeleteBuildpackArgsForCall(0)
		Expect(actualBuildpack).To(Equal("the-buildpack"))
		Expect(actualStack).To(Equal("the-stack"))
	})

	It("prints warnings", func() {
		cmd.RequiredArgs.Buildpack = "a-buildpack"
		cmd.Stack = "a-stack"
		fakeActor.DeleteBuildpackReturns( v7action.Warnings{"a-warning"}, nil)

		executeErr = cmd.Execute(nil)

		Expect(executeErr).ToNot(HaveOccurred())
		Expect(testUI.Err).To(Say("a-warning"))
	})
})
