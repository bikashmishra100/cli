package isolated

import (
	"regexp"
	"strings"

	"code.cloudfoundry.org/cli/integration/helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var _ = Describe("login command", func() {
	var buffer *Buffer

	BeforeEach(func() {
		buffer = NewBuffer()
		buffer.Write([]byte("\n"))
	})

	Describe("Help Text", func() {
		When("--help flag is set", func() {
			It("Displays the command usage", func() {
				session := helpers.CF("login", "--help")
				Eventually(session).Should(Exit(0))

				Expect(session).Should(Say("NAME:\n"))
				Expect(session).Should(Say("login - Log user in"))

				Expect(session).Should(Say("USAGE:\n"))
				Expect(session).Should(Say(`cf login \[-a API_URL\] \[-u USERNAME\] \[-p PASSWORD\] \[-o ORG\] \[-s SPACE\] \[--sso | --sso-passcode PASSCODE\]`))

				Expect(session).Should(Say("WARNING:\n"))
				Expect(session).Should(Say("Providing your password as a command line option is highly discouraged\n"))
				Expect(session).Should(Say("Your password may be visible to others and may be recorded in your shell history\n"))

				Expect(session).Should(Say("EXAMPLES:\n"))
				Expect(session).Should(Say(regexp.QuoteMeta("cf login (omit username and password to login interactively -- cf will prompt for both)")))
				Expect(session).Should(Say(regexp.QuoteMeta("cf login -u name@example.com -p pa55woRD (specify username and password as arguments)")))
				Expect(session).Should(Say(regexp.QuoteMeta("cf login -u name@example.com -p \"my password\" (use quotes for passwords with a space)")))
				Expect(session).Should(Say(regexp.QuoteMeta("cf login -u name@example.com -p \"\\\"password\\\"\" (escape quotes if used in password)")))
				Expect(session).Should(Say(regexp.QuoteMeta("cf login --sso (cf will provide a url to obtain a one-time passcode to login)")))

				Expect(session).Should(Say("ALIAS:\n"))
				Expect(session).Should(Say("l"))

				Expect(session).Should(Say("OPTIONS:\n"))
				Expect(session).Should(Say(`-a\s+API endpoint \(e.g. https://api\.example\.com\)`))
				Expect(session).Should(Say(`-o\s+Org`))
				Expect(session).Should(Say(`-p\s+Password`))
				Expect(session).Should(Say(`-s\s+Space`))
				Expect(session).Should(Say(`--skip-ssl-validation\s+Skip verification of the API endpoint\. Not recommended\!`))
				Expect(session).Should(Say(`--sso\s+Prompt for a one-time passcode to login`))
				Expect(session).Should(Say(`--sso-passcode\s+One-time passcode`))
				Expect(session).Should(Say(`-u\s+Username`))

				Expect(session).Should(Say("SEE ALSO:\n"))
				Expect(session).Should(Say("api, auth, target"))
			})
		})
	})

	Describe("API Endpoint", func() {

		When("the API endpoint is not set", func() {
			BeforeEach(func() {
				helpers.UnsetAPI()
			})

			It("prompts the user for an endpoint", func() {
				buffer = NewBuffer()
				buffer.Write([]byte("\n"))
				session := helpers.CFWithStdin(buffer, "login")
				Eventually(session).Should(Say("API endpoint>"))
				session.Interrupt()
				Eventually(session).Should(Exit())
			})

			When("the API is set using -a flag", func() {
				FIt("sets the api endpoing and does not ask the user for api prompt", func() {
					apiURL := helpers.GetAPI()
					session := helpers.CF("login", "-a", apiURL, "--skip-ssl-validation")
					Eventually(session).Should(Say("API endpoint: %s", apiURL))
					Consistently(session).ShouldNot(Say("API endpoint>"))
					session.Interrupt()
					Eventually(session).Should(Exit())

					session = helpers.CF("api")
					Eventually(session).Should(Exit(0))
					Expect(session).Should(Say("api endpoint:   %s", apiURL))
				})
			})

			Describe("Insecure Endpoint", func() {
				When("the API endpoint is insecure", func() {
					It("shows a warning to the user", func() {
						apiURL := helpers.GetAPI()
						trimmedURL := strings.Trim(apiURL, "https://api")
						insecureURL := strings.Replace(apiURL, "https:", "http:", -1)
						session := helpers.CF("login", "-a", insecureURL)

						Eventually(session).Should(Exit(1))
						Expect(session).Should(Say("API endpoint: %s", insecureURL))
						Expect(session).Should(Say("Warning: Insecure http API endpoint detected: secure https API endpoints are recommended"))
						Expect(session).Should(Say("FAILED"))
						Expect(session).Should(Say("Received invalid SSL certificate from login%s - unknown authority", trimmedURL))
					})
				})
			})

			Describe("SSL Validation", func() {
				When("the ssl certificate is invalid", func() {
					It("fails with an error message", func() {
						apiURL := helpers.GetAPI()
						trimmedURL := strings.Trim(apiURL, "https://")
						session := helpers.CF("login", "-a", apiURL)
						Eventually(session).Should(Exit(1))
						Expect(session).Should(Say("API endpoint: %s", apiURL))
						Expect(session).Should(Say("FAILED"))
						Expect(session).Should(Say("Invalid SSL Cert for %s", trimmedURL))
						Expect(session).Should(Say("TIP: Use 'cf login --skip-ssl-validation' to continue with an insecure API endpoint"))

						session = helpers.CF("api")
						Eventually(session).Should(Exit(0))
						Expect(session).ShouldNot(Say("api endpoint:   %s", apiURL))
					})
				})
				When("the ssl certificate is valid", func() {

				})
			})
		})

		When("the API endpoint is already set", func() {
			It("does not promt the user for API endpoing", func() {
				session := helpers.CF("login")
				Consistently(session).ShouldNot(Say("API endpoint>"))
				session.Interrupt()
				Eventually(session).Should(Exit())
			})
		})

	})

	When("--sso-passcode flag is given", func() {
		When("a passcode isn't provided", func() {
			It("prompts the user to try again", func() {
				session := helpers.CFWithStdin(buffer, "login", "--sso-passcode")
				Eventually(session.Err).Should(Say("Incorrect Usage: expected argument for flag `--sso-passcode'"))
				Eventually(session).Should(Exit(1))
			})
		})

		When("the provided passcode is invalid", func() {
			It("prompts the user to try again", func() {
				session := helpers.CFWithStdin(buffer, "login", "--sso-passcode", "bad-passcode")
				Eventually(session).Should(Say("Authenticating..."))
				Eventually(session).Should(Say("Credentials were rejected, please try again."))
				session.Interrupt()
				Eventually(session).Should(Exit())
			})
		})
	})

	When("both --sso and --sso-passcode flags are provided", func() {
		It("errors with invalid use", func() {
			session := helpers.CFWithStdin(buffer, "login", "--sso", "--sso-passcode", "some-passcode")
			Eventually(session).Should(Say("Incorrect usage: --sso-passcode flag cannot be used with --sso"))
			Eventually(session).Should(Exit(1))
		})
	})

	When("a user authenticates with valid client credentials", func() {
		BeforeEach(func() {
			clientID, clientSecret := helpers.SkipIfClientCredentialsNotSet()
			session := helpers.CF("auth", clientID, clientSecret, "--client-credentials")
			Eventually(session).Should(Exit(0))
		})

		When("a different user logs in with valid password credentials", func() {
			It("should fail log in and display an error informing the user they need to log out", func() {
				username, password := helpers.GetCredentials()
				session := helpers.CF("login", "-u", username, "-p", password)

				Eventually(session).Should(Say("FAILED"))
				Eventually(session).Should(Say(`Service account currently logged in\. Use 'cf logout' to log out service account and try again\.`))
				Eventually(session).Should(Exit(1))
			})
		})
	})
})
