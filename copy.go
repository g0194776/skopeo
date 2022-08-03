package skopeo

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	commonFlag "github.com/containers/common/pkg/flag"
	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/pkg/cli"
	"github.com/containers/image/v5/transports"
	"github.com/containers/image/v5/transports/alltransports"
	encconfig "github.com/containers/ocicrypt/config"
	enchelpers "github.com/containers/ocicrypt/helpers"
	"github.com/spf13/cobra"
)

type CopyOptions struct {
	Global                   *globalOptions
	DeprecatedTLSVerify      *deprecatedTLSVerifyOption
	SrcImage                 *imageOptions
	DestImage                *imageDestOptions
	RetryOpts                *retry.Options
	AdditionalTags           []string                  // For docker-archive: destinations, in addition to the name:tag specified as destination, also add these
	RemoveSignatures         bool                      // Do not copy signatures from the source image
	SignByFingerprint        string                    // Sign the image using a GPG key with the specified fingerprint
	SignBySigstorePrivateKey string                    // Sign the image using a sigstore private key
	SignPassphraseFile       string                    // Path pointing to a passphrase file when signing (for either signature Format, but only one of them)
	SignIdentity             string                    // Identity of the signed image, must be a fully specified docker reference
	DigestFile               string                    // Write digest to this file
	Format                   commonFlag.OptionalString // Force conversion of the image to a specified Format
	Quiet                    bool                      // Suppress output information when copying images
	All                      bool                      // Copy All of the images if the source is a list
	MultiArch                commonFlag.OptionalString // How to handle multi architecture images
	PreserveDigests          bool                      // Preserve digests during copy
	EncryptLayer             []int                     // The list of layers to encrypt
	EncryptionKeys           []string                  // Keys needed to encrypt the image
	DecryptionKeys           []string                  // Keys needed to decrypt the image
}

func copyCmd(global *globalOptions) *cobra.Command {
	sharedFlags, sharedOpts := sharedImageFlags()
	deprecatedTLSVerifyFlags, deprecatedTLSVerifyOpt := deprecatedTLSVerifyFlags()
	srcFlags, srcOpts := imageFlags(global, sharedOpts, deprecatedTLSVerifyOpt, "src-", "screds")
	destFlags, destOpts := imageDestFlags(global, sharedOpts, deprecatedTLSVerifyOpt, "dest-", "dcreds")
	retryFlags, retryOpts := retryFlags()
	opts := CopyOptions{
		Global:              global,
		DeprecatedTLSVerify: deprecatedTLSVerifyOpt,
		SrcImage:            srcOpts,
		DestImage:           destOpts,
		RetryOpts:           retryOpts,
	}
	cmd := &cobra.Command{
		Use:   "copy [command options] SOURCE-IMAGE DESTINATION-IMAGE",
		Short: "Copy an IMAGE-NAME from one location to another",
		Long: fmt.Sprintf(`Container "IMAGE-NAME" uses a "transport":"details" Format.

Supported transports:
%s

See skopeo(1) section "IMAGE NAMES" for the expected Format
`, strings.Join(transports.ListNames(), ", ")),
		RunE:              commandAction(opts.run),
		Example:           `skopeo copy docker://quay.io/skopeo/stable:latest docker://registry.example.com/skopeo:latest`,
		ValidArgsFunction: autocompleteSupportedTransports,
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.AddFlagSet(&sharedFlags)
	flags.AddFlagSet(&deprecatedTLSVerifyFlags)
	flags.AddFlagSet(&srcFlags)
	flags.AddFlagSet(&destFlags)
	flags.AddFlagSet(&retryFlags)
	flags.StringSliceVar(&opts.AdditionalTags, "additional-tag", []string{}, "additional tags (supports docker-archive)")
	flags.BoolVarP(&opts.Quiet, "Quiet", "q", false, "Suppress output information when copying images")
	flags.BoolVarP(&opts.All, "All", "a", false, "Copy All images if SOURCE-IMAGE is a list")
	flags.Var(commonFlag.NewOptionalStringValue(&opts.MultiArch), "multi-arch", `How to handle multi-architecture images (system, All, or index-only)`)
	flags.BoolVar(&opts.PreserveDigests, "preserve-digests", false, "Preserve digests of images and lists")
	flags.BoolVar(&opts.RemoveSignatures, "remove-signatures", false, "Do not copy signatures from SOURCE-IMAGE")
	flags.StringVar(&opts.SignByFingerprint, "sign-by", "", "Sign the image using a GPG key with the specified `FINGERPRINT`")
	flags.StringVar(&opts.SignBySigstorePrivateKey, "sign-by-sigstore-private-key", "", "Sign the image using a sigstore private key at `PATH`")
	flags.StringVar(&opts.SignPassphraseFile, "sign-passphrase-file", "", "Read a passphrase for signing an image from `PATH`")
	flags.StringVar(&opts.SignIdentity, "sign-identity", "", "Identity of signed image, must be a fully specified docker reference. Defaults to the target docker reference.")
	flags.StringVar(&opts.DigestFile, "digestfile", "", "Write the digest of the pushed image to the specified file")
	flags.VarP(commonFlag.NewOptionalStringValue(&opts.Format), "Format", "f", `MANIFEST TYPE (oci, v2s1, or v2s2) to use in the destination (default is manifest type of source, with fallbacks)`)
	flags.StringSliceVar(&opts.EncryptionKeys, "encryption-key", []string{}, "*Experimental* key with the encryption protocol to use needed to encrypt the image (e.g. jwe:/path/to/key.pem)")
	flags.IntSliceVar(&opts.EncryptLayer, "encrypt-layer", []int{}, "*Experimental* the 0-indexed layer indices, with support for negative indexing (e.g. 0 is the first layer, -1 is the last layer)")
	flags.StringSliceVar(&opts.DecryptionKeys, "decryption-key", []string{}, "*Experimental* key needed to decrypt the image")
	return cmd
}

// parseMultiArch parses the list processing selection
// It returns the copy.ImageListSelection to use with image.Copy option
func parseMultiArch(multiArch string) (copy.ImageListSelection, error) {
	switch multiArch {
	case "system":
		return copy.CopySystemImage, nil
	case "All":
		return copy.CopyAllImages, nil
	// There is no CopyNoImages value in copy.ImageListSelection, but because we
	// don't provide an option to select a set of images to copy, we can use
	// CopySpecificImages.
	case "index-only":
		return copy.CopySpecificImages, nil
	// We don't expose CopySpecificImages other than index-only above, because
	// we currently don't provide an option to choose the images to copy. That
	// could be added in the future.
	default:
		return copy.CopySystemImage, fmt.Errorf("unknown multi-arch option %q. Choose one of the supported options: 'system', 'All', or 'index-only'", multiArch)
	}
}

func (opts *CopyOptions) Run(args []string, stdout io.Writer) (retErr error) {
	return opts.run(args, stdout)
}

func (opts *CopyOptions) run(args []string, stdout io.Writer) (retErr error) {
	if len(args) != 2 {
		return errorShouldDisplayUsage{errors.New("Exactly two arguments expected")}
	}
	opts.DeprecatedTLSVerify.warnIfUsed([]string{"--src-tls-verify", "--dest-tls-verify"})
	imageNames := args

	if err := reexecIfNecessaryForImages(imageNames...); err != nil {
		return err
	}

	policyContext, err := opts.Global.getPolicyContext()
	if err != nil {
		return fmt.Errorf("Error loading trust policy: %v", err)
	}
	defer func() {
		if err := policyContext.Destroy(); err != nil {
			retErr = noteCloseFailure(retErr, "tearing down policy context", err)
		}
	}()

	srcRef, err := alltransports.ParseImageName(imageNames[0])
	if err != nil {
		return fmt.Errorf("Invalid source name %s: %v", imageNames[0], err)
	}
	destRef, err := alltransports.ParseImageName(imageNames[1])
	if err != nil {
		return fmt.Errorf("Invalid destination name %s: %v", imageNames[1], err)
	}

	sourceCtx, err := opts.SrcImage.newSystemContext()
	if err != nil {
		return err
	}
	destinationCtx, err := opts.DestImage.newSystemContext()
	if err != nil {
		return err
	}

	var manifestType string
	if opts.Format.Present() {
		manifestType, err = parseManifestFormat(opts.Format.Value())
		if err != nil {
			return err
		}
	}

	for _, image := range opts.AdditionalTags {
		ref, err := reference.ParseNormalizedNamed(image)
		if err != nil {
			return fmt.Errorf("error parsing additional-tag '%s': %v", image, err)
		}
		namedTagged, isNamedTagged := ref.(reference.NamedTagged)
		if !isNamedTagged {
			return fmt.Errorf("additional-tag '%s' must be a tagged reference", image)
		}
		destinationCtx.DockerArchiveAdditionalTags = append(destinationCtx.DockerArchiveAdditionalTags, namedTagged)
	}

	ctx, cancel := opts.Global.commandTimeoutContext()
	defer cancel()

	if opts.Quiet {
		stdout = nil
	}

	imageListSelection := copy.CopySystemImage
	if opts.MultiArch.Present() && opts.All {
		return fmt.Errorf("Cannot use --All and --multi-arch flags together")
	}
	if opts.MultiArch.Present() {
		imageListSelection, err = parseMultiArch(opts.MultiArch.Value())
		if err != nil {
			return err
		}
	}
	if opts.All {
		imageListSelection = copy.CopyAllImages
	}

	if len(opts.EncryptionKeys) > 0 && len(opts.DecryptionKeys) > 0 {
		return fmt.Errorf("--encryption-key and --decryption-key cannot be specified together")
	}

	var encLayers *[]int
	var encConfig *encconfig.EncryptConfig
	var decConfig *encconfig.DecryptConfig

	if len(opts.EncryptLayer) > 0 && len(opts.EncryptionKeys) == 0 {
		return fmt.Errorf("--encrypt-layer can only be used with --encryption-key")
	}

	if len(opts.EncryptionKeys) > 0 {
		// encryption
		p := opts.EncryptLayer
		encLayers = &p
		encryptionKeys := opts.EncryptionKeys
		ecc, err := enchelpers.CreateCryptoConfig(encryptionKeys, []string{})
		if err != nil {
			return fmt.Errorf("Invalid encryption keys: %v", err)
		}
		cc := encconfig.CombineCryptoConfigs([]encconfig.CryptoConfig{ecc})
		encConfig = cc.EncryptConfig
	}

	if len(opts.DecryptionKeys) > 0 {
		// decryption
		decryptionKeys := opts.DecryptionKeys
		dcc, err := enchelpers.CreateCryptoConfig([]string{}, decryptionKeys)
		if err != nil {
			return fmt.Errorf("Invalid decryption keys: %v", err)
		}
		cc := encconfig.CombineCryptoConfigs([]encconfig.CryptoConfig{dcc})
		decConfig = cc.DecryptConfig
	}

	// c/image/copy.Image does allow creating both simple signing and sigstore signatures simultaneously,
	// with independent passphrases, but that would make the CLI probably too confusing.
	// For now, use the passphrase with either, but only one of them.
	if opts.SignPassphraseFile != "" && opts.SignByFingerprint != "" && opts.SignBySigstorePrivateKey != "" {
		return fmt.Errorf("Only one of --sign-by and sign-by-sigstore-private-key can be used with sign-passphrase-file")
	}
	var passphrase string
	if opts.SignPassphraseFile != "" {
		p, err := cli.ReadPassphraseFile(opts.SignPassphraseFile)
		if err != nil {
			return err
		}
		passphrase = p
	} else if opts.SignBySigstorePrivateKey != "" {
		p, err := promptForPassphrase(opts.SignBySigstorePrivateKey, os.Stdin, os.Stdout)
		if err != nil {
			return err
		}
		passphrase = p
	} // opts.SignByFingerprint triggers a GPG-agent passphrase prompt, possibly using a more secure channel, so we usually shouldn’t prompt ourselves if no passphrase was explicitly provided.

	var signIdentity reference.Named = nil
	if opts.SignIdentity != "" {
		signIdentity, err = reference.ParseNamed(opts.SignIdentity)
		if err != nil {
			return fmt.Errorf("Could not parse --sign-identity: %v", err)
		}
	}

	return retry.IfNecessary(ctx, func() error {
		manifestBytes, err := copy.Image(ctx, policyContext, destRef, srcRef, &copy.Options{
			RemoveSignatures:                 opts.RemoveSignatures,
			SignBy:                           opts.SignByFingerprint,
			SignPassphrase:                   passphrase,
			SignBySigstorePrivateKeyFile:     opts.SignBySigstorePrivateKey,
			SignSigstorePrivateKeyPassphrase: []byte(passphrase),
			SignIdentity:                     signIdentity,
			ReportWriter:                     stdout,
			SourceCtx:                        sourceCtx,
			DestinationCtx:                   destinationCtx,
			ForceManifestMIMEType:            manifestType,
			ImageListSelection:               imageListSelection,
			PreserveDigests:                  opts.PreserveDigests,
			OciDecryptConfig:                 decConfig,
			OciEncryptLayers:                 encLayers,
			OciEncryptConfig:                 encConfig,
		})
		if err != nil {
			return err
		}
		if opts.DigestFile != "" {
			manifestDigest, err := manifest.Digest(manifestBytes)
			if err != nil {
				return err
			}
			if err = os.WriteFile(opts.DigestFile, []byte(manifestDigest.String()), 0644); err != nil {
				return fmt.Errorf("Failed to write digest to file %q: %w", opts.DigestFile, err)
			}
		}
		return nil
	}, opts.RetryOpts)
}
