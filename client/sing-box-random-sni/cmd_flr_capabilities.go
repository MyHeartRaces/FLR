//go:build with_quic && !generate

package main

import "github.com/spf13/cobra"

func init() {
	mainCommand.AddCommand(&cobra.Command{
		Use: "flr-capabilities", Short: "Report audited FLR custom-client capabilities", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := cmd.OutOrStdout().Write([]byte("{\"version\":1,\"capabilities\":[\"hysteria2-random-sni-per-quic-dial-v1\"]}\n"))
			return err
		},
	})
}
