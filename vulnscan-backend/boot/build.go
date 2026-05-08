package boot

import (
	"code.yt-security.com/public/core/v2/product"
)

var (
	ProductId      = "vulnscan"
	ProductName    = "漏洞扫描系统"
	ProductVersion = "dev"
)

var (
	BuildTime   = "unknown"
	BuildCommit = "unknown"
	GoVersion   = "unknown"
	BuildHash   = "unknown"
)

func GetVersion() string {
	return ProductVersion
}

func LoadProduct() *product.SystemProduct {
	p := product.NewSystemProduct(ProductId, ProductName, ProductVersion, ProductName, "", "")
	p.SetBuildInfo(product.BuildInfo{
		BuildTime:    BuildTime,
		BuildCommit:  BuildCommit,
		BuildVersion: ProductVersion,
		BuildHash:    BuildHash,
		GoVersion:    GoVersion,
	})
	return p
}
