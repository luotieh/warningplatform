package boot

import (
	"code.yt-security.com/public/core/product"
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

func LoadProduct() *product.Product {
	p := product.New(ProductId, ProductName, ProductVersion)
	p.SetBuildInfo(product.BuildInfo{
		BuildTime:    BuildTime,
		BuildCommit:  BuildCommit,
		BuildVersion: ProductVersion,
		BuildHash:    BuildHash,
		GoVersion:    GoVersion,
	})
	return p
}
