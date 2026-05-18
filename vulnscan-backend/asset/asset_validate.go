package asset

import (
	"fmt"

	"vulnscan-backend/pkg/validate"
)

func validateConstructionOrgImport(input constructionOrgImport) error {
	if err := validate.CNPhone(input.ChargePhone); err != nil {
		return fmt.Errorf("联系电话：%w", err)
	}
	return nil
}

func validateAssetNetworkFields(ipv4 string, port int) error {
	if err := validate.IPv4List(ipv4); err != nil {
		return err
	}
	if err := validate.Port(port); err != nil {
		return err
	}
	return nil
}

func validateAssetImportRow(rowNum int, ipv4 string, port int) error {
	if err := validateAssetNetworkFields(ipv4, port); err != nil {
		return fmt.Errorf("第 %d 行：%w", rowNum, err)
	}
	return nil
}
