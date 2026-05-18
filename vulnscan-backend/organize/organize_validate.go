package organize

import (
	"fmt"
	"strings"

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/validate"
)

func validateOrganizeProfile(creditCode, deptPhone, contactPhone string) error {
	if err := validate.USCC(creditCode); err != nil {
		return err
	}
	if err := validate.CNPhone(deptPhone); err != nil {
		return fmt.Errorf("负责人电话：%w", err)
	}
	if err := validate.CNPhone(contactPhone); err != nil {
		return fmt.Errorf("联系人电话：%w", err)
	}
	return nil
}

func validateOrganizeItem(item *model.Organize) error {
	if item == nil {
		return nil
	}
	return validateOrganizeProfile(
		item.UnifiedSocialCreditCode,
		item.DepartmentLeaderPhone,
		item.ContactPhone,
	)
}

// ValidateOrganizeProfileUpdates 校验组织档案更新字段（供资产导入等调用）。
func ValidateOrganizeProfileUpdates(updates map[string]interface{}) error {
	return validateOrganizeUpdates(updates)
}

func validateOrganizeUpdates(updates map[string]interface{}) error {
	if updates == nil {
		return nil
	}
	credit := stringFieldFromUpdates(updates, "unified_social_credit_code")
	deptPhone := stringFieldFromUpdates(updates, "department_leader_phone")
	contactPhone := stringFieldFromUpdates(updates, "contact_phone")
	return validateOrganizeProfile(credit, deptPhone, contactPhone)
}

func validateConstructionOrg(item *model.ConstructionOrg) error {
	if item == nil {
		return nil
	}
	return validate.CNPhone(item.ChargePhone)
}

func validateConstructionUpdates(updates map[string]interface{}) error {
	if updates == nil {
		return nil
	}
	if _, ok := updates["charge_phone"]; !ok {
		return nil
	}
	return validate.CNPhone(stringFieldFromUpdates(updates, "charge_phone"))
}

func stringFieldFromUpdates(updates map[string]interface{}, key string) string {
	v, ok := updates[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}
