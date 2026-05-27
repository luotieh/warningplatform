package contract

type TargetUpdateReq struct {
	Name                string         `json:"name"`
	Notes               string         `json:"notes"`
	Enabled             *bool          `json:"enabled"`
	TargetType          string         `json:"target_type"`
	TargetValue         string         `json:"target_value"`
	DefaultScheme       string         `json:"default_scheme"`
	VirtualHost         string         `json:"virtual_host"`
	ExpectedIPs         string         `json:"expected_ips"`
	ScheduleEnabled     *bool          `json:"schedule_enabled"`
	ScheduleCron        string         `json:"schedule_cron"`
	ConfigDomainHijack  map[string]any `json:"config_domain_hijack"`
	ConfigSensitiveFile map[string]any `json:"config_sensitive_file"`
}

type TargetListReq struct {
	Name        string `form:"name"`
	TargetType  string `form:"target_type"`
	TargetValue string `form:"target_value"`
	Enabled     string `form:"enabled"`
	PageReq
}

type PathTaskUpdateReq struct {
	Name                string         `json:"name"`
	Notes               string         `json:"notes"`
	Enabled             *bool          `json:"enabled"`
	Path                string         `json:"path"`
	URLOverride         string         `json:"url_override"`
	ScheduleEnabled     *bool          `json:"schedule_enabled"`
	ScheduleCron        string         `json:"schedule_cron"`
	ConfigAvailability  map[string]any `json:"config_availability"`
	ConfigTamper        map[string]any `json:"config_tamper"`
	ConfigSensitiveWord map[string]any `json:"config_sensitive_word"`
	ConfigBlacklink     map[string]any `json:"config_blacklink"`
}

type PathTaskListReq struct {
	TargetID string `form:"target_id"`
	Name     string `form:"name"`
	Enabled  string `form:"enabled"`
	PageReq
}

type CrawlStartReq struct {
	UseHeadless       bool   `json:"use_headless"`
	MaxDepth          int    `json:"max_depth"`
	MaxPages          int    `json:"max_pages"`
	SameHost          bool   `json:"same_host"`
	StartURL          string `json:"start_url"`
	ScreenshotWidth   int    `json:"screenshot_width"`
	ScreenshotHeight  int    `json:"screenshot_height"`
	ScreenshotQuality int    `json:"screenshot_quality"`
	CreatorID         string `json:"-"`
}

type CrawlApplyReq struct {
	SkipExisting bool     `json:"skip_existing"`
	SelectedURLs []string `json:"selected_urls"`
}

type RunTargetReq struct {
	Dimensions []string `json:"dimensions"`
}

type RunPathTaskReq struct {
	Dimensions []string `json:"dimensions"`
}

type CreateTasksFromAssetsReq struct {
	AssetIDs []string `json:"asset_ids"`
}

type CreateTasksFromAssetsItem struct {
	AssetID   string `json:"asset_id"`
	AssetName string `json:"asset_name"`
	TaskID    string `json:"task_id,omitempty"`
	Success   bool   `json:"success"`
	Skipped   bool   `json:"skipped"`
	Reason    string `json:"reason,omitempty"`
	Error     string `json:"error,omitempty"`
}

type CreateTasksFromAssetsResp struct {
	Total   int                         `json:"total"`
	Success int                         `json:"success"`
	Results []CreateTasksFromAssetsItem `json:"results"`
}
