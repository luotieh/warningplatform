package nuclei

import "testing"

func TestBuildTechExclusionSet(t *testing.T) {
	tests := []struct {
		name     string
		products []string
		excluded []string
		kept     []string
	}{
		{
			name:     "PHP detected excludes Java/Python/Ruby/Node/.NET/Go",
			products: []string{"php", "wordpress"},
			excluded: []string{"java", "spring", "tomcat", "django", "flask", "rails", "express", "asp.net", "golang"},
			kept:     []string{"php", "wordpress", "laravel"},
		},
		{
			name:     "Java detected excludes PHP/Python/Ruby/Node/.NET/Go",
			products: []string{"java", "spring"},
			excluded: []string{"php", "wordpress", "drupal", "django", "flask", "rails", "express", "asp.net", "golang"},
			kept:     []string{"java", "spring", "tomcat", "shiro"},
		},
		{
			name:     "No language detected returns nil",
			products: []string{"nginx", "apache"},
			excluded: nil,
			kept:     nil,
		},
		{
			name:     "Empty products returns nil",
			products: nil,
			excluded: nil,
			kept:     nil,
		},
		{
			name:     "Multiple stacks detected excludes only undetected",
			products: []string{"php", "java"},
			excluded: []string{"django", "flask", "rails", "express", "asp.net", "golang"},
			kept:     []string{"php", "java", "wordpress", "spring"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildTechExclusionSet(tt.products)
			if tt.excluded == nil {
				if result != nil {
					t.Errorf("expected nil exclusion set, got %v", result)
				}
				return
			}
			for _, ex := range tt.excluded {
				if _, ok := result[ex]; !ok {
					t.Errorf("expected %q to be in exclusion set", ex)
				}
			}
			if tt.kept != nil {
				for _, k := range tt.kept {
					if _, ok := result[k]; ok {
						t.Errorf("expected %q NOT to be in exclusion set", k)
					}
				}
			}
		})
	}
}

func TestShouldExcludeByTechStack(t *testing.T) {
	phpExclusion := BuildTechExclusionSet([]string{"php", "wordpress"})

	tests := []struct {
		name    string
		tags    string
		exclude bool
	}{
		{"Java PoC should be excluded", "java,spring,cve-2024-1234", true},
		{"Python PoC should be excluded", "django,rce", true},
		{"PHP PoC should NOT be excluded", "php,wordpress,sqli", false},
		{"Generic PoC should NOT be excluded", "sqli,rce,cve", false},
		{"Mixed generic should NOT be excluded", "network,http,config", false},
		{"No tech tags should NOT be excluded", "cve-2024-1234,exposure", false},
		{"Empty tags should NOT be excluded", "", false},
		{"Tomcat should be excluded", "tomcat,default-login", true},
		{"Rails should be excluded", "rails,ruby", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &PocEntry{Tags: tt.tags}
			got := ShouldExcludeByTechStack(entry, phpExclusion)
			if got != tt.exclude {
				t.Errorf("ShouldExcludeByTechStack(tags=%q) = %v, want %v", tt.tags, got, tt.exclude)
			}
		})
	}
}
