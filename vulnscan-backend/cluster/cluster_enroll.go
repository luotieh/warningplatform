package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	clusterContract "vulnscan-backend/cluster/cluster-contract"
	"vulnscan-backend/model"
	"vulnscan-backend/pkg/nodeauth"
	"vulnscan-backend/pkg/nodeenroll"

	"code.yt-security.com/public/core/v2/generate/qulid"
)

func (s *serviceCluster) IssueScanNodeCredentials(ctx context.Context, req *clusterContract.NodeEnrollmentIssueRequest) (*clusterContract.NodeEnrollmentIssueResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("请求为空")
	}
	if err := nodeenroll.Validate(&req.Enrollment); err != nil {
		return nil, err
	}

	fp := strings.TrimSpace(req.Enrollment.MachineFingerprint)
	var count int64
	sess := s.session()
	if ctx != nil {
		sess = sess.WithContext(ctx)
	}
	if err := sess.Model(&model.Node{}).Where("machine_fingerprint = ?", fp).Count(&count).Error; err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, fmt.Errorf("该机器指纹已存在扫描节点，请先禁用或删除旧节点后再签发")
	}

	plainSecret, err := nodeauth.GeneratePlainSecret()
	if err != nil {
		return nil, err
	}
	hashStr, err := nodeauth.HashSecret(plainSecret)
	if err != nil {
		return nil, err
	}

	nodeUUID := qulid.GenerateID()
	mac := strings.TrimSpace(req.Enrollment.PrimaryMAC)
	if len(mac) > 20 {
		mac = mac[:20]
	}

	node := model.Node{
		ID:                 nodeUUID,
		UUID:               nodeUUID,
		MachineFingerprint: fp,
		AgentSecretHash:    hashStr,
		Status:             model.NodeStatusOffline,
		Hostname:           strings.TrimSpace(req.Enrollment.Hostname),
		MacAddress:         mac,
		Label:              strings.TrimSpace(req.Label),
		MaxConcurrent:      10,
		Version:            "",
		IPAddress:          "",
		CPUUsage:           0,
		MemoryUsage:        0,
		RunningTasks:       0,
		QueuedTasks:        0,
		TasksCompleted:     0,
		LastHeartbeat:      nil,
	}

	if err := sess.Create(&node).Error; err != nil {
		return nil, fmt.Errorf("创建节点记录失败: %w", err)
	}

	cred := &clusterContract.NodeAgentCredentialsFile{
		Version:   clusterContract.NodeAgentCredentialsVersion,
		MasterURL: strings.TrimSpace(req.MasterURL),
		NodeUUID:  nodeUUID,
		Secret:    plainSecret,
		IssuedAt:  time.Now().UTC().Format(time.RFC3339),
		Label:     strings.TrimSpace(req.Label),
	}

	if strings.TrimSpace(req.Enrollment.PublicKeyPEM) != "" {
		pub, err := nodeenroll.ParseRSAPublicKeyFromPEM(req.Enrollment.PublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("公钥无效: %w", err)
		}
		plain, err := json.Marshal(cred)
		if err != nil {
			return nil, err
		}
		env, err := nodeenroll.EncryptCredentialsJSON(pub, plain)
		if err != nil {
			return nil, fmt.Errorf("加密凭据失败: %w", err)
		}
		return &clusterContract.NodeEnrollmentIssueResponse{
			Encrypted: true,
			Envelope:  env,
		}, nil
	}

	return &clusterContract.NodeEnrollmentIssueResponse{
		Encrypted:   false,
		Credentials: cred,
	}, nil
}
