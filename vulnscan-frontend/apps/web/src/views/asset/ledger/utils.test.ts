import { describe, expect, it } from 'vitest';

import {
  buildOrgTreeFromFlat,
  buildOrgTreeOptions,
  mapOrganizeToUnitExtra,
  mapUnitExtraToOrganizeUpdate,
} from './utils';

describe('mapOrganizeToUnitExtra', () => {
  it('maps organize fields to ledger unit extra', () => {
    const extra = mapOrganizeToUnitExtra({
      id: '1',
      parent_id: '',
      name: '测试单位',
      unit_type: '事业单位',
      industry_category: '政务',
      is_notification_member: true,
      unified_social_credit_code: '91110000',
      address: '北京市',
      unit_detail_address: '海淀区1号',
      leader_name: '张三',
      leader_title: '主任',
      responsible_department_name: '信息中心',
      department_leader_name: '李四',
      department_leader_title: '工程师',
      department_leader_phone: '13800000000',
      contact_name: '王五',
      contact_title: '科员',
      contact_phone: '13900000000',
      asset_count: 0,
    });
    expect(extra.unit_type).toBe('事业单位');
    expect(extra.unified_social_credit_code).toBe('91110000');
    expect(extra.unit_address).toContain('海淀区1号');
    expect(extra.leader_name).toBe('张三');
    expect(extra.contact_phone).toBe('13900000000');
  });
});

describe('mapUnitExtraToOrganizeUpdate', () => {
  it('merges region label into organize address', () => {
    const payload = mapUnitExtraToOrganizeUpdate({
      unit_type: '企业',
      industry_category: '金融',
      is_notification_member: false,
      unified_social_credit_code: '9111',
      unit_location_code: '110101',
      unit_address: '长安街1号',
      leader_name: '',
      leader_title: '',
      responsible_department_name: '',
      department_leader_name: '',
      department_leader_title: '',
      department_leader_phone: '',
      contact_name: '',
      contact_title: '',
      contact_phone: '',
    });
    expect(payload.unit_type).toBe('企业');
    expect(payload.address).toContain('长安街1号');
    expect(payload.unit_detail_address).toBe('');
  });
});

describe('buildOrgTreeFromFlat', () => {
  it('builds hierarchy from parent_id', () => {
    const roots = buildOrgTreeFromFlat([
      { id: 'a', name: '总部', parent_id: '' },
      { id: 'b', name: '分部', parent_id: 'a' },
    ]);
    expect(roots).toHaveLength(1);
    expect(roots[0]?.key).toBe('a');
    expect(roots[0]?.children?.[0]?.key).toBe('b');
  });
});

describe('buildOrgTreeOptions', () => {
  it('uses nested children when present', () => {
    const roots = buildOrgTreeOptions([
      { id: 'a', name: '总部', children: [{ id: 'b', name: '分部' }] },
    ]);
    expect(roots[0]?.children?.[0]?.key).toBe('b');
  });

  it('falls back to flat parent_id', () => {
    const roots = buildOrgTreeOptions([
      { id: 'a', name: '总部' },
      { id: 'b', name: '分部', parent_id: 'a' },
    ]);
    expect(roots[0]?.children?.[0]?.key).toBe('b');
  });
});
