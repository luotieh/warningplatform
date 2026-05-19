import { describe, expect, it } from 'vitest';

import {
  buildImportErrorTableRows,
  groupImportIssuesByRow,
  importErrorSummary,
} from './import-errors';

describe('groupImportIssuesByRow', () => {
  it('merges multiple fields on the same row', () => {
    const rows = groupImportIssuesByRow([
      { row: 3, field: '是否联网', message: '不能为空' },
      { row: 3, field: '资产分类', message: '不能为空' },
      { row: 5, field: '访问地址', message: 'URL 格式不正确' },
    ]);
    expect(rows).toHaveLength(2);
    expect(rows[0]?.row).toBe(3);
    expect(rows[0]?.summary).toContain('是否联网');
    expect(rows[0]?.summary).toContain('资产分类');
  });
});

describe('buildImportErrorTableRows', () => {
  it('prefers failed_rows preview from backend', () => {
    const rows = buildImportErrorTableRows(
      [
        {
          row: 3,
          name: '系统A',
          organize_name: '单位1',
          address: '',
          error_summary: '【访问地址】不能为空',
        },
      ],
      [],
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]?.name).toBe('系统A');
    expect(rows[0]?.summary).toContain('访问地址');
  });
});

describe('importErrorSummary', () => {
  it('shows row count when different from issue count', () => {
    expect(importErrorSummary(96, 32)).toContain('96');
    expect(importErrorSummary(96, 32)).toContain('32');
  });
});
