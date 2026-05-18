import { describe, expect, it } from 'vitest';

import {
  isIPv4,
  validateCNPhone,
  validateIPv4List,
  validatePort,
  validateUSCC,
} from './validators';

describe('validators', () => {
  it('validates ipv4 list', () => {
    expect(validateIPv4List('192.168.0.1,10.0.0.1')).toBeNull();
    expect(validateIPv4List('999.0.0.1')).toMatch(/不正确/);
    expect(isIPv4('127.0.0.1')).toBe(true);
  });

  it('validates port', () => {
    expect(validatePort(80)).toBeNull();
    expect(validatePort(0)).toBeNull();
    expect(validatePort(70000)).toMatch(/端口/);
  });

  it('validates phone', () => {
    expect(validateCNPhone('13800138000')).toBeNull();
    expect(validateCNPhone('123')).toMatch(/格式/);
  });

  it('validates uscc length', () => {
    expect(validateUSCC('')).toBeNull();
    expect(validateUSCC('9111')).toMatch(/18/);
  });
});
