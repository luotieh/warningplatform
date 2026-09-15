"""Fill local demo event details without changing existing event/list fields.

Requires Python, toml (or Python 3.11), and mysql CLI. Dry-run by default:
  python scripts/enrich_demo_traffic.py --apply
Only the three sensor-demo events in local traffic DB are eligible.
Backups and a context-only rollback SQL file are saved before the transaction.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess

try:
    import tomllib as toml
except ImportError:
    import toml


IDS = ('demo-event-001', 'demo-event-002', 'demo-event-003')
FIELDS = {'occurrences', 'session_summary', 'ioc', 'ioc_evidence', 'demo_details'}
UTC = dt.timezone.utc


def timestamp(value):
    value = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone(dt.timedelta(hours=8)))


def iso(value):
    return value.astimezone(UTC).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def sql_text(value):
    return "CONVERT(0x" + value.encode('utf-8').hex() + " USING utf8mb4)"


def context_of(row):
    value = row['context']
    return json.loads(value) if isinstance(value, str) else value


def additions(row):
    ctx = context_of(row)
    count = int(ctx['occurrence_count'])
    if not 1 <= count <= 200:
        raise ValueError('Demo count must be between 1 and 200')
    start, end = timestamp(ctx['first_time']), timestamp(ctx['last_time'])
    if end < start:
        raise ValueError('Invalid event interval')
    protocol = ctx['protocol']
    records = []
    for i in range(count):
        when = start + (end - start) * (i / max(count - 1, 1))
        direction = 'request' if i % 2 == 0 else 'response'
        if protocol == 'ssh':
            payload = '[LOCAL DEMO] SSH #%d\r\n' % (i + 1)
        elif protocol == 'http':
            payload = ('GET /demo/sample.txt HTTP/1.1\r\nHost: web.demo.invalid\r\nX-Data-Source: LOCAL-DEMO\r\n\r\n'
                       if direction == 'request' else
                       'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 20\r\n\r\nLOCAL DEMO RESPONSE\n')
        else:
            payload = '[LOCAL DEMO] Synthetic DNS %s #%d: sample-%03d.demo.invalid TXT' % (direction, i + 1, i + 1)
        raw = payload.encode('utf-8')
        length = 580 if protocol == 'ssh' else len(raw) + (54 if protocol == 'http' else 42)
        record = dict(time=iso(when), wire_bytes=length, packets=1,
                      message_direction=direction, payload_text=payload, payload_hex=raw.hex(),
                      payload_hex_truncated=False, packet_sequence=i + 1,
                      captured_length=length, wire_length=length, capture_truncated=False,
                      capture_time=iso(when), session_start_time=iso(start))
        if protocol != 'dns':
            record[direction] = dict(tcp_seq=1000 + i * 1024, tcp_ack=5000 + i * 1024,
                                     retransmission=False)
        records.append(record)
    client = [r for r in records if r['message_direction'] == 'request']
    server = [r for r in records if r['message_direction'] == 'response']
    return dict(
        occurrences=records,
        session_summary=dict(first_time_usec=int(start.timestamp() * 1_000_000),
                             last_time_usec=int(end.timestamp() * 1_000_000),
                             client_packets=len(client), server_packets=len(server),
                             client_wire_bytes=sum(r['wire_bytes'] for r in client),
                             server_wire_bytes=sum(r['wire_bytes'] for r in server), hit_count=count),
        ioc=dict(ioc_type='domain', ioc_value='demo.invalid', ioc_category='本地演示',
                 ioc_source='LOCAL-DEMO（模拟数据）', ioc_tags=['本地演示', '非真实威胁情报'],
                 ioc_description='仅用于本地明细展示，时间与次数沿用原事件；报文、会话和情报均为模拟数据。'),
        ioc_evidence=dict(activity='本地演示', threat_labels=['模拟命中']),
        demo_details=dict(version=1, synthetic=True, original_event_fields_preserved=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--config', type=Path, default=Path(__file__).resolve().parents[1] / 'config.toml')
    parser.add_argument('--backup-dir', type=Path, default=Path(os.environ.get('TEMP', '.')) / 'traffic-demo-details')
    args = parser.parse_args()
    cfg = toml.loads(args.config.read_text(encoding='utf-8-sig'))['traffic']
    match = re.fullmatch(r'([^:]+):(.*?)@tcp\(([^:]+):(\d+)\)/([^?]+)(?:\?.*)?', cfg['database_url'])
    if not match:
        raise ValueError('Unsupported database URL')
    user, password, host, port, database = match.groups()
    if cfg.get('store_backend') != 'mysql' or host not in ('127.0.0.1', 'localhost') or database != 'traffic':
        raise ValueError('Only local MySQL traffic database is allowed')
    env = os.environ.copy()
    env['MYSQL_PWD'] = password

    def query(sql):
        result = subprocess.run(['mysql', '--protocol=TCP', '-h', host, '-P', port, '-u', user,
                                 '--connect-timeout=5', '--default-character-set=utf8mb4',
                                 '--batch', '--raw', '--skip-column-names', database],
                                input=sql, capture_output=True, encoding='utf-8', env=env)
        if result.returncode:
            raise RuntimeError(result.stderr.strip())
        return result.stdout.strip()

    columns = query("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='events' ORDER BY ORDINAL_POSITION;").splitlines()
    if not columns or any(not re.fullmatch(r'[a-z_]+', c) for c in columns):
        raise ValueError('Unexpected events schema')
    pairs = ','.join("'%s',`%s`" % (c, c) for c in columns)

    def snapshot():
        return [json.loads(line) for line in query('SELECT JSON_OBJECT(%s) FROM events ORDER BY event_id;' % pairs).splitlines()]

    before = snapshot()
    targets = [r for r in before if r['event_id'] in IDS]
    if len(targets) != 3 or any(r['source'] != 'sensor-demo' for r in targets):
        raise ValueError('Expected exactly three sensor-demo events')
    changes = []
    for row in targets:
        ctx = context_of(row)
        if ctx.get('demo_details', {}).get('version') == 1:
            continue
        if FIELDS.intersection(ctx):
            raise ValueError('Existing detail fields found; refusing to overwrite ' + row['event_id'])
        new = dict(ctx, **additions(row))
        if len(json.dumps(new, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) > 65535:
            raise ValueError('Demo context exceeds the existing MySQL TEXT limit')
        assert len(new['occurrences']) == ctx['occurrence_count']
        assert all(new[key] == value for key, value in ctx.items())
        changes.append((row, new))
    print(json.dumps({'apply': args.apply, 'events_to_enrich': {r['event_id']: len(c['occurrences']) for r, c in changes}}, ensure_ascii=False))
    if not args.apply or not changes:
        return
    folder = args.backup_dir / dt.datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')
    folder.mkdir(parents=True, exist_ok=False)
    (folder / 'events-before.json').write_text(json.dumps(before, ensure_ascii=False, indent=2), encoding='utf-8')
    statements = ['CREATE TEMPORARY TABLE demo_detail_guard (affected INT CHECK (affected=1));', 'START TRANSACTION;']
    rollback = ['USE traffic;', 'START TRANSACTION;']
    for row, new in changes:
        old_raw = row['context'] if isinstance(row['context'], str) else json.dumps(row['context'], ensure_ascii=False)
        new_raw = json.dumps(new, ensure_ascii=False, separators=(',', ':'))
        where = 'BINARY event_id=BINARY %s AND source=\'sensor-demo\'' % sql_text(row['event_id'])
        statements.append('UPDATE events SET context=%s, updated_at=updated_at WHERE %s AND BINARY context=BINARY %s;' % (sql_text(new_raw), where, sql_text(old_raw)))
        statements.append('INSERT INTO demo_detail_guard VALUES (ROW_COUNT());')
        rollback.append('UPDATE events SET context=%s, updated_at=updated_at WHERE %s AND BINARY context=BINARY %s;' % (sql_text(old_raw), where, sql_text(new_raw)))
    rollback.append('COMMIT;')
    (folder / 'rollback.sql').write_text('\n'.join(rollback), encoding='utf-8')
    statements.append('COMMIT;')
    query('\n'.join(statements))
    after = snapshot()
    expected = {row['event_id']: ctx for row, ctx in changes}
    assert len(before) == len(after), 'Event count changed during verification'
    for old, new in zip(before, after):
        assert old['event_id'] == new['event_id']
        if old['event_id'] not in expected:
            assert old == new, 'Unrelated event changed during verification'
        else:
            assert context_of(new) == expected[old['event_id']]
            assert {k: v for k, v in old.items() if k != 'context'} == {k: v for k, v in new.items() if k != 'context'}, 'Non-context event field changed'
    (folder / 'events-after.json').write_text(json.dumps(after, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Verified: only demo detail context fields changed; all existing fields preserved.')
    print('Backup: ' + str(folder))


if __name__ == '__main__':
    main()
