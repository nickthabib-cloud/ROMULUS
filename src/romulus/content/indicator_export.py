"""Streaming, version-specific local indicator exports."""
from __future__ import annotations

import csv
import io

import yaml


def export_indicators(store, list_id, version=None, format='yaml'):
    """Validate before streaming and keep only one value row in memory."""
    if format not in {'yaml', 'csv'}:
        raise ValueError('Unsupported indicator export format')
    metadata = store.get(list_id, version)
    if metadata is None:
        raise ValueError('Unknown indicator list version')
    selected = metadata['version']

    def chunks():
        rows = store.values(list_id, selected)
        if format == 'csv':
            buffer = io.StringIO(newline='')
            writer = csv.writer(buffer, lineterminator='\n')
            writer.writerow(['kind', 'value', 'label', 'attack'])
            yield buffer.getvalue()
            for row in rows:
                buffer.seek(0)
                buffer.truncate(0)
                writer.writerow([row['kind'], row['value'], row['label'], ';'.join(row['attack'])])
                yield buffer.getvalue()
            return
        provenance = {key: metadata[key] for key in (
            'id', 'version', 'name', 'source', 'author', 'digest', 'created_at', 'expires_at', 'status', 'notes')}
        yield yaml.safe_dump({'schema_version': 1, 'provenance': provenance}, sort_keys=False)
        if not metadata['value_count']:
            yield 'indicators: []\n'
            return
        yield 'indicators:\n'
        for row in rows:
            indicator = {key: row[key] for key in ('id', 'kind', 'label', 'lane', 'severity', 'attack')}
            indicator['values'] = [row['value']]
            if row['expires_at']:
                indicator['expires_at'] = row['expires_at']
            yield ''.join('  '+line+'\n' for line in yaml.safe_dump([indicator], sort_keys=False).splitlines())
    return chunks()
