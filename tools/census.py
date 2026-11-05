#!/usr/bin/env python3
"""Census binary-oracle text, without importing any DWARF implementation."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


def numbers(text, prefix):
    return dict(sorted(Counter(re.findall(r'\b' + prefix + r'\w+', text)).items()))


def unit_fields(text):
    tags = Counter(re.findall(r'^0x[0-9a-fA-F]+:\s+(DW_TAG_\w+)\b', text, re.M))
    attributes, forms, operations, expressions = Counter(), Counter(), Counter(), set()
    fields = list(re.finditer(r'^\s+(DW_AT_\w+)\s+\[(DW_FORM_\w+)\]', text, re.M))
    location_attributes = {'DW_AT_location', 'DW_AT_frame_base', 'DW_AT_data_member_location',
        'DW_AT_data_location', 'DW_AT_string_length', 'DW_AT_return_addr',
        'DW_AT_use_location', 'DW_AT_vtable_elem_location'}
    for i, field in enumerate(fields):
        attribute, form = field[1], field[2]
        attributes[attribute] += 1
        forms[form] += 1
        if form != 'DW_FORM_exprloc' and attribute not in location_attributes:
            continue
        body = text[field.end():fields[i + 1].start() if i + 1 < len(fields) else len(text)]
        # Names in quoted operands are not operation encodings.
        body = re.sub(r'"(?:\\.|[^"\\])*"', '""', body)
        operations.update(numbers(body, 'DW_OP_'))
        expressions.update(line[line.index('DW_OP_'):].strip()
                           for line in body.splitlines() if 'DW_OP_' in line)
    return {'tags': tags, 'attributes': attributes, 'forms': forms,
            'location_ops': operations, 'expressions': expressions}


def file_digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def summarize(info, line, frames):
    chunks = re.split(r'(?=^0x[0-9a-fA-F]+: (?:Compile|Type) Unit:)', info, flags=re.M)[1:]
    if not chunks:
        raise ValueError('no measured compilation/type units')
    producers = {}
    line_tables = {}
    for table in re.split(r'(?=^debug_line\[)', line, flags=re.M)[1:]:
        offset = re.match(r'debug_line\[(0x[0-9a-fA-F]+|\d+)\]', table)
        if offset:
            line_tables[int(offset[1], 0)] = table
    wolf_functions = []
    for chunk in chunks:
        version = re.search(r'\bversion\s*=\s*(0x[0-9a-fA-F]+|\d+)', chunk)
        producer = re.search(r'DW_AT_producer[^\n]*?"([^"\n]*)"', chunk)
        if not version:
            raise ValueError('unit with no version')
        name = producer[1] if producer else '<no DW_AT_producer>'
        entry = producers.setdefault(name, {'producer': name, 'units': 0, 'versions': set(),
            'forms': Counter(), 'attributes': Counter(), 'tags': Counter(), 'location_ops': Counter(),
            'expressions': set(), 'line_offsets': set()})
        entry['units'] += 1
        line_offset = re.search(r'DW_AT_stmt_list[^\n]*?\((0x[0-9a-fA-F]+)\)', chunk)
        if line_offset:
            entry['line_offsets'].add(int(line_offset[1], 16))
        entry['versions'].add(int(version[1], 0))
        fields = unit_fields(chunk)
        for key in ('forms', 'attributes', 'tags', 'location_ops'):
            entry[key].update(fields[key])
        entry['expressions'].update(fields['expressions'])
        if name.startswith('wolf '):
            for block in re.split(r'(?=^0x[0-9a-fA-F]+:\s+DW_TAG_)', chunk, flags=re.M):
                if not re.match(r'^0x[0-9a-fA-F]+:\s+DW_TAG_subprogram\b', block):
                    continue
                fn = re.search(r'DW_AT_name[^\n]*?"([^"\n]+)"', block)
                low = re.search(r'DW_AT_low_pc[^\n]*?\((0x[0-9a-fA-F]+)\)', block)
                high = re.search(r'DW_AT_high_pc\s+\[(DW_FORM_\w+)\]\s+\((0x[0-9a-fA-F]+|\d+)\)', block)
                if fn and low and high:
                    start, end = int(low[1], 16), int(high[2], 0)
                    if high[1] != 'DW_FORM_addr': end += start
                    wolf_functions.append({'name': fn[1], 'low_pc': start, 'high_pc': end})
    cfi_kinds = []
    fdes = []
    for section in re.split(r'(?=\.(?:eh_frame|debug_frame) contents:)', frames):
        kind = re.match(r'\.(eh_frame|debug_frame) contents:', section)
        if not kind: continue
        ranges = re.findall(r'\bFDE[^\n]*\bpc=(?:0x)?([0-9a-fA-F]+)\.{2,3}(?:0x)?([0-9a-fA-F]+)', section)
        if ranges: cfi_kinds.append('.' + kind[1])
        fdes += [{'kind': '.' + kind[1], 'low_pc': int(a, 16), 'high_pc': int(b, 16)} for a, b in ranges]
    for function in wolf_functions:
        function['cfi_fully_covers_range'] = any(f['low_pc'] <= function['low_pc'] and
            f['high_pc'] >= function['high_pc'] for f in fdes)
    rows = []
    for producer in sorted(producers):
        e = producers[producer]
        for key in ('versions', 'expressions'): e[key] = sorted(e[key])
        for key in ('forms', 'attributes', 'tags', 'location_ops'): e[key] = dict(sorted(e[key].items()))
        tables = []
        for offset in sorted(e['line_offsets']):
            if offset not in line_tables:
                raise ValueError('missing line table at offset ' + hex(offset))
            tables.append(line_tables[offset])
        e['line_offsets'] = sorted(e['line_offsets'])
        e['line_versions'] = sorted({int(v) for t in tables for v in re.findall(r'^\s*version:\s*(\d+)', t, re.M)})
        executed_tables = '\n'.join(v for t in tables for v in t.splitlines() if re.match(r'^0x[0-9a-fA-F]+:', v))
        e['line_opcodes'] = numbers(executed_tables, r'DW_LN[SE]_')
        e['line_special_opcodes'] = len(re.findall(r'^0x[^\n]*address \+=.*line \+=', executed_tables, re.M))
        rows.append(e)
    # Header standard_opcode_lengths declarations are NOT executed opcodes.
    executed = '\n'.join(v for v in line.splitlines() if re.match(r'^0x[0-9a-fA-F]+:', v))
    return {'schema': 1, 'units': len(chunks), 'producers': rows,
            'line_opcodes': numbers(executed, r'DW_LN[SE]_'),
            'line_special_opcodes': len(re.findall(r'^0x[^\n]*address \+=.*line \+=', executed, re.M)),
            'line_versions': sorted({int(v) for v in re.findall(r'^\s*version:\s*(\d+)', line, re.M)}),
            'cfi_kinds': sorted(set(cfi_kinds)), 'cfi_fde_count': len(fdes),
            'cfi_ops': dict(sorted(Counter(re.findall(r'^\s+(DW_CFA_\w+):', frames, re.M)).items())), 'wolf_functions': wolf_functions}


def capture(args):
    builds_path = Path(args.builds)
    builds = json.loads(builds_path.read_text())
    root = builds_path.parent
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    version = subprocess.check_output([args.dwarfdump, '--version'], text=True).strip()
    result = {'schema': 1, 'dwarfdump_version': version, 'platform': builds['platform'], 'fixtures': []}
    for fixture in builds['fixtures']:
        ident = fixture['id']
        if Path(ident).is_absolute() or '..' in Path(ident).parts:
            raise ValueError('invalid fixture id: ' + ident)
        directory = root / ident
        exe = directory / 'prog'
        artifacts = list((directory / 'prog.dSYM/Contents/Resources/DWARF').glob('*'))
        artifact = artifacts[0] if artifacts else exe
        if len(artifacts) > 1: raise ValueError('ambiguous dSYM for ' + ident)
        if builds['platform'].startswith('Darwin') and not artifacts:
            raise ValueError('missing dSYM for ' + ident)
        measured_files = set((exe, artifact))
        def verify_artifacts():
            for path in measured_files:
                key = path.relative_to(directory).as_posix()
                if file_digest(path) != fixture['sha256_read_2'].get(key):
                    raise ValueError('fixture-digest-mismatch: ' + ident + '/' + key)
        verify_artifacts()
        raw = {}
        sha = {}
        for part, flags, target in [('info', ['--debug-info', '--show-form'], artifact),
                ('line', ['--debug-line', '--verbose'], artifact),
                ('frames', ['--eh-frame', '--debug-frame'], exe)]:
            print('CENSUS ' + ident + ' ' + part, flush=True)
            p = subprocess.run([args.dwarfdump, *flags, str(target)],
                               capture_output=True, check=True, timeout=120)
            text = p.stdout.decode('utf-8', 'strict')
            if p.stderr:
                raise ValueError('oracle diagnostic: ' + p.stderr.decode('utf-8', 'replace'))
            raw[part] = text
            sha[part] = hashlib.sha256(p.stdout).hexdigest()
            path = out / ident / (part + '.txt.gz')
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('wb') as stream:
                with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as compressed:
                    compressed.write(p.stdout)
        verify_artifacts()
        summary = summarize(raw['info'], raw['line'], raw['frames'])
        summary['id'] = ident
        summary['oracle_stdout_sha256'] = sha
        summary['binary_sha256'] = fixture['sha256_read_2']['prog']
        result['fixtures'].append(summary)
        print('PASS census ' + ident + ' units=' + str(summary['units']), flush=True)
    (out / 'census.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS census-all fixtures=' + str(len(result['fixtures'])))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_subparsers(dest='mode', required=True)
    s = modes.add_parser('summarize')
    for key in ('info', 'line', 'frames', 'out'): s.add_argument('--' + key, required=True)
    c = modes.add_parser('capture')
    for key in ('builds', 'dwarfdump', 'out'): c.add_argument('--' + key, required=True)
    args = p.parse_args()
    try:
        if args.mode == 'capture': capture(args)
        else:
            result = summarize(*(Path(getattr(args, k)).read_text() for k in ('info', 'line', 'frames')))
            Path(args.out).write_text(json.dumps(result, indent=2) + '\n')
            print('PASS census-summary units=' + str(result['units']))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('FAIL census ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__': sys.exit(main())
