#!/usr/bin/env python3
"""Manuelle Report-Review-Vorbereitung, keine automatische Erkennungsgarantie."""
import argparse,csv,json,re
from pathlib import Path

MARKERS={
 'PROC-13':['LAB_NESTED_SHELL_MARKER','cmd.exe'],
 'PROC-14':['child-written.txt','LAB_CHILD_FILE_MARKER'],
 'PROC-15':['LAB_STDERR_MARKER','child-stderr.txt'],
 'PROC-16':['certutil.exe','hashfile'],
 'FILE-24':['marker-01.txt','batch-files'],
 'FILE-25':['stage-a','stage-b'],
 'FILE-26':['inert-example.cmd','inert-example.ini'],
 'FILE-27':['file-hash-manifest.json'],
 'FILE-28':['synthetic-records.jsonl'],
 'REG-13':['LabFeatureEnabled'],
 'REG-16':['TransientMarker'],
 'CHAIN-01':['LAB_CHAIN_A','chain-a.txt'],
 'CHAIN-02':['ChainB','chain-b.txt'],
 'CHAIN-03':['chain-c.zip','chain-c-input'],
 'NET-01':['example.com'],
}

def main():
    p=argparse.ArgumentParser(description='Review-Liste mit unbestätigten Textkandidaten erzeugen')
    p.add_argument('--report',required=True,help='Sandbox-Export in TXT, JSON, CSV oder HTML')
    p.add_argument('--ground-truth',help='Pfad zu events.jsonl aus der Ausführung')
    p.add_argument('--catalog',default=str(Path(__file__).with_name('Soll-Katalog.json')))
    p.add_argument('--output',default='Review-Ergebnis.csv')
    args=p.parse_args()
    report=Path(args.report).read_text(encoding='utf-8-sig',errors='replace')
    catalog=json.loads(Path(args.catalog).read_text(encoding='utf-8'))
    execution={}
    if args.ground_truth:
        for line in Path(args.ground_truth).read_text(encoding='utf-8-sig').splitlines():
            try:ev=json.loads(line)
            except json.JSONDecodeError:continue
            if ev.get('phase')=='END':execution[ev.get('test_id')]=ev.get('status')
    with Path(args.output).open('w',newline='',encoding='utf-8-sig') as fh:
        writer=csv.writer(fh,delimiter=';')
        writer.writerow(['Test-ID','Aktion','Ausführung laut Ground Truth','Kandidaten im Report','Textfragmente','Manuelle Bewertung','Fundstelle/Begründung'])
        for item in catalog:
            test_id=item['test_id']
            matched=[term for term in MARKERS.get(test_id,[]) if term.casefold() in report.casefold()]
            status=execution.get(test_id,'UNBEKANNT')
            writer.writerow([test_id,item['action'],status,'MOEGLICH' if matched else 'KEIN BELEG',', '.join(matched),'PRUEFEN',''])
    print('Review-Tabelle geschrieben:',args.output)
    print('Hinweis: Texttreffer sind unbestätigte Kandidaten. Ohne Ground Truth und manuelle Prüfung keine Vollständigkeitsquote.')
if __name__=='__main__':main()
