"""Reconcile every source declaration with the partial Linux recorded mirrors.

Static inventory only. This never runs Windows code, discovers theory rows,
reads credentials, or infers that a capture is complete.
"""
import collections
import hashlib
import json
import pathlib
import re
import sys
from extract_offline_oracle import validate_input_projection, shared_source_hashes, METHODS

ROOT = pathlib.Path(__file__).parent
REPO = ROOT.parents[2]
sys.path.insert(0,str(REPO/'tests/windows/differential-replay/suite-wide'))
import inventory


def mirror_methods():
    methods = collections.defaultdict(list)
    structured = json.loads((ROOT/'oracle.json').read_text())
    for method in structured['frameworks']['net8.0-windows']:
        methods['DirectorySearchOptionsComparisonTests.'+method].append('structured-four-fact-oracle')
    hardcoded = (ROOT/'HardcodedExpectations.g.cs').read_text()
    for name in set(re.findall(r'\["([^"\n]+):\d+"\]',hardcoded)):
        methods[name].append('hardcoded-source-reviewed-operands')
    theory = (ROOT/'RecordedTheoryExpectations.g.cs').read_text()
    for name in set(re.findall(r'\["net8\.0-windows\|([^"\n]+)"\]',theory)):
        methods[name].append('recorded-eight-theory-multisets')
    for filename in ('offline-oracle.json','reviewed-assertions-oracle.json'):
        for name in json.loads((ROOT/filename).read_text())['frameworks']['net8.0-windows']:
            methods[name].append(filename)
    return dict(sorted(methods.items()))


def review_notes():
    document=json.loads((ROOT/'review-notes.json').read_text())
    capture=json.loads((ROOT/'capture-inventory.json').read_text())
    if document['sourceCommit']!=capture['sourceCommit'] or document['runId']!=capture['runId']:
        raise ValueError('Review provenance changed')
    notes={}
    for note in document['notes']:
        name=note['method']
        if name in notes: raise ValueError('Duplicate review note')
        if note['file']!=name.split('.')[0]+'.cs': raise ValueError('Review source identity differs')
        for reference in [note]+note.get('relatedSources',[]):
            source=REPO/'tests/windows/AdForLinux.DifferentialTests'/reference['file']
            if hashlib.sha256(source.read_bytes()).hexdigest()!=reference['sourceSha256']:
                raise ValueError('Reviewed source changed: '+reference['file'])
        for reference in note.get('relatedImplementationSources',[]):
            relative=pathlib.PurePosixPath(reference['file'])
            if relative.is_absolute() or '..' in relative.parts or not relative.parts or relative.parts[0]!='src' or relative.suffix!='.cs':
                raise ValueError('Invalid reviewed implementation source path')
            source=(REPO/reference['file']).resolve()
            if not source.is_relative_to(REPO.resolve()):
                raise ValueError('Invalid reviewed implementation source path')
            if hashlib.sha256(source.read_bytes()).hexdigest()!=reference['sourceSha256']:
                raise ValueError('Reviewed implementation source changed: '+reference['file'])
        notes[name]=note
    return notes


def complete_metadata_methods():
    complete={}
    for spec in json.loads((ROOT/'reviewed-assertions-spec.json').read_text()):
        scope=spec.get('coverage','partial')
        if scope=='partial': continue
        if (scope!='complete-local-metadata-fact' or spec.get('kind')!='Fact'
                or spec['rows']!=1 or spec['checks']!=1 or spec.get('adaptation')
                or spec.get('inputProjection') or not spec.get('completionReview')):
            raise ValueError('Invalid complete metadata Fact review')
        source=REPO/'tests/windows/AdForLinux.DifferentialTests'/spec['file']
        if hashlib.sha256(source.read_bytes()).hexdigest()!=spec['sha']:
            raise ValueError('Completed metadata source changed')
        complete[spec['method']]=spec['completionReview']
    return complete


def historical_methods():
    base=REPO/'tests/windows/differential-replay/results'
    manifest=json.loads((base/'manifest.json').read_text())
    fixture_sets=[]
    for framework in ('net8.0','net10.0'):
        cases=json.loads((base/f'run202-{framework}.json').read_text())['cases']
        fixture_sets.append(set(cases))
    if fixture_sets[0]!=fixture_sets[1] or len(fixture_sets[0])!=42:
        raise ValueError('Historical case identities differ or are incomplete')
    counts=collections.Counter(name.split('(',1)[0] for name in fixture_sets[0])
    return {name:{'sourceRun':manifest['sourceRun'],'sourceCommit':manifest['sourceCommit'],
                  'recordedCasesPerRuntime':count,'sourceLinked':True}
            for name,count in sorted(counts.items())}


def build():
    source = inventory.inventory(REPO)
    historical = historical_methods()
    mirrors = mirror_methods()
    reviews = review_notes()
    complete = complete_metadata_methods()
    specs=[s for filename in ('offline-extra-spec.json','reviewed-assertions-spec.json') for s in json.loads((ROOT/filename).read_text())]
    notes={s['method']:s['adaptation'] for s in specs if s.get('adaptation')}
    dependencies={s['method']:s['relatedSources'] for s in specs if s.get('relatedSources')}
    shared_source_hashes(specs,{})
    projections={s['method']:validate_input_projection(s,(REPO/'tests/windows/AdForLinux.DifferentialTests'/s['file']).read_bytes()) for s in specs if s.get('inputProjection')}
    declared_rows={name:value[1] for name,value in METHODS.items()}
    declared_rows.update({s['method']:s['rows'] for s in specs})
    capture = json.loads((ROOT/'capture-inventory.json').read_text())
    methods = []
    for file in source['files']:
        for test in file['test_declarations']:
            short = test['id'].removeprefix('AdForLinux.DifferentialTests.')
            mirrored = short in mirrors
            public = capture['methods'].get(hashlib.sha256(test['id'].encode()).hexdigest(),{})
            if short in complete:
                if not mirrored or test['kind'] not in ('Fact','OfflineFact'):
                    raise ValueError('Completed metadata Fact has no Fact adapter')
                reason = complete[short]
            elif mirrored:
                reason = 'Only the documented scalar projections are compared; original assertions and unresolved theory identity remain partial.'
            elif test['portable_replay_classification'] == 'controlled_transport_or_live_scenario_review_needed':
                reason = 'Source has live fixture/settings signals; an equivalent controlled scenario or scoped AD authorization is required before execution. Public scalars alone are insufficient.'
            elif not public:
                reason = 'No parseable public scalar records were identified for this declaration; missing or opaque capture is not a pass.'
            else:
                reason = 'Public scalars exist but this method is not adapted. Microsoft origin, fixture dependencies and complete input/execution coverage still require source review.'
            methods.append({'id':test['id'],'path':test['path'],'line':test['line'],
                'kind':test['kind'],'status':'complete_metadata_fact' if short in complete else 'partial_recorded_mirror' if mirrored else 'not_mirrored',
                'reason':reason,'adapters':mirrors.get(short,[]),
                'source_dependency_classification':test['portable_replay_classification'],
                'inline_data_declarations':test['inline_data_declarations'],
                'dynamic_data_attributes':test['dynamic_data_attributes'],
                'public_scalar_metadata':public})
            if short in reviews:
                if mirrored: raise ValueError('Blocked review method now has an adapter; reconcile review note')
                methods[-1]['sourceReview']=reviews[short]
                methods[-1]['reason']=reviews[short]['reason']
            if (short in declared_rows and test['kind'] in ('Theory','OfflineTheory')
                    and test['inline_data_declarations'] and not test['dynamic_data_attributes']
                    and declared_rows[short]!=test['inline_data_declarations'] and short not in projections):
                raise ValueError('Explicit input subset metadata required for source declaration count')
            if short in complete: methods[-1]['completionReview']=complete[short]
            if short in notes: methods[-1]['adaptationNote']=notes[short]
            if short in dependencies: methods[-1]['adapterSourceDependencies']=dependencies[short]
            if short in projections:
                projection=projections[short]
                if not mirrored or test['kind'] not in ('Theory','OfflineTheory') or test['inline_data_declarations']!=projection['sourceDeclaredInputs']:
                    raise ValueError('Reviewed input subset disagrees with source declarations')
                methods[-1]['inputProjection']=projection
            if test['id'] in historical: methods[-1]['historicalReplay']=historical[test['id']]
    known = {method['id'].removeprefix('AdForLinux.DifferentialTests.') for method in methods}
    if {name.removeprefix('AdForLinux.DifferentialTests.') for name in historical}-known:
        raise ValueError('Historical replay identities missing from source')
    if set(complete)-known: raise ValueError('Complete metadata identity missing from source')
    if set(projections)-known: raise ValueError('Input subset identity missing from source')
    if set(reviews)-known: raise ValueError('Review note identity missing from source')
    if set(mirrors)-known: raise ValueError('Mirror identities missing from source: '+str(set(mirrors)-known))
    evidence=collections.Counter()
    reviewed=collections.Counter()
    for method in methods:
        if method['status']!='not_mirrored': continue
        public=method['public_scalar_metadata']
        category=('no_public_scalars' if not public else 'explicit_pair_present'
                  if any(meta['kinds'].get('reviewed-scalar-pair',0) for meta in public.values())
                  else 'unverified_operands_only')
        evidence[category]+=1
        reviewed[method.get('sourceReview',{}).get('decision','not_source_reviewed')]+=1
    return {'schemaVersion':1,'measurement':'static-source-declarations-and-reviewed-adapter-scopes-not-runtime-coverage',
        'sourceCommitOfRecordings':capture['sourceCommit'],'runId':capture['runId'],'jobId':capture['jobId'],
        'summary':{'sourceDeclarations':len(methods),'fullyMirroredMethods':len(complete),
            'fullyMirroredMetadataFacts':len(complete),'distinctMirroredMethods':len(mirrors),
            'methodsWithReviewedInputSubsets':len(projections),'explicitlyExcludedSourceInputs':sum(len(p['excludedInputs']) for p in projections.values()),
            'distinctPartiallyMirroredMethods':sum(m['status']=='partial_recorded_mirror' for m in methods),
            'partiallyMirroredFacts':sum(m['status']=='partial_recorded_mirror' and m['kind'] in ('Fact','OfflineFact') for m in methods),
            'partiallyMirroredTheories':sum(m['status']=='partial_recorded_mirror' and m['kind'] in ('Theory','OfflineTheory') for m in methods),'notMirroredMethods':sum(m['status']=='not_mirrored' for m in methods),
            'notMirroredPublicEvidence':dict(sorted(evidence.items())),
            'notMirroredSourceReviews':dict(sorted(reviewed.items())),
            'historicalSourceLinkedMethods':len(historical),
            'historicalRecordedCasesPerRuntime':sum(m['recordedCasesPerRuntime'] for m in historical.values()),
            'sourceDeclarationsWithAnyRecordedAdapter':sum(m['status']!='not_mirrored' or 'historicalReplay' in m for m in methods),
            'sourceDeclarationsWithoutRecordedAdapter':sum(m['status']=='not_mirrored' and 'historicalReplay' not in m for m in methods),
            'statuses':dict(collections.Counter(m['status'] for m in methods)),
            'inheritedMethodCountCorrection':'The starting runner reported 24 adapters, representing 22 distinct source methods. Two methods appeared in both the structured and hardcoded adapters.',
            'allCasesCovered':False},
        'limits':['Source declaration counts are not the 1398 Windows execution files per runtime.',
            'Public scalar execution identities do not identify theory arguments, complete discovered cases, or capture completeness.',
            'An explicit public pair may have a literal or clone expected operand; its presence is not Microsoft provenance or a pass.',
            'Historical source-linked replay is attributed separately to its earlier recording and is excluded from current-run method/scalar totals.',
            'Only explicitly source-reviewed complete metadata Facts are marked complete; other adapters remain partial. Missing, redacted, unsupported and unadapted checks are not counted as passing.',
            'Source dependency classifications are lexical review signals, not execution authorization or a proof that a method requires AD.',
            'Some unmirrored offline methods can be adapted after further source review. The full suite additionally requires data absent from the public capture and scenario support.'],
        'methods':sorted(methods,key=lambda method:method['id'])}

if __name__ == '__main__':
    output = pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'coverage-inventory.json'
    output.write_text(json.dumps(build(),indent=2)+'\n')
