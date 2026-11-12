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


def build():
    source = inventory.inventory(REPO)
    mirrors = mirror_methods()
    capture = json.loads((ROOT/'capture-inventory.json').read_text())
    methods = []
    for file in source['files']:
        for test in file['test_declarations']:
            short = test['id'].removeprefix('AdForLinux.DifferentialTests.')
            mirrored = short in mirrors
            public = capture['methods'].get(hashlib.sha256(test['id'].encode()).hexdigest(),{})
            if mirrored:
                reason = 'Only the documented scalar projections are compared; original assertions and unresolved theory identity remain partial.'
            elif test['portable_replay_classification'] == 'controlled_transport_or_live_scenario_review_needed':
                reason = 'Source has live fixture/settings signals; an equivalent controlled scenario or scoped AD authorization is required before execution. Public scalars alone are insufficient.'
            elif not public:
                reason = 'No parseable public scalar records were identified for this declaration; missing or opaque capture is not a pass.'
            else:
                reason = 'Public scalars exist but this method is not adapted. Microsoft origin, fixture dependencies and complete input/execution coverage still require source review.'
            methods.append({'id':test['id'],'path':test['path'],'line':test['line'],
                'kind':test['kind'],'status':'partial_recorded_mirror' if mirrored else 'not_mirrored',
                'reason':reason,'adapters':mirrors.get(short,[]),
                'source_dependency_classification':test['portable_replay_classification'],
                'inline_data_declarations':test['inline_data_declarations'],
                'dynamic_data_attributes':test['dynamic_data_attributes'],
                'public_scalar_metadata':public})
    known = {method['id'].removeprefix('AdForLinux.DifferentialTests.') for method in methods}
    if set(mirrors)-known: raise ValueError('Mirror identities missing from source: '+str(set(mirrors)-known))
    return {'schemaVersion':1,'measurement':'static-source-declarations-and-partial-adapters-not-runtime-coverage',
        'sourceCommitOfRecordings':capture['sourceCommit'],'runId':capture['runId'],'jobId':capture['jobId'],
        'summary':{'sourceDeclarations':len(methods),'fullyMirroredMethods':0,
            'distinctPartiallyMirroredMethods':len(mirrors),'notMirroredMethods':sum(m['status']=='not_mirrored' for m in methods),
            'statuses':dict(collections.Counter(m['status'] for m in methods)),
            'inheritedMethodCountCorrection':'The starting runner reported 24 adapters, representing 22 distinct source methods. Two methods appeared in both the structured and hardcoded adapters.',
            'allCasesCovered':False},
        'limits':['Source declaration counts are not the 1398 Windows execution files per runtime.',
            'Public scalar execution identities do not identify theory arguments, complete discovered cases, or capture completeness.',
            'Every implemented adaptation remains partial. Missing, redacted, unsupported and unadapted checks are not counted as passing.',
            'Source dependency classifications are lexical review signals, not execution authorization or a proof that a method requires AD.',
            'Some unmirrored offline methods can be adapted after further source review. The full suite additionally requires data absent from the public capture and scenario support.'],
        'methods':sorted(methods,key=lambda method:method['id'])}

if __name__ == '__main__':
    output = pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'coverage-inventory.json'
    output.write_text(json.dumps(build(),indent=2)+'\n')
