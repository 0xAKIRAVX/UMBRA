#!/usr/bin/env python3
"""Generates ios/UMBRA.xcodeproj/project.pbxproj with deterministic UUIDs.

Reads the actual source tree (ios/UMBRA, ios/UMBRATests) so the project and
the filesystem can never drift. objectVersion 56 / Xcode 14+ compatible;
opens in Xcode 14/15/16. Also validates UUID uniqueness and emits the file
sorted in canonical section order.
"""
import hashlib
import os
import sys

ROOT = '/home/z/my-project/umbra/ios'
APP_DIR = os.path.join(ROOT, 'UMBRA')
TEST_DIR = os.path.join(ROOT, 'UMBRATests')
OUT = os.path.join(ROOT, 'UMBRA.xcodeproj', 'project.pbxproj')

MARKETING_VERSION = '3.11.0'
CURRENT_PROJECT_VERSION = '1'
BUNDLE_ID = 'com.umbra.scanner.ios'
SWIFT_VERSION = '5.9'
DEPLOYMENT_TARGET = '16.0'

_uuids = {}

def uid(role: str, name: str) -> str:
    h = hashlib.sha1(f'{role}::{name}'.encode()).hexdigest().upper()[:24]
    assert len(h) == 24 and all(c in '0123456789ABCDEF' for c in h)
    assert h not in _uuids.values(), f'UUID collision for {role}/{name}'
    _uuids[(role, name)] = h
    return h

def u(role: str, name: str) -> str:
    return _uuids[(role, name)]

# ---------------------------------------------------------------- collect --
app_swift = []   # (groupPath, fileName)
app_resources = []  # (groupPath, fileName, type)
test_swift = []

def walk(base: str, prefix: str):
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        rel = os.path.relpath(dirpath, base)
        for f in sorted(filenames):
            if f == '.DS_Store':
                continue
            full = os.path.join(dirpath, f)
            relfile = os.path.normpath(os.path.join(prefix, rel, f)) if rel != '.' else os.path.normpath(os.path.join(prefix, f))
            group = os.path.dirname(relfile) or ''
            if f.endswith('.swift'):
                yield ('swift', group, f, full)
            elif f.endswith('.xcassets'):
                yield ('assetcatalog', group, f, full)
            elif f.endswith('.ttf'):
                yield ('font', group, f, full)
            elif f == 'Info.plist':
                yield ('plist', group, f, full)
            else:
                yield ('other', group, f, full)

for kind, group, fname, full in walk(APP_DIR, ''):
    if kind == 'swift':
        app_swift.append((group, fname))
    elif kind == 'font':
        app_resources.append((group, fname, 'font'))
    elif kind == 'assetcatalog':
        app_resources.append((group, fname, 'assetcatalog'))
    elif kind == 'plist':
        app_resources.append((group, fname, 'plist'))  # referenced, not built
    else:
        print('WARN: unhandled app file', full, file=sys.stderr)

for kind, group, fname, full in walk(TEST_DIR, ''):
    if kind == 'swift':
        test_swift.append((group, fname))

print(f'app sources: {len(app_swift)} swift, {len(app_resources)} resources')
print(f'test sources: {len(test_swift)}')

# ---------------------------------------------------------------- objects --
build_files = []       # list of (uuid, comment, refUuid, refComment)
file_refs = {}         # uuid -> (isa line string)
groups = []            # (uuid, name/path, children list, kind)
native_targets = []
sources_phases = []
resources_phases = []
frameworks_phases = []
build_configs = []     # (uuid, name, settings dict)
config_lists = []

# --- file references + build files for app sources
for group, fname in app_swift:
    ref = uid('fileref', f'UMBRA/{group}/{fname}' if group else f'UMBRA/{fname}')
    bf = uid('buildfile', f'UMBRA/{group}/{fname}' if group else f'UMBRA/{fname}')
    file_refs[ref] = f'{{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = {fname}; sourceTree = "<group>"; }};'
    build_files.append((bf, f'{fname} in Sources', ref))

for group, fname, kind in app_resources:
    path = f'UMBRA/{group}/{fname}' if group else f'UMBRA/{fname}'
    ref = uid('fileref', path)
    if kind == 'font':
        file_refs[ref] = f'{{isa = PBXFileReference; lastKnownFileType = file; path = {fname}; sourceTree = "<group>"; }};'
        bf = uid('buildfile', path)
        build_files.append((bf, f'{fname} in Resources', ref))
    elif kind == 'assetcatalog':
        file_refs[ref] = f'{{isa = PBXFileReference; lastKnownFileType = folder.assetcatalog; path = {fname}; sourceTree = "<group>"; }};'
        bf = uid('buildfile', path)
        build_files.append((bf, f'{fname} in Resources', ref))
    else:  # Info.plist — referenced only
        file_refs[ref] = f'{{isa = PBXFileReference; lastKnownFileType = text.plist.xml; path = {fname}; sourceTree = "<group>"; }};'

for group, fname in test_swift:
    path = f'UMBRATests/{group}/{fname}' if group else f'UMBRATests/{fname}'
    ref = uid('fileref', path)
    bf = uid('buildfile', path)
    file_refs[ref] = f'{{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = {fname}; sourceTree = "<group>"; }};'
    build_files.append((bf, f'{fname} in Sources', ref))

# products
app_product = uid('product', 'UMBRA.app')
tests_product = uid('product', 'UMBRATests.xctest')
file_refs[app_product] = '{isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = UMBRA.app; sourceTree = BUILT_PRODUCTS_DIR; };'
file_refs[tests_product] = '{isa = PBXFileReference; explicitFileType = wrapper.cfbundle; includeInIndex = 0; path = UMBRATests.xctest; sourceTree = BUILT_PRODUCTS_DIR; };'

# --- groups
def group_of(prefix):
    """children uuids of files under a group prefix"""
    out = []
    for (group, fname) in app_swift:
        if group == prefix:
            out.append(u('fileref', f'UMBRA/{group}/{fname}' if group else f'UMBRA/{fname}'))
    for (group, fname, kind) in app_resources:
        if group == prefix:
            out.append(u('fileref', f'UMBRA/{group}/{fname}' if group else f'UMBRA/{fname}'))
    return out

main_group = uid('group', 'Main')
umbra_group = uid('group', 'UMBRA')
tests_group = uid('group', 'UMBRATests')
products_group = uid('group', 'Products')
subgroups = {}
for sub in ['Core', 'Crypto', 'Net', 'Engine', 'Settings', 'Vless', 'Export', 'UI',
            'Fonts', 'Fonts/Vazirmatn', 'Fonts/ChakraPetch']:
    subgroups[sub] = uid('group', f'UMBRA/{sub}')

groups.append((main_group, None, None, 'main'))
groups.append((umbra_group, 'UMBRA', None, 'normal'))
groups.append((tests_group, 'UMBRATests', None, 'normal'))
groups.append((products_group, None, 'Products', 'products'))
for sub in subgroups:
    groups.append((subgroups[sub], sub.split('/')[-1], None, 'normal'))

# --- build phases
app_sources_phase = uid('phase', 'UMBRA Sources')
app_frameworks_phase = uid('phase', 'UMBRA Frameworks')
app_resources_phase = uid('phase', 'UMBRA Resources')
tests_sources_phase = uid('phase', 'UMBRATests Sources')
tests_frameworks_phase = uid('phase', 'UMBRATests Frameworks')

# --- native targets
app_target = uid('target', 'UMBRA')
tests_target = uid('target', 'UMBRATests')
project_object = uid('project', 'UMBRA')
proxy = uid('proxy', 'UMBRATests->UMBRA')
dependency = uid('dependency', 'UMBRATests->UMBRA')

app_config_list = uid('configlist', 'project/UMBRA')
tests_config_list = uid('configlist', 'target/UMBRATests')
project_config_list = uid('configlist', 'PBXProject')

# --- build configurations
project_debug = uid('config', 'project Debug')
project_release = uid('config', 'project Release')
app_debug = uid('config', 'UMBRA Debug')
app_release = uid('config', 'UMBRA Release')
tests_debug = uid('config', 'UMBRATests Debug')
tests_release = uid('config', 'UMBRATests Release')

# ---------------------------------------------------------------- emit ----
def q(s):
    if any(c in s for c in ' \t"'):
        return f'"{s}"'
    return s

def settings_lines(d, indent='\t\t\t\t'):
    lines = []
    for k in sorted(d.keys()):
        v = d[k]
        lines.append(f'{indent}{k} = {q(str(v))};')
    return '\n'.join(lines)

out = []
out.append('// !$*UTF8*$!')
out.append('{')
out.append('\tarchiveVersion = 1;')
out.append('\tobjectVersion = 56;')
out.append('\tclasses = {')
out.append('\t};')
out.append('\tobjects = {')
out.append('')

# PBXBuildFile
out.append('/* Begin PBXBuildFile section */')
for uuid, comment, ref, in []: pass
for uuid, comment, ref in sorted(build_files, key=lambda x: x[0]):
    ref_comment = comment.replace(' in Sources', '').replace(' in Resources', '')
    out.append(f'\t\t{uuid} /* {comment} */ = {{isa = PBXBuildFile; fileRef = {ref} /* {ref_comment} */; }};')
out.append('/* End PBXBuildFile section */')
out.append('')

# PBXFileReference
out.append('/* Begin PBXFileReference section */')
for uuid in sorted(file_refs):
    body = file_refs[uuid]
    name = body.split('path = ')[1].split(';')[0]
    out.append(f'\t\t{uuid} /* {name} */ = {body}')
out.append('/* End PBXFileReference section */')
out.append('')

# PBXContainerItemProxy
out.append('/* Begin PBXContainerItemProxy section */')
out.append(f'\t\t{proxy} /* PBXContainerItemProxy */ = {{')
out.append('\t\t\tisa = PBXContainerItemProxy;')
out.append(f'\t\t\tcontainerPortal = {project_object} /* Project object */;')
out.append('\t\t\tproxyType = 1;')
out.append(f'\t\t\tremoteGlobalIDString = {app_target};')
out.append('\t\t\tremoteInfo = UMBRA;')
out.append('\t\t};')
out.append('/* End PBXContainerItemProxy section */')
out.append('')

# PBXFrameworksBuildPhase
out.append('/* Begin PBXFrameworksBuildPhase section */')
for phase_uuid, comment in [(app_frameworks_phase, 'Frameworks'), (tests_frameworks_phase, 'Frameworks')]:
    out.append(f'\t\t{phase_uuid} /* {comment} */ = {{')
    out.append('\t\t\tisa = PBXFrameworksBuildPhase;')
    out.append('\t\t\tbuildActionMask = 2147483647;')
    out.append('\t\t\tfiles = (')
    out.append('\t\t\t);')
    out.append('\t\t\trunOnlyForDeploymentPostprocessing = 0;')
    out.append('\t\t};')
out.append('/* End PBXFrameworksBuildPhase section */')
out.append('')

# PBXGroup
out.append('/* Begin PBXGroup section */')
grp_children = {
    main_group: [umbra_group, tests_group, products_group],
    umbra_group: (
        group_of('') +
        [subgroups[s] for s in ['Core', 'Crypto', 'Net', 'Engine', 'Settings', 'Vless', 'Export', 'UI', 'Fonts']]
    ),
    tests_group: [
        u('fileref', f'UMBRATests/{group}/{fname}' if group else f'UMBRATests/{fname}')
        for (group, fname) in test_swift
    ],
    products_group: [app_product, tests_product],
}
for sub in ['Core', 'Crypto', 'Net', 'Engine', 'Settings', 'Vless', 'Export', 'UI']:
    grp_children[subgroups[sub]] = group_of(sub)
grp_children[subgroups['Fonts']] = [subgroups['Fonts/Vazirmatn'], subgroups['Fonts/ChakraPetch']]
grp_children[subgroups['Fonts/Vazirmatn']] = group_of('Fonts/Vazirmatn')
grp_children[subgroups['Fonts/ChakraPetch']] = group_of('Fonts/ChakraPetch')

grp_names = {main_group: None, umbra_group: 'UMBRA', tests_group: 'UMBRATests',
             products_group: 'Products'}
for sub in subgroups:
    grp_names[subgroups[sub]] = sub.split('/')[-1]
grp_comments = {main_group: None, umbra_group: 'UMBRA', tests_group: 'UMBRATests',
                products_group: 'Products'}
for sub in subgroups:
    grp_comments[subgroups[sub]] = sub

def emit_group(uuid):
    name = grp_names[uuid]
    comment = grp_comments[uuid] or 'main'
    children = grp_children[uuid]
    out.append(f'\t\t{uuid} /* {comment} */ = {{')
    out.append('\t\t\tisa = PBXGroup;')
    out.append('\t\t\tchildren = (')
    for c in children:
        # comment for child: file name / group name / product name
        if c in file_refs:
            cname = file_refs[c].split('path = ')[1].split(';')[0]
        else:
            cname = grp_comments[c]
        out.append(f'\t\t\t\t{c} /* {cname} */,'.rstrip() if not cname else f'\t\t\t\t{c} /* {cname} */,')
    out.append('\t\t\t);')
    if name:
        out.append(f'\t\t\tpath = {name};')
    elif grp_names[uuid]:
        out.append(f'\t\t\tpath = {name};')
    else:
        out.append('\t\t\tsourceTree = "<group>";')
    if name and uuid not in (main_group, products_group):
        out.append('\t\t\tsourceTree = "<group>";')
    elif uuid == products_group:
        out.append('\t\t\tsourceTree = "<group>";')
    out.append('\t\t};')

for uuid in [main_group, umbra_group] + [subgroups[s] for s in
             ['Core', 'Crypto', 'Net', 'Engine', 'Settings', 'Vless', 'Export', 'UI',
              'Fonts', 'Fonts/Vazirmatn', 'Fonts/ChakraPetch']] + [tests_group, products_group]:
    emit_group(uuid)
out.append('/* End PBXGroup section */')
out.append('')

# PBXNativeTarget
out.append('/* Begin PBXNativeTarget section */')
out.append(f'\t\t{app_target} /* UMBRA */ = {{')
out.append('\t\t\tisa = PBXNativeTarget;')
out.append(f'\t\t\tbuildConfigurationList = {app_config_list} /* Build configuration list for PBXNativeTarget "UMBRA" */;')
out.append('\t\t\tbuildPhases = (')
out.append(f'\t\t\t\t{app_sources_phase} /* Sources */,')
out.append(f'\t\t\t\t{app_frameworks_phase} /* Frameworks */,')
out.append(f'\t\t\t\t{app_resources_phase} /* Resources */,')
out.append('\t\t\t);')
out.append('\t\t\tname = UMBRA;')
out.append('\t\t\tproductName = UMBRA;')
out.append(f'\t\t\tproductReference = {app_product} /* UMBRA.app */;')
out.append('\t\t\tproductType = "com.apple.product-type.application";')
out.append('\t\t};')
out.append(f'\t\t{tests_target} /* UMBRATests */ = {{')
out.append('\t\t\tisa = PBXNativeTarget;')
out.append(f'\t\t\tbuildConfigurationList = {tests_config_list} /* Build configuration list for PBXNativeTarget "UMBRATests" */;')
out.append('\t\t\tbuildPhases = (')
out.append(f'\t\t\t\t{tests_sources_phase} /* Sources */,')
out.append(f'\t\t\t\t{tests_frameworks_phase} /* Frameworks */,')
out.append('\t\t\t);')
out.append('\t\t\tdependencies = (')
out.append(f'\t\t\t\t{dependency} /* PBXTargetDependency */,')
out.append('\t\t\t);')
out.append('\t\t\tname = UMBRATests;')
out.append('\t\t\tproductName = UMBRATests;')
out.append(f'\t\t\tproductReference = {tests_product} /* UMBRATests.xctest */;')
out.append('\t\t\tproductType = "com.apple.product-type.bundle.unit-test";')
out.append('\t\t};')
out.append('/* End PBXNativeTarget section */')
out.append('')

# PBXProject
out.append('/* Begin PBXProject section */')
out.append(f'\t\t{project_object} /* Project object */ = {{')
out.append('\t\t\tisa = PBXProject;')
out.append('\t\t\tattributes = {')
out.append('\t\t\t\tBuildIndependentTargetsInParallel = 1;')
out.append('\t\t\t\tLastUpgradeCheck = 1540;')
out.append('\t\t\t\tTargetAttributes = {')
out.append(f'\t\t\t\t\t{tests_target} = {{')
out.append('\t\t\t\t\t\tTestTargetType = 2;')
out.append('\t\t\t\t\t};')
out.append('\t\t\t\t};')
out.append('\t\t\t};')
out.append(f'\t\t\tbuildConfigurationList = {project_config_list} /* Build configuration list for PBXProject "UMBRA" */;')
out.append('\t\t\tcompatibilityVersion = "Xcode 14.0";')
out.append('\t\t\tdevelopmentRegion = en;')
out.append('\t\t\thasScannedForEncodings = 0;')
out.append('\t\t\tknownRegions = (')
out.append('\t\t\t\ten,')
out.append('\t\t\t\tfa,')
out.append('\t\t\t\tBase,')
out.append('\t\t\t);')
out.append(f'\t\t\tmainGroup = {main_group};')
out.append(f'\t\t\tproductRefGroup = {products_group} /* Products */;')
out.append('\t\t\tprojectDirPath = "";')
out.append('\t\t\tprojectRoot = "";')
out.append('\t\t\ttargets = (')
out.append(f'\t\t\t\t{app_target} /* UMBRA */,')
out.append(f'\t\t\t\t{tests_target} /* UMBRATests */,')
out.append('\t\t\t);')
out.append('\t\t};')
out.append('/* End PBXProject section */')
out.append('')

# PBXResourcesBuildPhase
out.append('/* Begin PBXResourcesBuildPhase section */')
out.append(f'\t\t{app_resources_phase} /* Resources */ = {{')
out.append('\t\t\tisa = PBXResourcesBuildPhase;')
out.append('\t\t\tbuildActionMask = 2147483647;')
out.append('\t\t\tfiles = (')
res_bfs = [(bf, comment) for (bf, comment, ref) in build_files if ' in Resources' in comment]
for bf, comment in sorted(res_bfs, key=lambda x: x[0]):
    out.append(f'\t\t\t\t{bf} /* {comment} */,')
out.append('\t\t\t);')
out.append('\t\t\trunOnlyForDeploymentPostprocessing = 0;')
out.append('\t\t};')
out.append('/* End PBXResourcesBuildPhase section */')
out.append('')

# PBXSourcesBuildPhase
out.append('/* Begin PBXSourcesBuildPhase section */')
def emit_sources(phase_uuid, comment, target_files):
    out.append(f'\t\t{phase_uuid} /* {comment} */ = {{')
    out.append('\t\t\tisa = PBXSourcesBuildPhase;')
    out.append('\t\t\tbuildActionMask = 2147483647;')
    out.append('\t\t\tfiles = (')
    for bf, c in target_files:
        out.append(f'\t\t\t\t{bf} /* {c} */,')
    out.append('\t\t\t);')
    out.append('\t\t\trunOnlyForDeploymentPostprocessing = 0;')
    out.append('\t\t};')

app_src_bfs = sorted([(bf, comment) for (bf, comment, ref) in build_files
                      if ' in Sources' in comment and 'UMBRATests' not in comment],
                     key=lambda x: x[0])
test_src_bfs = sorted([(bf, comment) for (bf, comment, ref) in build_files
                       if ' in Sources' in comment and 'UMBRATests' in comment],
                      key=lambda x: x[0])
emit_sources(app_sources_phase, 'Sources', app_src_bfs)
emit_sources(tests_sources_phase, 'Sources', test_src_bfs)
out.append('/* End PBXSourcesBuildPhase section */')
out.append('')

# PBXTargetDependency
out.append('/* Begin PBXTargetDependency section */')
out.append(f'\t\t{dependency} /* PBXTargetDependency */ = {{')
out.append('\t\t\tisa = PBXTargetDependency;')
out.append(f'\t\t\ttarget = {app_target} /* UMBRA */;')
out.append(f'\t\t\ttargetProxy = {proxy} /* PBXContainerItemProxy */;')
out.append('\t\t};')
out.append('/* End PBXTargetDependency section */')
out.append('')

# XCBuildConfiguration
out.append('/* Begin XCBuildConfiguration section */')
common_project = {
    'ALWAYS_SEARCH_USER_PATHS': 'NO',
    'CLANG_ENABLE_MODULES': 'YES',
    'CLANG_ENABLE_OBJC_ARC': 'YES',
    'CLANG_WARN_BLOCK_CAPTURE_AUTORELEASING': 'YES',
    'CLANG_WARN_BOOL_CONVERSION': 'YES',
    'CLANG_WARN_COMMA': 'YES',
    'CLANG_WARN_CONSTANT_CONVERSION': 'YES',
    'CLANG_WARN_DEPRECATED_OBJC_IMPLEMENTATIONS': 'YES',
    'CLANG_WARN_DIRECT_OBJC_ISA_USAGE': 'YES_ERROR',
    'CLANG_WARN_EMPTY_BODY': 'YES',
    'CLANG_WARN_ENUM_CONVERSION': 'YES',
    'CLANG_WARN_INFINITE_RECURSION': 'YES',
    'CLANG_WARN_INT_CONVERSION': 'YES',
    'CLANG_WARN_NON_LITERAL_NULL_CONVERSION': 'YES',
    'CLANG_WARN_OBJC_LITERAL_CONVERSION': 'YES',
    'CLANG_WARN_RANGE_LOOP_ANALYSIS': 'YES',
    'CLANG_WARN_STRICT_PROTOTYPES': 'YES',
    'CLANG_WARN_SUSPICIOUS_MOVE': 'YES',
    'CLANG_WARN_UNREACHABLE_CODE': 'YES',
    'CLANG_WARN__DUPLICATE_MATCHING_ISA': 'YES',
    'COPY_PHASE_STRIP': 'NO',
    'ENABLE_STRICT_OBJC_MSGSEND': 'YES',
    'ENABLE_USER_SCRIPT_SANDBOXING': 'YES',
    'GCC_C_LANGUAGE_STANDARD': 'gnu17',
    'GCC_NO_COMMON_BLOCKS': 'YES',
    'GCC_WARN_64_TO_32_BIT_CONVERSION': 'YES',
    'GCC_WARN_ABOUT_RETURN_TYPE': 'YES_ERROR',
    'GCC_WARN_UNDECLARED_SELECTOR': 'YES',
    'GCC_WARN_UNINITIALIZED_AUTOS': 'YES_AGGRESSIVE',
    'GCC_WARN_UNUSED_FUNCTION': 'YES',
    'GCC_WARN_UNUSED_VARIABLE': 'YES',
    'LOCALIZATION_PREFERS_STRING_CATALOGS': 'YES',
    'MTL_ENABLE_DEBUG_INFO': 'NO',  # release
}
project_common = {
    'ALWAYS_SEARCH_USER_PATHS': 'NO',
    'CLANG_ENABLE_MODULES': 'YES',
    'CLANG_ENABLE_OBJC_ARC': 'YES',
    'COPY_PHASE_STRIP': 'NO',
    'ENABLE_STRICT_OBJC_MSGSEND': 'YES',
    'GCC_C_LANGUAGE_STANDARD': 'gnu17',
    'GCC_NO_COMMON_BLOCKS': 'YES',
    'IPHONEOS_DEPLOYMENT_TARGET': DEPLOYMENT_TARGET,
    'MTL_ENABLE_DEBUG_INFO': 'NO',
    'SDKROOT': 'iphoneos',
}
project_debug_cfg = dict(project_common, GCC_OPTIMIZATION_LEVEL='0', SWIFT_OPTIMIZATION_LEVEL='-Onone', DEBUG_INFORMATION_FORMAT='dwarf')
project_release_cfg = dict(project_common, SWIFT_COMPILATION_MODE='wholemodule', SWIFT_OPTIMIZATION_LEVEL='-O', DEBUG_INFORMATION_FORMAT='dwarf-with-dsym')
app_common = {
    'ASSETCATALOG_COMPILER_APPICON_NAME': 'AppIcon',
    'ASSETCATALOG_COMPILER_GLOBAL_ACCENT_COLOR_NAME': 'AccentColor',
    'CODE_SIGN_STYLE': 'Automatic',
    'CURRENT_PROJECT_VERSION': CURRENT_PROJECT_VERSION,
    'DEVELOPMENT_ASSET_PATHS': '',
    'DEVELOPMENT_TEAM': '',
    'ENABLE_PREVIEWS': 'YES',
    'GENERATE_INFOPLIST_FILE': 'NO',
    'INFOPLIST_FILE': 'UMBRA/Info.plist',
    'IPHONEOS_DEPLOYMENT_TARGET': DEPLOYMENT_TARGET,
    'LD_RUNPATH_SEARCH_PATHS': '"$(inherited) @executable_path/Frameworks"',
    'MARKETING_VERSION': MARKETING_VERSION,
    'PRODUCT_BUNDLE_IDENTIFIER': BUNDLE_ID,
    'PRODUCT_NAME': '"$(TARGET_NAME)"',
    'SWIFT_EMIT_LOC_STRINGS': 'NO',
    'SWIFT_VERSION': SWIFT_VERSION,
    'TARGETED_DEVICE_FAMILY': '"1,2"',
}
app_debug_cfg = dict(app_common, ENABLE_TESTABILITY='YES', GCC_OPTIMIZATION_LEVEL='0', SWIFT_OPTIMIZATION_LEVEL='-Onone', DEBUG_INFORMATION_FORMAT='dwarf')
app_release_cfg = dict(app_common, ENABLE_TESTABILITY='NO', SWIFT_COMPILATION_MODE='wholemodule', SWIFT_OPTIMIZATION_LEVEL='-O', DEBUG_INFORMATION_FORMAT='dwarf-with-dsym', VALIDATE_PRODUCT='YES')
tests_common = {
    'BUNDLE_LOADER': '"$(TEST_HOST)"',
    'CODE_SIGN_STYLE': 'Automatic',
    'CURRENT_PROJECT_VERSION': CURRENT_PROJECT_VERSION,
    'GENERATE_INFOPLIST_FILE': 'YES',
    'IPHONEOS_DEPLOYMENT_TARGET': DEPLOYMENT_TARGET,
    'MARKETING_VERSION': MARKETING_VERSION,
    'PRODUCT_BUNDLE_IDENTIFIER': BUNDLE_ID + '.tests',
    'PRODUCT_NAME': '"$(TARGET_NAME)"',
    'SWIFT_EMIT_LOC_STRINGS': 'NO',
    'SWIFT_VERSION': SWIFT_VERSION,
    'TARGETED_DEVICE_FAMILY': '"1,2"',
    'TEST_HOST': '"$(BUILT_PRODUCTS_DIR)/UMBRA.app/UMBRA"',
    'TEST_TARGET_NAME': 'UMBRA',
}
tests_debug_cfg = dict(tests_common, ENABLE_TESTABILITY='YES', GCC_OPTIMIZATION_LEVEL='0', SWIFT_OPTIMIZATION_LEVEL='-Onone')
tests_release_cfg = dict(tests_common, ENABLE_TESTABILITY='NO', SWIFT_COMPILATION_MODE='wholemodule', SWIFT_OPTIMIZATION_LEVEL='-O')

def emit_config(uuid, name, cfg, indent='\t\t\t'):
    out.append(f'\t\t{uuid} /* {name} */ = {{')
    out.append('\t\t\tisa = XCBuildConfiguration;')
    out.append(f'\t\t\tbuildSettings = {{')
    out.append(settings_lines(cfg, indent='\t\t\t\t'))
    out.append('\t\t\t};')
    out.append(f'\t\t\tname = {name};')
    out.append('\t\t};')

emit_config(project_debug, 'Debug', project_debug_cfg)
emit_config(project_release, 'Release', project_release_cfg)
emit_config(app_debug, 'Debug', app_debug_cfg)
emit_config(app_release, 'Release', app_release_cfg)
emit_config(tests_debug, 'Debug', tests_debug_cfg)
emit_config(tests_release, 'Release', tests_release_cfg)
out.append('/* End XCBuildConfiguration section */')
out.append('')

# XCConfigurationList
out.append('/* Begin XCConfigurationList section */')
for uuid, comment, configs, default in [
    (project_config_list, 'Build configuration list for PBXProject "UMBRA"', [project_debug, project_release], 'Release'),
    (app_config_list, 'Build configuration list for PBXNativeTarget "UMBRA"', [app_debug, app_release], 'Release'),
    (tests_config_list, 'Build configuration list for PBXNativeTarget "UMBRATests"', [tests_debug, tests_release], 'Release'),
]:
    out.append(f'\t\t{uuid} /* {comment} */ = {{')
    out.append('\t\t\tisa = XCConfigurationList;')
    out.append('\t\t\tbuildConfigurations = (')
    for c in configs:
        cname = 'Debug' if c in (project_debug, app_debug, tests_debug) else 'Release'
        out.append(f'\t\t\t\t{c} /* {cname} */,')
    out.append('\t\t\t);')
    out.append('\t\t\tdefaultConfigurationIsVisible = 0;')
    out.append(f'\t\t\tdefaultConfigurationName = {default};')
    out.append('\t\t};')
out.append('/* End XCConfigurationList section */')
out.append('')
out.append('\t};')
out.append(f'\trootObject = {project_object} /* Project object */;')
out.append('}')

content = '\n'.join(out) + '\n'
os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, 'w', encoding='utf-8').write(content)
print(f'wrote {OUT}: {len(content)} bytes, {len(file_refs)} file refs, {len(build_files)} build files')
