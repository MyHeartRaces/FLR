import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ci'))
from engine_releases import IntegrityError, Incompatible
import engine_compat as native
import awg_release as awg

class NativeArchiveBoundary(unittest.TestCase):
    def test_mac_refuses_native_execution(self):
        # This suite must never call a downloaded executable on the workstation.
        if sys.platform == 'darwin':
            with self.assertRaises(IntegrityError):native.invoke('/unused',['--help'],'guard')
    def test_exact_payload_only_and_missing_is_incompatible(self):
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w:gz') as archive:
            item=tarfile.TarInfo('good'); item.size=3;archive.addfile(item,io.BytesIO(b'ELF'))
            link=tarfile.TarInfo('link'); link.type=tarfile.SYMTYPE;link.linkname='good';archive.addfile(link)
        self.assertEqual(native.member(output.getvalue(),'good'),b'ELF')
        for name in ['missing','link']:
            with self.assertRaises(Incompatible):native.member(output.getvalue(),name)
    def test_wstunnel_help_cannot_hide_removed_owned_option(self):
        with self.assertRaises(Incompatible):native.check_cli_surface('Usage client: --tls-verify-certificate', ['client','--socket-so-mark','2147483648','wss://example.com:443'])
        native.check_cli_surface('--socket-so-mark --tls-verify-certificate --http-upgrade-path-prefix', ['client','--socket-so-mark','2147483648','--tls-verify-certificate','--http-upgrade-path-prefix','wgws','wss://example.com:443'])

    def test_xray_schema_missing_owned_wan_or_xhttp_is_incompatible(self):
        schema = '\n'.join('type '+name+' struct {\n'+'\n'.join(' Field'+str(i)+' string `json:"'+field+'"`' for i,field in enumerate(fields))+'\n}' for name,fields in native.XRAY_FIELDS.items())
        native.check_xray_schema(schema)
        with self.assertRaises(Incompatible):native.check_xray_schema(schema.replace('json:"interface"','json:"removedInterface"'))
        with self.assertRaises(Incompatible):native.check_xray_schema(schema.replace('json:"xhttpSettings"','json:"removedXhttpSettings"'))

class AWGSourceContract(unittest.TestCase):
    def test_source_enum_preserves_indices_and_rejects_missing_31_fields(self):
        header='enum wgdevice_attribute { WGDEVICE_A_UNSPEC, '+', '.join(awg.REQUIRED)+', __WGDEVICE_A_LAST };'
        values=awg.enum_values(header)
        self.assertEqual(values['WGDEVICE_A_PRIVATE_KEY'],1)
        self.assertEqual(values['WGDEVICE_A_HEADER_PROTECTION_KEY'],21)
        with self.assertRaises(Incompatible):awg.enum_values(header.replace('WGDEVICE_A_RANDOM_TRAILERS,',''))
    def test_untrusted_tag_rejected_before_api_or_make_input(self):
        class NoAPI:
            def json(self,path):raise AssertionError('unsafe tag reached network boundary')
        with self.assertRaises(IntegrityError):awg.source(NoAPI(),awg.MODULE_REPO,'v1.0\nEVIL:=yes',{})
    def test_official_blob_digest_rejects_tampered_license(self):
        data=b'license'; sha=hashlib.sha1(b'blob 7\0'+data).hexdigest()
        self.assertEqual(awg.decode_blob({'sha':sha,'encoding':'base64','size':7,'content':base64.b64encode(data).decode()},sha),data)
        with self.assertRaises(IntegrityError):awg.decode_blob({'sha':sha,'encoding':'base64','size':7,'content':base64.b64encode(b'changed').decode()},sha)


class AWGPairSelection(unittest.TestCase):
    def test_newer_pair_selected_and_incompatible_newer_pair_rejected(self):
        class OfficialFixture:
            def __init__(self, shifted=False):
                self.shifted=shifted;self.blobs={};self.trees={}
            def json(self,path):
                if '/tags?' in path:return [{'name':'v99.0.0'},{'name':'v3.1.0'}]
                if '/commits/' in path:
                    repo,tag=path.split('/commits/')
                    sha=hashlib.sha1(path.encode()).hexdigest();tree=hashlib.sha1(('tree '+path).encode()).hexdigest()
                    header='enum device { WGDEVICE_A_UNSPEC, '+('NEW_FIELD, ' if self.shifted and repo==awg.MODULE_REPO and tag=='v99.0.0' else '')+', '.join(awg.REQUIRED)+', __WGDEVICE_A_LAST };'
                    paths=['src/uapi/wireguard.h','src/netlink.c'] if repo==awg.MODULE_REPO else ['src/uapi/linux/linux/wireguard.h','src/config.c']
                    entries=[]
                    for name,data in [(paths[0],header.encode()),(paths[1],(' '.join(awg.REQUIRED)+' '+' '.join('"'+field+'"' for field in awg.FIELDS)).encode())]:
                        digest=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
                        self.blobs[digest]={'sha':digest,'encoding':'base64','size':len(data),'content':base64.b64encode(data).decode()}
                        entries.append({'path':name,'type':'blob','sha':digest})
                    self.trees[tree]={'truncated':False,'tree':entries}
                    return {'sha':sha,'commit':{'tree':{'sha':tree}}}
                if '/git/trees/' in path:return self.trees[path.split('/git/trees/')[1].split('?')[0]]
                if '/git/blobs/' in path:return self.blobs[path.split('/git/blobs/')[1]]
                raise AssertionError(path)
        tools=[{'tag_name':'v99.0.0','draft':False,'prerelease':False}]
        module,tool,rejected=awg.resolve_pair(OfficialFixture(),'v3.1.0',tools)
        self.assertEqual((module['version'],tool['version'],rejected),('99.0.0','99.0.0',[]))
        module,tool,rejected=awg.resolve_pair(OfficialFixture(shifted=True),'v3.1.0',tools)
        self.assertEqual(module['version'],'3.1.0')
        self.assertEqual(tool['version'],'99.0.0')
        self.assertIn('UAPI indices disagree',rejected[0]['reason'])


class RetainedXraySchema(unittest.TestCase):
    def test_removal_of_each_retained_grpc_or_websocket_field_rejects(self):
        required={'GRPCConfig':{'serviceName','authority','multiMode','idle_timeout','health_check_timeout','permit_without_stream','initial_windows_size'},
                  'WebSocketConfig':{'path','headers'}}
        schemas={name:set(fields) for name,fields in native.XRAY_FIELDS.items()}
        schemas.update(required)
        schema='\n'.join('type '+name+' struct {\n'+'\n'.join(' Field'+str(i)+' string `json:"'+field+'"`' for i,field in enumerate(fields))+'\n}' for name,fields in schemas.items())
        native.check_xray_schema(schema)
        for name,fields in required.items():
            for field in fields:
                with self.subTest(struct=name,field=field),self.assertRaises(Incompatible):
                    native.check_xray_schema(schema.replace('json:"'+field+'"','json:"REMOVED_'+field+'"'))

class XrayWebSocketSemantics(unittest.TestCase):
    build = '''func (c *WebSocketConfig) Build() (proto.Message, error) {
        path := c.Path
        var ed uint32
        if u, err := url.Parse(path); err == nil {
            if q := u.Query(); q.Get("ed") != "" {
                Ed, _ := strconv.Atoi(q.Get("ed"))
                ed = uint32(Ed)
                q.Del("ed")
                u.RawQuery = q.Encode()
                path = u.String()
            }
        }
        config := &websocket.Config{Path: path, Ed: ed}
        return config, nil
}
'''
    dialer = '''func Dial() {
    if streamSettings.ProtocolSettings.(*Config).Ed > 0 {
    }
}
func dialWebSocket() {
        header.Set("Sec-WebSocket-Protocol", base64.RawURLEncoding.EncodeToString(ed))
}
func (d *delayDialConn) Write() {
        if len(ed) > int(d.streamSettings.ProtocolSettings.(*Config).Ed) {
            return nil, errors.New("too large")
        }
}'''
    def test_matching_source_proves_owned_query_translation_and_standard_header(self):
        native.check_xray_ws_source(self.build, self.dialer)
    def test_removal_of_each_native_early_data_semantic_rejects(self):
        for part in ['url.Parse(path)', 'u.Query()', 'q.Get("ed")', 'strconv.Atoi(q.Get("ed"))', 'ed = uint32(Ed)', 'q.Del("ed")', 'u.RawQuery = q.Encode()', 'path = u.String()', 'Path: path', 'Ed: ed']:
            with self.subTest(build=part), self.assertRaises(Incompatible):
                native.check_xray_ws_source(self.build.replace(part, 'REMOVED'), self.dialer)
        for part in ['ProtocolSettings.(*Config).Ed > 0', 'header.Set("Sec-WebSocket-Protocol", base64.RawURLEncoding.EncodeToString(ed))', 'len(ed) > int(d.streamSettings.ProtocolSettings.(*Config).Ed)']:
            with self.subTest(dialer=part), self.assertRaises(Incompatible):
                native.check_xray_ws_source(self.build, self.dialer.replace(part, 'REMOVED'))
    def test_unrelated_function_tokens_cannot_supply_missing_build_semantic(self):
        with self.assertRaises(Incompatible):
            native.check_xray_ws_source(self.build.replace('q.Del("ed")', 'REMOVED')+'\nfunc unrelated() { q.Del("ed") }', self.dialer)

class NativeFailureClassification(unittest.TestCase):
    def run_selection(self, result):
        import subprocess
        from unittest.mock import patch
        from engine_releases import select_compatible
        seen=[]
        def check(release):
            seen.append(release['tag_name'])
            if release['tag_name']=='v2.0.0':native.invoke(Path('wstunnel'),['client','--removed-option','--help'],'fixture')
        with patch.object(native,'require_ci'),patch.object(native.subprocess,'run',return_value=result):
            selected,rejected=select_compatible([{'tag_name':'v2.0.0'},{'tag_name':'v1.0.0'}],check)
        return selected,rejected,seen
    def test_identified_cli_rejection_can_fallback(self):
        import subprocess
        selected,rejected,seen=self.run_selection(subprocess.CompletedProcess([],2,"error: unexpected argument '--removed-option' found\n"))
        self.assertEqual(selected['tag_name'],'v1.0.0');self.assertEqual(seen,['v2.0.0','v1.0.0'])
        self.assertIn('parser rejected',rejected[0]['reason'])
    def test_signals_crashes_unknown_status_and_environment_failures_abort(self):
        import subprocess
        for code,message in [(-9,'killed'),(-11,'segmentation fault'),(1,'internal failure'),(2,'error: cannot open file: Permission denied'),(127,'shared library unavailable')]:
            with self.subTest(code=code,message=message),self.assertRaises(IntegrityError):
                self.run_selection(subprocess.CompletedProcess([],code,message))
    def test_known_sing_box_decode_rejection_is_distinct_from_read_or_initialize_failure(self):
        args=['check','-c','/fixtures/config.json']
        diagnostic='FATAL[0000] decode config at /fixtures/config.json: outbounds[0]: unknown field "removed"'
        self.assertTrue(native.parser_rejection('sing-box',args,1,diagnostic))
        self.assertFalse(native.parser_rejection('sing-box',args,1,diagnostic.replace('decode config','read config')))
        self.assertFalse(native.parser_rejection('sing-box',args,-9,diagnostic))
        self.assertFalse(native.parser_rejection('xray',['run','-test'],23,'Failed to start: unknown failure'))
        self.assertFalse(native.parser_rejection('nfqws2',['--dry-run'],1,'unknown failure'))
    def test_xray_identified_reality_transport_rejection_only(self):
        args=['run','-test','-config','/fixtures/xray.json']
        diagnostic='Failed to start: main: failed to load config files: [/fixtures/xray.json] > infra/conf: failed to build outbound config with tag proxy > infra/conf: failed to build stream settings for outbound detour > infra/conf: REALITY only supports RAW, XHTTP and gRPC for now.'
        self.assertTrue(native.parser_rejection('xray',args,23,diagnostic))
        for code,output in [(-9,diagnostic),(23,diagnostic.replace('REALITY only supports RAW, XHTTP and gRPC for now.','unknown runtime failure')),(23,diagnostic.replace('/fixtures/xray.json','/other/input.json')),(23,'Segmentation fault'),(1,diagnostic)]:
            with self.subTest(code=code,output=output):
                self.assertFalse(native.parser_rejection('xray',args,code,output))

    def test_timeout_and_os_execution_failure_are_fatal(self):
        import subprocess
        from unittest.mock import patch
        for error in [subprocess.TimeoutExpired('engine',20),OSError('loader unavailable')]:
            with self.subTest(error=type(error).__name__),patch.object(native,'require_ci'),patch.object(native.subprocess,'run',side_effect=error),self.assertRaises(IntegrityError):
                native.invoke(Path('wstunnel'),['--help'],'fixture')

if __name__=='__main__':unittest.main()
